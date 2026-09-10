#!/usr/bin/env python3
"""
Measure what night_sniffer_v3 drops relative to a dumpcap capture.

Answers two questions about one pcap file, without touching the radio and
without writing any CSV:

  1. Frame coverage — of every 802.11 management frame in the file, which ones
     does ``classify_frame()`` recognise, and which does it silently discard?
     Ground truth is the frame's own ``type``/``subtype`` header field, so this
     half needs nothing but scapy.

  2. Information-element coverage — of every element tshark finds in a frame,
     which ones does ``_iter_ies()`` yield? Ground truth here has to come from
     an independent parser, so this half shells out to tshark and is skipped
     with a clear message when tshark is not installed.

Both halves join on the frame's position in the file: scapy's PcapReader and
tshark's ``frame.number`` walk the capture in the same order, so ordinal N in
one is ordinal N in the other.

Typical use, against a capture made by scripts/run_dumpcap.sh:

    python3 scripts/mgmt_parity.py pcap_files/20260817-2300-lobby.pcap
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from collections import Counter, defaultdict

# The tool under test lives in src/, one directory up from this script. Anchored
# on __file__ rather than the working directory so the script works from
# anywhere, matching the convention the project applies to file paths.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_SCRIPT_DIR)
sys.path.insert(0, os.path.join(_REPO_ROOT, "src"))

from scapy.layers.dot11 import Dot11  # noqa: E402
from scapy.utils import PcapReader  # noqa: E402

import night_sniffer_v3 as ns  # noqa: E402

# 802.11 management subtypes (frame control type == 0), IEEE 802.11-2020 9.2.4.1.3.
# Defined here rather than imported from scapy's private _dot11_subtypes so this
# script does not break when that internal table is renamed.
MGMT_SUBTYPE_NAMES: dict[int, str] = {
    0:  "Association Request",
    1:  "Association Response",
    2:  "Reassociation Request",
    3:  "Reassociation Response",
    4:  "Probe Request",
    5:  "Probe Response",
    6:  "Timing Advertisement",
    7:  "Reserved (7)",
    8:  "Beacon",
    9:  "ATIM",
    10: "Disassociation",
    11: "Authentication",
    12: "Deauthentication",
    13: "Action",
    14: "Action No Ack",
    15: "Reserved (15)",
}

# The Pkt_Type label each subtype should carry. Names for subtypes the tool
# already handles are its own; the rest are the names Phase 1 will introduce, so
# this table keeps working as coverage grows instead of needing an edit then.
#
# A frame can fail in two distinct ways and both matter: it can be dropped, or
# it can be kept under the wrong label. The second is easy to miss because the
# frame counts look healthy — it is exactly how Reassociation Response frames
# are currently recorded as ASSOC_RESP.
EXPECTED_LABEL: dict[int, str] = {
    0:  "ASSOC_REQ",
    1:  "ASSOC_RESP",
    2:  "REASSOC_REQ",
    3:  "REASSOC_RESP",
    4:  "PROBE",
    5:  "PROBE_RESP",
    6:  "TIMING_AD",
    7:  "MGMT_7",
    8:  "BEACON",
    9:  "ATIM",
    10: "DISASSOC",
    11: "AUTH",
    12: "DEAUTH",
    13: "ACTION",
    14: "ACTION_NOACK",
    15: "MGMT_15",
}


# ---------------------------------------------------------------------------
# Ground truth from tshark
# ---------------------------------------------------------------------------

def tshark_available() -> str | None:
    """Return the tshark executable path, or None when it is not installed."""
    return shutil.which("tshark")


def read_tshark_tags(pcap_path: str, tshark: str) -> dict[int, list[int]] | None:
    """
    Return ``{frame_number: [tag_id, ...]}`` for every frame tshark can dissect.

    No display filter is applied, so ``frame.number`` keeps the file's own
    numbering and lines up with the ordinal PcapReader assigns. ``occurrence=a``
    makes tshark emit every occurrence of wlan.tag.number rather than just the
    first, which is the whole point of the comparison.

    Returns None if tshark fails, so the caller can report the frame-coverage
    half on its own instead of aborting.
    """
    cmd = [
        tshark, "-r", pcap_path,
        "-T", "fields",
        "-E", "separator=/t",
        "-E", "occurrence=a",
        "-e", "frame.number",
        "-e", "wlan.tag.number",
    ]
    result = subprocess.run(
        cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    if result.returncode != 0:
        print(f"[WARN] tshark exited {result.returncode}: {result.stderr.strip()}",
              file=sys.stderr)
        return None

    tags_by_frame: dict[int, list[int]] = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if not parts or not parts[0]:
            continue
        try:
            frame_no = int(parts[0])
        except ValueError:
            continue
        raw_tags = parts[1] if len(parts) > 1 else ""
        tags: list[int] = []
        for token in raw_tags.split(","):
            token = token.strip()
            if token.isdigit():
                tags.append(int(token))
        tags_by_frame[frame_no] = tags
    return tags_by_frame


# ---------------------------------------------------------------------------
# Walk the capture through the tool under test
# ---------------------------------------------------------------------------

def walk_capture(pcap_path: str, max_frames: int | None) -> tuple[
    Counter, Counter, Counter, dict[int, list[int]], int
]:
    """
    Run every frame in ``pcap_path`` through classify_frame() and _iter_ies().

    Returns ``(seen, kept, mislabelled, tool_tags_by_frame, total_frames)``.
    ``seen``, ``kept`` and ``mislabelled`` are per-subtype counters over
    management frames only; ``tool_tags_by_frame`` maps frame number to the tag
    IDs _iter_ies() yielded. ``mislabelled`` counts frames that were kept but
    recorded under a Pkt_Type belonging to a different subtype, so it is a
    subset of ``kept``.
    """
    seen: Counter = Counter()
    kept: Counter = Counter()
    mislabelled: Counter = Counter()
    tool_tags: dict[int, list[int]] = {}
    total = 0

    with PcapReader(pcap_path) as reader:
        for index, pkt in enumerate(reader, start=1):
            total = index
            if max_frames is not None and index > max_frames:
                total = index - 1
                break

            dot11 = pkt.getlayer(Dot11)
            # Non-802.11 or undissectable frames are outside the comparison;
            # dumpcap's `type mgt` filter would not have kept them either.
            if dot11 is None or dot11.type != 0:
                continue

            subtype = int(dot11.subtype)
            seen[subtype] += 1

            pkt_type, mac_addr = ns.classify_frame(pkt)
            # handle_packet() drops on either condition, so parity has to test
            # both — a recognised subtype with no usable address is still lost.
            if pkt_type is not None and mac_addr:
                kept[subtype] += 1
                if pkt_type != EXPECTED_LABEL.get(subtype, pkt_type):
                    mislabelled[subtype] += 1

            tool_tags[index] = [tag_id for tag_id, _info in ns._iter_ies(pkt)]

    return seen, kept, mislabelled, tool_tags, total


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def report_frame_coverage(seen: Counter, kept: Counter, mislabelled: Counter) -> int:
    """Print the per-subtype kept/dropped/mislabelled table. Returns frames lost."""
    print()
    print("=" * 90)
    print("FRAME COVERAGE  —  ground truth: the frame's own type/subtype field")
    print("=" * 90)
    print(f"{'sub':>3}  {'name':<24}{'in pcap':>9}{'kept':>8}{'dropped':>9}"
          f"{'mislabelled':>13}")
    print("-" * 90)

    total_seen = total_kept = total_mis = 0
    for subtype in sorted(seen):
        count = seen[subtype]
        keep = kept[subtype]
        mis = mislabelled[subtype]
        drop = count - keep
        total_seen += count
        total_kept += keep
        total_mis += mis
        flags = []
        if drop:
            flags.append("DROPPED")
        if mis:
            flags.append(f"as {ns_label_seen(subtype)}")
        flag = ("  <-- " + ", ".join(flags)) if flags else ""
        print(f"{subtype:>3}  {MGMT_SUBTYPE_NAMES.get(subtype, '?'):<24}"
              f"{count:>9}{keep:>8}{drop:>9}{mis:>13}{flag}")

    total_drop = total_seen - total_kept
    pct = (total_drop / total_seen * 100) if total_seen else 0.0
    print("-" * 90)
    print(f"{'':>3}  {'TOTAL':<24}{total_seen:>9}{total_kept:>8}{total_drop:>9}"
          f"{total_mis:>13}")
    print(f"     {pct:.1f}% of management frames dropped; "
          f"{total_mis} further frame(s) kept under the wrong Pkt_Type.")
    return total_drop + total_mis


def ns_label_seen(subtype: int) -> str:
    """
    Report what the tool actually labels ``subtype`` as, for the mislabel note.

    Built by asking classify_frame() about a minimal synthetic frame of that
    subtype rather than hardcoding today's answer, so the note stays truthful
    once Phase 1 changes the classifier.
    """
    from scapy.layers.dot11 import Dot11FCS, RadioTap
    from scapy.packet import Raw
    probe = RadioTap(bytes(
        RadioTap(present="Flags", Flags="FCS")
        / Dot11FCS(type=0, subtype=subtype, addr1="ff:ff:ff:ff:ff:ff",
                   addr2="aa:bb:cc:dd:ee:ff", addr3="11:22:33:44:55:66")
        / Raw(bytes(32))
    ))
    label, _mac = ns.classify_frame(probe)
    return str(label)


def report_ie_coverage(
    tshark_tags: dict[int, list[int]], tool_tags: dict[int, list[int]]
) -> None:
    """Print the per-tag element table, comparing tshark against _iter_ies()."""
    print()
    print("=" * 78)
    print("ELEMENT COVERAGE  —  ground truth: tshark wlan.tag.number")
    print("=" * 78)

    truth_counts: Counter = Counter()
    tool_counts: Counter = Counter()
    # Frames where tshark found elements but the tool found none at all: these
    # are the frames whose element region the tool never located, as opposed to
    # frames where individual elements went missing.
    blind_frames: dict[int, int] = defaultdict(int)

    for frame_no, tags in tool_tags.items():
        truth = tshark_tags.get(frame_no, [])
        truth_counts.update(truth)
        tool_counts.update(tags)
        if truth and not tags:
            blind_frames[frame_no] = len(truth)

    all_tags = sorted(set(truth_counts) | set(tool_counts))
    print(f"{'tag':>4}  {'name':<30}{'tshark':>10}{'tool':>10}{'missing':>10}")
    print("-" * 78)
    total_truth = total_tool = 0
    for tag in all_tags:
        truth_n = truth_counts[tag]
        tool_n = tool_counts[tag]
        missing = truth_n - tool_n
        total_truth += truth_n
        total_tool += tool_n
        flag = "  <-- MISSING" if missing > 0 else ""
        name = ns.IE_NAMES.get(tag, f"Unknown({tag})")
        print(f"{tag:>4}  {name:<30}{truth_n:>10}{tool_n:>10}{missing:>10}{flag}")

    print("-" * 78)
    print(f"{'':>4}  {'TOTAL':<30}{total_truth:>10}{total_tool:>10}"
          f"{total_truth - total_tool:>10}")

    if blind_frames:
        lost = sum(blind_frames.values())
        print()
        print(f"Frames where tshark found elements but _iter_ies() yielded none: "
              f"{len(blind_frames)} frame(s), {lost} element(s) lost.")
        sample = sorted(blind_frames)[:10]
        print(f"  first frame numbers: {', '.join(str(n) for n in sample)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare night_sniffer_v3's management-frame and element "
                    "coverage against a pcap, using tshark as the element oracle.",
    )
    parser.add_argument("pcap", help="Capture file to measure against.")
    parser.add_argument(
        "--max-frames",
        type=int,
        default=None,
        help="Stop after this many frames. Useful for a quick check on a large "
             "capture; omit to measure the whole file.",
    )
    parser.add_argument(
        "--no-tshark",
        action="store_true",
        help="Skip the element-coverage half even if tshark is installed.",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.pcap):
        parser.error(f"no such file: {args.pcap}")

    print(f"Reading {args.pcap} …")
    seen, kept, mislabelled, tool_tags, total = walk_capture(args.pcap, args.max_frames)
    print(f"Read {total} frame(s); {sum(seen.values())} were management frames.")

    if not seen:
        print("No management frames found — nothing to compare.")
        return

    report_frame_coverage(seen, kept, mislabelled)

    if args.no_tshark:
        print("\n[skipped] Element coverage: --no-tshark was passed.")
        return

    tshark = tshark_available()
    if tshark is None:
        print("\n[skipped] Element coverage: tshark not found on PATH. "
              "Install it (same package as dumpcap) to measure element loss.")
        return

    tshark_tags = read_tshark_tags(args.pcap, tshark)
    if tshark_tags is None:
        print("\n[skipped] Element coverage: tshark could not read the file.")
        return

    report_ie_coverage(tshark_tags, tool_tags)


if __name__ == "__main__":
    main()
