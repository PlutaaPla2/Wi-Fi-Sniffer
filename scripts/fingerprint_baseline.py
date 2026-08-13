#!/usr/bin/env python3
"""
Baseline measurement for the IE-fingerprint fix (Step 0 of
``prompts/20260813-1257-ie-fingerprint-fix-plan.md``).

Reads the capture CSVs and prints **aggregate statistics only**. No MAC address,
SSID, fingerprint value, or raw IE hex is ever printed — every output is a count
or a distribution summary, so the result is safe to share off-device while the
CSVs themselves stay put.

Run it once before change set A and once after, against the same input, then
compare the two acceptance metrics:

  * distinct fingerprints per MAC  — must go DOWN (issue 1, over-splitting)
  * distinct MACs per fingerprint  — must go DOWN (issue 2, collisions)

Usage:
    python3 scripts/fingerprint_baseline.py
    python3 scripts/fingerprint_baseline.py --csv-dir /home/pi/logs
    python3 scripts/fingerprint_baseline.py --label post-fix > after.txt

Standard library only — no new dependencies.
"""

from __future__ import annotations

import argparse
import csv
import glob
import os
import sys
from collections import defaultdict
from typing import Iterable

# Anchor the default location to the repo, not the CWD, per project convention.
REPO_ROOT       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CSV_DIR = os.path.join(REPO_ROOT, "csv_analyze")

# The fingerprint hash currently keeps the first 8 bytes of each IE. Issue 2 is
# sized by asking how much element content that window throws away.
TRUNCATION_WINDOW = 8


# ---------------------------------------------------------------------------
# Distribution helpers
# ---------------------------------------------------------------------------

def _percentile(sorted_values: list[int], fraction: float) -> int:
    """
    Nearest-rank percentile. Deliberately not interpolated: these are counts of
    discrete things (fingerprints, MACs), so a fractional answer would be a
    fiction, and nearest-rank is defined for n == 1 where interpolation is not.
    """
    if not sorted_values:
        return 0
    rank = max(1, min(len(sorted_values), int(round(fraction * len(sorted_values) + 0.5))))
    return sorted_values[rank - 1]


def _summarise(values: Iterable[int], label: str, indent: str = "  ") -> None:
    """Print median / p95 / max / mean / n for one distribution."""
    ordered = sorted(values)
    if not ordered:
        print(f"{indent}{label:<41} (no data)")
        return

    median = _percentile(ordered, 0.50)
    p95    = _percentile(ordered, 0.95)
    mean   = sum(ordered) / len(ordered)
    print(
        f"{indent}{label:<41} "
        f"n={len(ordered):<7} median={median:<5} p95={p95:<5} "
        f"max={ordered[-1]:<5} mean={mean:.2f}"
    )


def _is_randomized(mac: str) -> bool:
    """
    True if the locally-administered bit is set in the first octet.

    This is the population the merge scorer actually operates on, so the two
    acceptance metrics are reported separately for it — a change that improves
    the global-MAC numbers but not the randomized ones has not fixed anything
    that affects the people count.
    """
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def _open_csv(path: str) -> tuple[list[dict[str, str]], str | None]:
    """Read a CSV into memory, returning (rows, error_message)."""
    if not os.path.exists(path):
        return [], f"not found: {path}"
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            return list(csv.DictReader(fh)), None
    except OSError as exc:
        return [], f"unreadable: {path} ({exc})"


# ---------------------------------------------------------------------------
# Metric 1+2 — the acceptance metrics, from the main recon log
# ---------------------------------------------------------------------------

def report_recon(path: str) -> None:
    """Fingerprint over-splitting and collision rates."""
    print("\n" + "=" * 78)
    print("ACCEPTANCE METRICS — wifi_full_recon_report.csv")
    print("=" * 78)

    rows, error = _open_csv(path)
    if error:
        print(f"  SKIPPED — {error}")
        return

    # MAC -> set of fingerprints, and fingerprint -> set of MACs. Sets of opaque
    # strings; nothing here is printed, only the cardinalities.
    fps_by_mac: dict[str, set[str]] = defaultdict(set)
    macs_by_fp: dict[str, set[str]] = defaultdict(set)
    blank_fp = 0

    for row in rows:
        mac = (row.get("MAC_Address") or "").strip()
        fp  = (row.get("IE_Fingerprint") or "").strip()
        if not mac:
            continue
        if not fp:
            blank_fp += 1
            continue
        fps_by_mac[mac].add(fp)
        macs_by_fp[fp].add(mac)

    total = len(rows)
    print(f"\n  total rows                             {total}")
    print(f"  rows with a fingerprint                {total - blank_fp}")
    print(
        f"  rows with EMPTY fingerprint            {blank_fp}"
        f"  ({(blank_fp / total * 100) if total else 0:.1f}%)"
    )
    print("    ^ expected to INCREASE after the fix — frames carrying only tags")
    print("      0 and 3 correctly produce no fingerprint. Not a regression.")

    print("\n  --- issue 1: over-splitting (distinct fingerprints per MAC) ---")
    print("      must go DOWN")
    _summarise([len(v) for v in fps_by_mac.values()], "all MACs", indent="      ")
    _summarise(
        [len(v) for m, v in fps_by_mac.items() if _is_randomized(m)],
        "randomized MACs (drives the count)", indent="      ",
    )
    _summarise(
        [len(v) for m, v in fps_by_mac.items() if not _is_randomized(m)],
        "global MACs", indent="      ",
    )

    print("\n  --- issue 2: collisions (distinct MACs per fingerprint) ---")
    print("      must go DOWN")
    _summarise([len(v) for v in macs_by_fp.values()], "all fingerprints", indent="      ")

    # A fingerprint shared by many MACs is the collision failure mode; count how
    # far into the tail it goes without naming any of them.
    shared = sum(1 for v in macs_by_fp.values() if len(v) > 1)
    print(f"\n      distinct fingerprints                {len(macs_by_fp)}")
    print(f"      shared by >1 MAC                     {shared}")
    print(f"      shared by >5 MACs                    "
          f"{sum(1 for v in macs_by_fp.values() if len(v) > 5)}")


# ---------------------------------------------------------------------------
# Metric 3 — what the two defects are actually costing, from the IE breakdown
# ---------------------------------------------------------------------------

def report_ie_details(path: str) -> None:
    """Volatility of tags 0/3, and how much content the 8-byte window discards."""
    print("\n" + "=" * 78)
    print("DEFECT SIZING — ie_details_report.csv")
    print("=" * 78)

    rows, error = _open_csv(path)
    if error:
        print(f"  SKIPPED — {error}")
        return

    # Distinct values per MAC for the two volatile tags. Values are hashed into
    # a set and never printed — tag 0's raw hex is the SSID.
    volatile: dict[int, dict[str, set[str]]] = {0: defaultdict(set), 3: defaultdict(set)}

    truncated_count = 0
    total_ies       = 0
    discarded_by_tag: dict[tuple[str, str], int] = defaultdict(int)
    count_by_tag:     dict[tuple[str, str], int] = defaultdict(int)

    for row in rows:
        try:
            ie_id  = int(row.get("IE_ID") or -1)
            ie_len = int(row.get("IE_Length") or 0)
        except ValueError:
            continue

        mac      = (row.get("MAC_Address") or "").strip()
        raw_hex  = (row.get("IE_Raw_Hex") or "").strip()
        ie_name  = (row.get("IE_Name") or "").strip()
        total_ies += 1

        if ie_id in volatile and mac:
            volatile[ie_id][mac].add(raw_hex)

        key = (str(ie_id), ie_name)
        count_by_tag[key] += 1
        if ie_len > TRUNCATION_WINDOW:
            truncated_count += 1
            discarded_by_tag[key] += ie_len - TRUNCATION_WINDOW

    print("\n  --- issue 1: how volatile are tags 0 and 3 within one MAC? ---")
    print("      values >1 are the over-splitting cause; 1.0 would mean no problem")
    _summarise(
        [len(v) for v in volatile[0].values()],
        "distinct tag-0 (SSID) values per MAC", indent="      ",
    )
    _summarise(
        [len(v) for v in volatile[3].values()],
        "distinct tag-3 (channel) values per MAC", indent="      ",
    )

    print("\n  --- issue 2: what the info[:8] window discards ---")
    print(f"      total IEs observed                   {total_ies}")
    print(
        f"      IEs longer than {TRUNCATION_WINDOW} bytes            {truncated_count}"
        f"  ({(truncated_count / total_ies * 100) if total_ies else 0:.1f}% truncated)"
    )
    print(f"      total bytes discarded                {sum(discarded_by_tag.values())}")

    if discarded_by_tag:
        print("\n      most-truncated elements (tag IDs are protocol constants):")
        print(f"        {'tag':<6} {'name':<30} {'count':>8} {'bytes lost':>12}")
        ranked = sorted(discarded_by_tag.items(), key=lambda kv: kv[1], reverse=True)
        for (tag_id, name), lost in ranked[:12]:
            print(f"        {tag_id:<6} {name[:30]:<30} "
                  f"{count_by_tag[(tag_id, name)]:>8} {lost:>12}")


# ---------------------------------------------------------------------------
# Metric 4 — the headline number
# ---------------------------------------------------------------------------

def report_summaries(csv_dir: str) -> None:
    """User_N row count per daily summary — the number senior review will ask about."""
    print("\n" + "=" * 78)
    print("HEADLINE COUNT — daily_summary_*.csv")
    print("=" * 78)

    files = sorted(glob.glob(os.path.join(csv_dir, "daily_summary_*.csv")))
    if not files:
        print(f"  SKIPPED — no daily_summary_*.csv in {csv_dir}")
        return

    print(f"\n  {'file':<34} {'User_N rows':>12}")
    for path in files:
        rows, error = _open_csv(path)
        if error:
            print(f"  {os.path.basename(path):<34} {'unreadable':>12}")
            continue
        users = sum(1 for r in rows if (r.get("User_ID") or "").startswith("User_"))
        print(f"  {os.path.basename(path):<34} {users:>12}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate-only baseline stats for the IE fingerprint fix.",
    )
    parser.add_argument(
        "--csv-dir", default=DEFAULT_CSV_DIR,
        help=f"directory holding the capture CSVs (default: {DEFAULT_CSV_DIR})",
    )
    parser.add_argument(
        "--label", default="baseline",
        help="free-text tag for this run, e.g. 'pre-fix' / 'post-fix'",
    )
    args = parser.parse_args()

    print(f"IE fingerprint measurement — label: {args.label}")
    print(f"source directory: {args.csv_dir}")
    print("output contains aggregate counts only; no MAC, SSID, fingerprint, or raw hex.")

    report_recon(os.path.join(args.csv_dir, "wifi_full_recon_report.csv"))
    report_ie_details(os.path.join(args.csv_dir, "ie_details_report.csv"))
    report_summaries(args.csv_dir)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
