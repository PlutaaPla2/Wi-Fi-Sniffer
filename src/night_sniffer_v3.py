#!/usr/bin/env python3
"""
WiFi Full Reconnaissance Tool
Passively captures and fingerprints WiFi clients and access points.
"""

import os
import sys
import time
import threading
import csv
import math
import logging
import hashlib
import argparse
import subprocess
from dataclasses import dataclass, field
from scapy.all import sniff
from scapy.layers.dot11 import (
    # Dot11 is the only layer the frame walk needs: subtypes come from the
    # frame control field and elements are read from the captured bytes, not
    # matched against per-subtype or per-element layer classes. The rest are
    # still used by parse_frame_body() for their fixed fields.
    Dot11, Dot11AssoReq, Dot11ReassoReq,
    Dot11Auth, Dot11Deauth, Dot11Disas, RadioTap
)
from mac_vendor_lookup import MacLookup

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Default capture interface. Overridable per run with --iface, or via the
# startup prompt when that flag is omitted and stdin is a terminal.
INTERFACE          = "wlan1"

# ── Output file paths (edit these to change where CSVs are written) ──────────
# Use an absolute path to write outside the working directory, e.g.:
#   LOG_FILE        = "/home/pi/logs/wifi_full_recon_report.csv"
#   SUMMARY_DIR     = "/home/pi/logs"
LOG_FILE           = "./csv_analyze/wifi_full_recon_report.csv"   # main per-packet log
IE_DETAILS_FILE    = "./csv_analyze/ie_details_report.csv"        # one row per information element
SUMMARY_DIR        = "./csv_analyze/"                             # directory for daily_summary_DATE.csv files
SUMMARY_PREFIX     = "daily_summary"                 # filename prefix (date appended automatically)
P0                 = -35    # Reference RSSI at 1 metre
N                  = 3.0    # Path-loss exponent (2.0 open space, 3.0 indoors)
SESSION_TIMEOUT    = 600    # Seconds before a session is considered expired
AUTO_SAVE_INTERVAL = 60     # Seconds between auto-save of session summary
GROUP_SCORE_THRESHOLD      = 6
OVERLAP_TOLERANCE_SECONDS  = 5
CHANNEL_HOP_INTERVAL       = 0.5

# ── Capture mode / channel plan ──────────────────────────────────────────────
# These are the defaults used when the matching CLI flag is not supplied AND
# the interactive prompt is skipped (stdin is not a terminal, e.g. nohup/cron).
# Edit them to change what a bare `sudo python3 night_sniffer_v3.py` does.
DEFAULT_CAPTURE_MODE = "hop"    # "camp" = stay on one channel, "hop" = rotate
DEFAULT_BAND         = "2.4"    # "2.4" | "5" | "both" — hop mode only
DEFAULT_CAMP_CHANNEL = 6        # camp mode only

CAPTURE_MODES = ("camp", "hop")
BANDS         = ("2.4", "5", "both")

# 2.4 GHz hop range. Channel 14 is Japan-only and deliberately omitted.
CHANNELS_2GHZ: list[int] = list(range(1, 14))

# 5 GHz hop range — the full regulatory set. Channels 52–144 are DFS
# (radar-shared spectrum). This tool only ever listens and never transmits, so
# the DFS obligation itself does not apply to us, but the kernel still marks
# those channels RADAR/NO-IR and some driver + regulatory-domain combinations
# refuse to tune there anyway. PROBE_HOP_CHANNELS below tests every channel
# once at startup and drops the refusals, so this list never needs hand-
# trimming per adapter or per country.
CHANNELS_5GHZ: list[int] = [
    36, 40, 44, 48,                          # UNII-1  — non-DFS
    52, 56, 60, 64,                          # UNII-2A — DFS
    100, 104, 108, 112, 116,                 # UNII-2C — DFS
    120, 124, 128,                           # UNII-2C — DFS, weather radar
    132, 136, 140, 144,                      # UNII-2C — DFS
    149, 153, 157, 161, 165,                 # UNII-3  — non-DFS
]

# Tune each channel once before hopping starts and keep only the ones the
# driver accepts. Costs PROBE_SETTLE seconds per channel at startup, and saves
# the hopper from burning a full CHANNEL_HOP_INTERVAL dwell on a dead channel
# on every single sweep, forever. Set False to trust the lists above verbatim.
PROBE_HOP_CHANNELS = True
PROBE_SETTLE       = 0.05   # Seconds to let the driver settle between probes

# ── Interface recovery ────────────────────────────────────────────────────────
# When sniff() exits unexpectedly (the adapter drops out of monitor mode),
# the script waits RETRY_DELAY seconds, resets the interface, then tries again.
# It gives up after MAX_RETRIES consecutive failures.
MAX_RETRIES  = 10   # maximum reconnect attempts before giving up
RETRY_DELAY  = 3    # seconds to wait between each attempt

# ── Capture filter ───────────────────────────────────────────────────────────
# Applied by libpcap in the kernel, matching scripts/run_dumpcap.sh. Without it
# every data frame on the channel is copied into userspace only to be discarded
# in Python, and that wasted throughput is what overflows the capture ring under
# load — dropping management frames we wanted, with no counter to show it.
#
# This narrows what the process ever sees, so it sits inside the passive-capture
# constraint rather than against it. Set to None to capture unfiltered; the code
# falls back to unfiltered automatically if libpcap cannot compile the filter
# for the interface's link type, which is what happens when the adapter is not
# actually in monitor mode.
CAPTURE_BPF_FILTER = "type mgt"

# A malformed frame must cost one frame, not the capture. Scapy catches any
# exception escaping the packet callback by closing the capture socket, which
# this script then reads as the adapter dropping out of monitor mode — costing
# RETRY_DELAY seconds and a monitor-mode reset, and giving up entirely after
# MAX_RETRIES of them. handle_packet() therefore swallows and counts instead.
# The first few are logged in full; after that only the count is kept, so a
# systematically bad frame cannot flood the log.
MAX_FRAME_ERROR_LOGS = 5

# ── Management frame subtypes ────────────────────────────────────────────────
# Every 802.11 management subtype (frame control type == 0), IEEE 802.11-2020
# 9.2.4.1.3, mapped to the Pkt_Type label written to the CSV.
#
# classify_frame() reads this subtype field directly instead of testing Scapy
# layer classes, for two measured reasons:
#
#   * Coverage. Scapy binds a layer class to only 12 of the 16 subtypes, so a
#     layer-based allowlist cannot see the rest at all. Probe Response and
#     Action were among the frames being dropped, and those are ordinarily the
#     most common management frames after beacons.
#   * Correctness. Dot11ReassoResp subclasses Dot11AssoResp, and Dot11FCS sets
#     match_subclass = True, which makes Scapy's haslayer() propagate subclass
#     matching down the rest of the layer chain. A Reassociation Response
#     therefore satisfied haslayer(Dot11AssoResp) on any capture carrying an
#     FCS — which is every capture from the AR9271 — and was recorded under the
#     wrong label. The subtype field is unambiguous.
#
# Labels for subtypes that were already tracked are unchanged, so CSVs written
# before and after this change stay comparable. Reserved subtypes get a
# MGMT_<n> label rather than being dropped: an unexpected frame is evidence,
# and dumpcap would have kept it.
MGMT_SUBTYPE_LABELS: dict[int, str] = {
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

# ── 802.11 frame geometry ────────────────────────────────────────────────────
# Where a frame's information elements begin, measured from the frame itself
# rather than inferred from Scapy's layer chain.
#
# Scapy binds an element layer to only some subtypes, so anchoring the element
# walk on getlayer(Dot11Elt) made the elements of every other subtype
# unreachable — an Action frame dissects as Dot11/Dot11Action/Raw and yielded
# nothing at all. Computing the offset from the frame's own header works for
# every subtype and does not depend on Scapy dissecting the body correctly.
MGMT_HEADER_LEN = 24   # frame control(2) duration(2) addr1(6) addr2(6) addr3(6) seq(2)
HT_CONTROL_LEN  = 4    # present only when the +HTC/Order bit is set
FCS_LEN         = 4    # trailing checksum, when radiotap says one is present

# Length of the fixed (non-element) part of each management frame body,
# IEEE 802.11-2020 9.3.3. Subtypes absent from this table — the reserved 7 and
# 15 — have no defined body, so no elements are read from them.
MGMT_FIXED_BODY_LEN: dict[int, int] = {
    0:  4,   # Assoc Req      capability(2) listen interval(2)
    1:  6,   # Assoc Resp     capability(2) status(2) AID(2)
    2:  10,  # Reassoc Req    capability(2) listen interval(2) current AP(6)
    3:  6,   # Reassoc Resp   capability(2) status(2) AID(2)
    4:  0,   # Probe Req      elements only
    5:  12,  # Probe Resp     timestamp(8) beacon interval(2) capability(2)
    6:  10,  # Timing Adv     timestamp(8) capability(2)
    8:  12,  # Beacon         timestamp(8) beacon interval(2) capability(2)
    9:  0,   # ATIM           no body
    10: 2,   # Disassoc       reason code(2)
    11: 6,   # Auth           algorithm(2) sequence(2) status(2)
    12: 2,   # Deauth         reason code(2)
}

# Action frames are the one case where the offset cannot be derived from the
# subtype alone: the body is Category(1) + Action(1) + category-specific fixed
# fields, and only some categories are followed by elements. Keyed by
# (category, action), the value being the offset of the first element from the
# start of the body.
#
# Only combinations whose fixed fields are unconditional appear here. WNM BSS
# Transition (category 10, actions 7 and 8) is deliberately absent: its fixed
# part has optional fields whose presence depends on flags earlier in the same
# frame, so a fixed offset would be wrong for some frames and right for others.
#
# Marked *verify* against a real capture — these come from the standard, not
# from measurement. A wrong entry cannot corrupt the CSV: _action_element_bytes
# accepts a candidate only if the walk tiles it exactly, so a bad offset yields
# no elements rather than invented ones.
ACTION_ELEMENT_OFFSETS: dict[tuple[int, int], int] = {
    (5, 0):  5,   # Radio Measurement Request   +token(1) repetitions(2)
    (5, 1):  3,   # Radio Measurement Report    +token(1)
    (5, 2):  5,   # Link Measurement Request    +token(1) tx power(1) max power(1)
    (5, 3):  3,   # Link Measurement Report     +token(1), TPC report is an element
    (5, 4):  3,   # Neighbor Report Request     +token(1)
    (5, 5):  3,   # Neighbor Report Response    +token(1)
    (6, 1):  14,  # FT Request                  +STA(6) target AP(6)
    (6, 2):  16,  # FT Response                 +STA(6) target AP(6) status(2)
    (6, 3):  14,  # FT Confirm                  +STA(6) target AP(6)
    (6, 4):  16,  # FT Ack                      +STA(6) target AP(6) status(2)
}

# Frame types that feed session tracking and the device-count model. This is
# deliberately NOT every client-originated subtype: it is the set the scorer in
# _same_randomized_session_score() was tuned against. Subtypes added to
# MGMT_SUBTYPE_LABELS are captured, fingerprinted and logged, but stay out of
# the count until that model is reviewed — widening capture and widening the
# device count are separate decisions.
CLIENT_FRAME_TYPES = {
    "PROBE", "ASSOC_REQ", "REASSOC_REQ", "AUTH", "DEAUTH", "DISASSOC",
}

# Which frame types appear in the real-time terminal log. This affects the
# terminal output only — every frame is still written to the CSV regardless.
#   "all"       → print every tracked frame type
#   "no-beacon" → print every frame except BEACON
# Set from the --frames CLI flag in main().
TERMINAL_FRAME_FILTER = "all"

# ── Offline replay (--pcap) ──────────────────────────────────────────────────
# Replay feeds a previously recorded pcap through the exact same handle_packet()
# path as a live capture, so a dumpcap file can be measured against this tool on
# identical input. Nothing here touches the radio: replay never opens an
# interface, never tunes a channel and never starts the hopper.
#
# REPLAY_MODE also switches the time source. Live capture timestamps a frame at
# the moment it is received; a replay must instead use the capture time stored
# in the pcap, or a whole night collapses into the few seconds the replay takes
# and both Interval_sec and SESSION_TIMEOUT become measurements of our own
# parsing speed. Set from the --pcap CLI flag in main().
REPLAY_MODE = False

# Capture time of the frame currently being handled, published by _frame_time()
# for the session tracker to read via _now(). Always None during live capture,
# which is what makes _now() fall back to the wall clock there. Only ever
# written from the single sniff() thread, and the auto-save thread that would
# otherwise race it is not started in replay mode.
_CURRENT_FRAME_TIME: float | None = None

CSV_FIELDS = [
    "Timestamp", "Pkt_Type", "MAC_Address", "Device_Type",
    "Vendor", "SSID", "Channel", "Band", "Power_dBm", "Distance_m",
    "Interval_sec", "IE_Sequence", "IE_Fingerprint", "Vendor_IEs",
    "Capabilities", "Note", "Session_Note", "Seq_Num",
    "Listen_Interval", "Cap_Info", "Current_AP",
    "Security_Tier", "Auth_Status", "Reason_Code", "Direction",
    # The complete 802.11 frame as captured, hex-encoded, checksum included.
    # Every other column is derived from these bytes, so anything this tool
    # cannot decode yet is still recoverable from the log afterwards without
    # re-capturing. Kept last so column positions above it never move.
    # Set --raw-frames on to populate it; off (the default) leaves it empty.
    "Frame_Hex",
]

# Whether Frame_Hex is populated. Management frames only, which is the same
# scope scripts/run_dumpcap.sh already writes to pcap_files/ — this adds no new
# collection surface, it keeps the bytes alongside the decoded columns.
# Set from the --raw-frames CLI flag in main().
CAPTURE_RAW_FRAMES = False

# Column layout for the per-IE breakdown file (one row per information element).
IE_CSV_FIELDS = [
    "Timestamp", "Pkt_Type", "MAC_Address", "IE_Index", "IE_ID",
    "IE_Name", "IE_Length", "IE_Raw_Hex", "IE_Decoded",
]

# Human-readable names for the 802.11 information-element IDs we care about.
IE_NAMES: dict[int, str] = {
    0:   "SSID",
    1:   "Supported Rates",
    3:   "DS Parameter Set",
    5:   "TIM",
    7:   "Country",
    11:  "QBSS Load",
    32:  "Power Constraint",
    33:  "Power Capability",
    35:  "TPC Report",
    36:  "Supported Channels",
    42:  "ERP Info",
    45:  "HT Capabilities",
    48:  "RSN",
    50:  "Extended Supported Rates",
    54:  "Mobility Domain",
    59:  "Supported Operating Classes",
    61:  "HT Operation",
    70:  "RM Enabled Capabilities",
    74:  "Overlapping BSS Scan Params",
    107: "Interworking",
    108: "Advertisement Protocol",
    127: "Extended Capabilities",
    191: "VHT Capabilities",
    192: "VHT Operation",
    195: "VHT Tx Power Envelope",
    221: "Vendor Specific",
    255: "Element Extension",
}

# Pseudo IE IDs for the parts of a frame body that are not information
# elements. Negative so they can never collide with a real 8-bit element ID,
# and so `IE_ID < 0` selects every non-element row in a report.
PSEUDO_IE_FIXED    = -1   # fixed parameters ahead of the element region
PSEUDO_IE_UNPARSED = -2   # bytes with no known layout, preserved verbatim

# Action frame categories, IEEE 802.11-2020 9.4.1.11. Used to label the fixed
# parameters of an Action frame in the per-IE report — the category is the most
# informative byte in the frame and would otherwise only exist as raw hex.
ACTION_CATEGORY_NAMES: dict[int, str] = {
    0:  "Spectrum Management",
    1:  "QoS",
    2:  "DLS",
    3:  "Block Ack",
    4:  "Public",
    5:  "Radio Measurement",
    6:  "Fast BSS Transition",
    7:  "HT",
    8:  "SA Query",
    9:  "Protected Dual of Public Action",
    10: "WNM",
    11: "Unprotected WNM",
    12: "TDLS",
    13: "Mesh",
    14: "Multihop",
    15: "Self-protected",
    16: "DMG",
    17: "Wi-Fi Alliance",
    18: "Fast Session Transfer",
    19: "Robust AV Streaming",
    20: "Unprotected DMG",
    21: "VHT",
    126: "Vendor Specific Protected",
    127: "Vendor Specific",
}

# ── Fingerprint algorithm version ────────────────────────────────────────────
# Bump ONLY when the INPUT to the SHA-1 in extract_ie_details() changes: the
# excluded-tag set, the byte window, or the separator format. Adding CSV
# columns, changing capability flags, or fixing vendor attribution does NOT
# bump this.
#
# v1 → v2 (2026-08-13): excluded volatile tags {0, 3} from the hash input;
#                       removed the 8-byte truncation, now hashes full IE
#                       content. v1 and v2 values are not comparable.
FINGERPRINT_VERSION = 2

# Tags excluded from the fingerprint hash because they vary WITHIN a device
# rather than between devices:
#   0 — SSID. A wildcard probe and a directed probe from one phone, seconds
#       apart, produce different hashes.
#   3 — DS Parameter Set. Carries the channel the device is probing on, which
#       our own hop sweep changes. Excluded UNCONDITIONALLY — making this
#       mode-dependent would silently make camp and hop captures incomparable,
#       which is the same class of bug being fixed here.
# Both remain in ie_sequence, which correctly records presence and order.
VOLATILE_IE_IDS = frozenset({0, 3})

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known OUI Dictionary  (OUI hex → friendly name)
# ---------------------------------------------------------------------------

KNOWN_OUIS: dict[str, str] = {
    "00:17:f2": "Apple, Inc.",
    "00:00:f0": "Samsung Electronics",
    "00:e0:fc": "Huawei Technologies",
    "ac:f7:f3": "Xiaomi Communications",
    "f8:a4:5f": "Oppo Mobile",
    "d4:f5:13": "Vivo Mobile",
    "00:1a:11": "Google (Pixel/Nest)",
    "00:16:ea": "Intel Corp (Laptop)",
    "00:50:f2": "Microsoft (Surface/WPS)",
    "00:10:18": "Broadcom",
    "00:23:45": "Foxconn",
    "4c:ed:de": "AzureWave (IoT/Laptop)",
    "50:c7:bf": "TP-Link",
    "00:00:0c": "Cisco Systems",
    "00:0f:3d": "D-Link",
    "00:bb:3a": "Amazon (Echo/Kindle)",
    "24:b2:de": "Espressif (IoT/SmartHome)",
    "84:e1:ba": "Tuya Smart (IoT)",
    "00:04:1f": "Sony Interactive (PS)",
    "00:1f:32": "Nintendo (Switch)",
    "44:fb:42": "Tesla, Inc.",
}

# Protocol markers that do not identify the device manufacturer. 00:50:f2 is
# commonly carried by WMM/WPS IEs on devices made by many different vendors.
NON_DEVICE_VENDOR_IE_OUIS = {"00:50:f2"}

# ANSI colour codes
COLOUR_RESET  = "\033[0m"
COLOUR_RED    = "\033[91m"
COLOUR_BLUE   = "\033[94m"
COLOUR_YELLOW = "\033[93m"
COLOUR_GREY   = "\033[90m"

# ---------------------------------------------------------------------------
# Session data
# ---------------------------------------------------------------------------

@dataclass
class Session:
    last_mac: str
    all_macs: set = field(default_factory=set)
    fingerprint: str = ""
    ie_fingerprints: set = field(default_factory=set)
    vendor_ies: set = field(default_factory=set)
    mac_type: str = ""
    rssi: int = 0
    rssi_min: int = 0
    rssi_max: int = 0
    rssi_total: int = 0
    rssi_count: int = 0
    zone: str = ""
    frame_types: set = field(default_factory=set)
    ssids: set = field(default_factory=set)
    first_ts: float = field(default_factory=time.time)
    last_ts: float = field(default_factory=time.time)
    last_seq: int | None = None
    current_aps:      set = field(default_factory=set)   # roaming lineage
    listen_intervals: set = field(default_factory=set)   # OS/driver hint
    security_tiers:   set = field(default_factory=set)   # Open / FT / WPA3-SAE


active_sessions: dict[int, Session] = {}
_session_lock = threading.Lock()
_last_seen: dict[str, float] = {}

# ---------------------------------------------------------------------------
# Vendor lookup (with graceful fallback)
# ---------------------------------------------------------------------------

log.info("Initialising vendor database …")
_vendor_lookup = MacLookup()
try:
    _vendor_lookup.update_metadata()
    log.info("Vendor database updated.")
except Exception:
    log.warning("Could not update vendor database – using cached copy.")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def apply_output_dir(out_dir: str) -> None:
    """
    Redirect all three report files into ``out_dir``, creating it if needed.

    Exists so a replay can be written somewhere other than the live capture's
    output. Without it, replaying a pcap would append to the accumulating
    wifi_full_recon_report.csv and — worse — setup_ie_csv() opens the per-IE
    report with mode "w", so a replay would truncate the IE breakdown belonging
    to a real capture. Basenames are kept exactly as configured above so the
    parity tooling and fingerprint_baseline.py find the same filenames.
    """
    global LOG_FILE, IE_DETAILS_FILE, SUMMARY_DIR
    os.makedirs(out_dir, exist_ok=True)
    LOG_FILE        = os.path.join(out_dir, os.path.basename(LOG_FILE))
    IE_DETAILS_FILE = os.path.join(out_dir, os.path.basename(IE_DETAILS_FILE))
    SUMMARY_DIR     = out_dir


# ── Output file handles ──────────────────────────────────────────────────────
# Both reports were being opened, written and closed once per frame — four extra
# syscalls per frame on an SD card, at beacon rates. The handles are held open
# instead and flushed after every row, so `tail -f` and a hard power-off both
# still see every row that was written.
_open_writers: dict[str, "object"] = {}
_writer_lock = threading.Lock()


def _writer_for(path: str):
    """Return a cached append-mode handle for ``path``, opening it if needed."""
    handle = _open_writers.get(path)
    if handle is None or handle.closed:
        handle = open(path, "a", newline="")
        _open_writers[path] = handle
    return handle


def _close_writer(path: str) -> None:
    """Drop any cached handle for ``path`` so the file can be re-created."""
    handle = _open_writers.pop(path, None)
    if handle is not None and not handle.closed:
        handle.close()


def close_output_files() -> None:
    """Flush and close every report handle. Called once on the way out."""
    with _writer_lock:
        for path in list(_open_writers):
            _close_writer(path)


def setup_csv() -> None:
    """Create CSV with header row if the file does not yet exist."""
    with _writer_lock:
        _close_writer(LOG_FILE)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as fh:
            csv.writer(fh).writerow(CSV_FIELDS)


def setup_ie_csv() -> None:
    """
    Start a fresh per-IE breakdown CSV with its header row.

    Unlike the main recon log (which accumulates across runs), this file is
    truncated on every startup so it only holds the current session's IEs —
    mirroring the daily summary. That keeps the two reports aligned for
    cross-checking devices seen in the same session.
    """
    # Drop any cached append handle first: truncating the file underneath one
    # would leave later rows writing past a hole at the old offset.
    with _writer_lock:
        _close_writer(IE_DETAILS_FILE)
    with open(IE_DETAILS_FILE, "w", newline="") as fh:
        csv.writer(fh).writerow(IE_CSV_FIELDS)


def calculate_distance(rssi: int) -> float:
    """Estimate distance (metres) from RSSI using the log-distance path-loss model."""
    if not rssi:
        return 0.0
    try:
        return round(math.pow(10, (P0 - rssi) / (10 * N)), 2)
    except (ValueError, ZeroDivisionError):
        return 0.0


def seq_delta(new_seq: int, last_seq: int) -> int:
    """Forward distance between two 12-bit sequence numbers, wraparound-aware.

    Returns (new_seq - last_seq) mod 4096. Small positive values indicate a
    plausible same-radio continuation across MAC rotation; this is consumed in
    Phase 2, not here.
    """
    return (new_seq - last_seq) % 4096


def proximity_zone(distance_m: float) -> str:
    """Return a coarse room-distance bucket for grouping decisions."""
    if distance_m <= 0:
        return "unknown"
    if distance_m <= 2:
        return "immediate"
    if distance_m <= 7:
        return "near"
    if distance_m <= 20:
        return "mid"
    return "far"


def check_mac_type(mac: str) -> str:
    """Return 'Randomized' if the MAC is locally administered, else 'Real'."""
    try:
        first_byte = int(mac.split(":")[0], 16)
        return "Randomized" if (first_byte & 0x02) else "Real"
    except (ValueError, IndexError):
        return "Unknown"


def get_vendor(mac: str, mac_type: str) -> str:
    """Look up manufacturer name; only meaningful for non-randomised MACs."""
    if mac_type != "Real":
        return "Randomized/Unknown"
    try:
        return _vendor_lookup.lookup(mac)
    except Exception:
        return "Unknown"


def oui_from_mac(mac: str) -> str:
    """Return the colon-separated OUI prefix (lower-case) from a MAC string."""
    parts = mac.replace(":", "").lower()
    return ":".join(parts[i:i+2] for i in range(0, 6, 2))


def lookup_oui(oui_hex: str) -> str:
    """Return a friendly vendor name from KNOWN_OUIS, or a default string."""
    return KNOWN_OUIS.get(oui_hex.lower(), f"Unknown({oui_hex})")


def vendor_from_ie_ouis(vendor_ies: str) -> str:
    """
    Resolve a friendly vendor name from Vendor Specific (tag 221) OUIs.

    Used for randomized MACs, which carry no real vendor OUI of their own —
    but the tag-221 elements a device advertises still leak the chipset /
    software-stack vendor. Tries the curated KNOWN_OUIS names first, falls
    back to the full mac_vendor_lookup database, and finally returns the raw
    OUI list when nothing resolves. Protocol-only OUIs such as 00:50:f2 are
    excluded. Returns "Unknown" when no attributable tag-221 OUIs remain.
    """
    ouis = sorted(
        {oui.lower() for oui in _parse_set(vendor_ies)}
        - NON_DEVICE_VENDOR_IE_OUIS
    )
    if not ouis:
        return "Unknown"
    for oui in ouis:
        name = lookup_oui(oui)
        if "Unknown" not in name:
            return name
    for oui in ouis:
        try:
            name = _vendor_lookup.lookup(oui + ":00:00:00")
        except Exception:
            continue
        if name:
            return name
    return f"Unknown({';'.join(ouis)})"


def oui_int_to_str(raw_oui: int) -> str:
    """Convert a 3-byte integer OUI to colon-separated hex string."""
    return ":".join(f"{b:02x}" for b in raw_oui.to_bytes(3, "big"))


def _format_ts(ts: float) -> str:
    """Return a full local timestamp for session reports."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _frame_time(pkt) -> float:
    """
    Return the time this frame should be attributed to, and publish it for _now().

    Live capture keeps the historical behaviour exactly: the frame arrived just
    now, so the wall clock is the right answer and _CURRENT_FRAME_TIME is left
    None so _now() stays on the wall clock too.

    Replay reads the capture time recorded in the pcap. Scapy hands that back as
    an EDecimal; it is converted once here so no downstream arithmetic ends up
    mixing Decimal with float. A pcap frame with no usable time falls back to
    the wall clock rather than raising inside the packet callback.
    """
    global _CURRENT_FRAME_TIME
    if not REPLAY_MODE:
        _CURRENT_FRAME_TIME = None
        return time.time()
    raw = getattr(pkt, "time", None)
    _CURRENT_FRAME_TIME = time.time() if raw is None else float(raw)
    return _CURRENT_FRAME_TIME


def _now() -> float:
    """
    Current time for session bookkeeping: frame time in replay, wall clock live.

    Session expiry, merge time windows and stay durations all have to run on the
    same clock as the frames feeding them, or a replayed capture never expires a
    session and reports one long stay per device.
    """
    return time.time() if _CURRENT_FRAME_TIME is None else _CURRENT_FRAME_TIME


def _safe_upper_mac(mac: str | None) -> str:
    """Normalize a MAC address, or return an empty string for malformed frames."""
    return mac.upper() if mac else ""


# ---------------------------------------------------------------------------
# Interface recovery
# ---------------------------------------------------------------------------

def reset_monitor_mode(iface: str) -> None:
    """
    Re-establish monitor mode after the adapter drops out.

    Runs three commands in sequence — the same ones you'd type manually:
        ip link set <iface> down
        iw dev <iface> set type monitor
        ip link set <iface> up

    Uses subprocess.run (already used in channel_hopper) rather than
    os.system so we get a return code and can log failures cleanly.
    A 1-second sleep after bringing the interface back up gives the
    kernel/driver time to settle before sniff() is called again.
    """
    log.warning("Attempting to reset monitor mode on %s …", iface)
    commands = [
        ["ip",  "link", "set", iface, "down"],
        ["iw",  "dev",  iface, "set", "type", "monitor"],
        ["ip",  "link", "set", iface, "up"],
    ]
    for cmd in commands:
        result = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            log.warning("  cmd %s failed: %s", " ".join(cmd), result.stderr.strip())
    time.sleep(1)


# ---------------------------------------------------------------------------
# Channel control
# ---------------------------------------------------------------------------

def set_channel(iface: str, channel: int, quiet: bool = False) -> bool:
    """
    Tune ``iface`` to ``channel`` and report whether the driver accepted it.

    Purely receive-side configuration — retuning the radio transmits nothing,
    so this stays inside the passive-capture constraint.

    ``quiet`` suppresses the per-failure warning; probe_channels() sets it so
    that testing 38 channels does not produce 38 warning lines.
    """
    result = subprocess.run(
        ["iw", "dev", iface, "set", "channel", str(channel)],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        if not quiet:
            log.warning("Channel set to %s failed: %s", channel, result.stderr.strip())
        return False
    return True


def _channel_band_label(channel: int) -> str:
    """
    Name the band a channel number belongs to, for logging and camp validation.

    Resolved against the configured lists rather than hardcoded ranges, so
    trimming CHANNELS_5GHZ is reflected here too.
    """
    if channel in CHANNELS_2GHZ:
        return "2.4GHz"
    if channel in CHANNELS_5GHZ:
        return "5GHz"
    return "unknown"


def build_hop_channels(band: str) -> list[int]:
    """
    Return the ordered channel list the hopper rotates through for ``band``.

    "both" is a single concatenated rotation walked by the one hopper thread —
    not two threads and not an alternating interleave. That keeps the dwell
    behaviour identical to a single-band sweep, at the cost of a proportionally
    longer revisit time for any individual channel.
    """
    if band == "2.4":
        return list(CHANNELS_2GHZ)
    if band == "5":
        return list(CHANNELS_5GHZ)
    if band == "both":
        return list(CHANNELS_2GHZ) + list(CHANNELS_5GHZ)
    raise ValueError(f"Unknown band: {band!r} (expected one of {BANDS})")


def probe_channels(iface: str, channels: list[int]) -> list[int]:
    """
    Return the subset of ``channels`` this adapter + regulatory domain accepts.

    Each channel is tuned once and the return code checked. Anything the driver
    refuses — most often DFS/no-IR channels, sometimes 12/13 under a US
    regdomain — is dropped so the hopper never wastes a dwell slot on it.

    If nothing at all is tunable the interface is almost certainly not in
    monitor mode, so we say so loudly and hand back the original list rather
    than leaving the caller with an empty rotation.
    """
    log.info("Probing %d channel(s) on %s for tunability …", len(channels), iface)
    usable:  list[int] = []
    refused: list[int] = []
    for channel in channels:
        if set_channel(iface, channel, quiet=True):
            usable.append(channel)
        else:
            refused.append(channel)
        time.sleep(PROBE_SETTLE)

    if not usable:
        log.error("No channels are tunable on %s — is it in monitor mode and up?", iface)
        log.error(
            "  sudo ip link set %s down && sudo iw dev %s set type monitor "
            "&& sudo ip link set %s up", iface, iface, iface,
        )
        log.warning("Falling back to the unverified channel list.")
        return list(channels)

    log.info("  usable  (%d): %s", len(usable), ",".join(str(c) for c in usable))
    if refused:
        log.warning(
            "  refused (%d): %s", len(refused), ",".join(str(c) for c in refused)
        )
    return usable


# ---------------------------------------------------------------------------
# Packet fingerprinting
# ---------------------------------------------------------------------------

def _walk_tlvs(buf: bytes) -> tuple[list[tuple[int, bytes]], int]:
    """
    Parse ``buf`` as a run of [ID][len][data] information elements.

    Returns the elements found and how many bytes they consumed. The caller
    compares that against ``len(buf)`` to see whether the region tiled cleanly:
    anything left over is a partial element from a snaplen-truncated capture, or
    a region that is not element-structured at all. Either way the leftover
    bytes are the caller's to keep — this function never decides they are
    uninteresting.
    """
    elements: list[tuple[int, bytes]] = []
    i = 0
    while i + 2 <= len(buf):
        ie_len = buf[i + 1]
        end    = i + 2 + ie_len
        if end > len(buf):
            break
        elements.append((buf[i], buf[i + 2:end]))
        i = end
    return elements, i


@dataclass(frozen=True)
class FrameParts:
    """
    Every byte of a captured frame, split into regions. Nothing is discarded.

    ``fixed + elements + unparsed`` always reconstructs the frame body exactly,
    and ``header + body + fcs`` reconstructs the whole frame. Where the layout
    is unknown — a reserved subtype, an Action category with no entry in
    ACTION_ELEMENT_OFFSETS — the bytes land in ``unparsed`` rather than being
    dropped, so they still reach the reports and can be decoded later.
    """
    subtype:  int                # -1 when the frame is not readable management
    header:   bytes = b""        # MAC header, including HT Control when present
    fixed:    bytes = b""        # fixed (non-element) body fields
    elements: bytes = b""        # region successfully parsed as elements
    unparsed: bytes = b""        # everything not attributed above
    fcs:      bytes = b""        # trailing checksum, when radiotap flagged one

    @property
    def body(self) -> bytes:
        """The complete frame body, however much of it could be attributed."""
        return self.fixed + self.elements + self.unparsed

    @property
    def frame(self) -> bytes:
        """The complete frame as captured, checksum included."""
        return self.header + self.body + self.fcs


def _split_action_body(body: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Split an Action frame body into (fixed, elements, unparsed).

    Action bodies are Category(1) + Action(1) + category-specific fixed fields,
    and only some categories are followed by elements, so the element offset
    cannot be derived from the subtype alone. When ACTION_ELEMENT_OFFSETS has no
    entry, or its entry does not fit the frame, the remainder is returned as
    ``unparsed`` — kept verbatim for later decoding rather than thrown away.
    """
    if len(body) < 2:
        return body, b"", b""

    offset = ACTION_ELEMENT_OFFSETS.get((body[0], body[1]))
    if offset is not None and offset <= len(body):
        candidate = body[offset:]
        _found, consumed = _walk_tlvs(candidate)
        # The offset is the one input here that comes from a table rather than
        # from the frame, so it must earn its keep: accept it only if it tiles
        # exactly, otherwise treat the region as unparsed rather than invent
        # elements from a wrong offset.
        if consumed == len(candidate):
            return body[:offset], candidate, b""

    return body[:2], b"", body[2:]


def _frame_parts(pkt) -> FrameParts:
    """
    Split a captured management frame into its regions, losing nothing.

    Works from the captured bytes and the frame's own header rather than Scapy's
    dissection, so the element region is the same one tshark would parse and the
    result does not depend on Scapy recognising the subtype.
    """
    dot11 = pkt.getlayer(Dot11)
    if dot11 is None:
        return FrameParts(subtype=-1)

    # .original is exactly what Scapy was handed for this layer. bytes() is a
    # fallback for frames built in memory, where the two are equal anyway — and
    # it is guarded, because a layer that cannot be re-serialised would
    # otherwise raise inside the packet callback and cost the whole frame.
    raw = getattr(dot11, "original", b"")
    if not raw:
        try:
            raw = bytes(dot11)
        except Exception:
            return FrameParts(subtype=-1)

    # A Dot11FCS layer means radiotap advertised a trailing checksum. It is held
    # separately so it is neither walked as a bogus element nor lost.
    fcs = b""
    if hasattr(dot11, "fcs") and len(raw) >= FCS_LEN:
        raw, fcs = raw[:-FCS_LEN], raw[-FCS_LEN:]

    # Frame control byte 0: bits 2-3 type, bits 4-7 subtype.
    if len(raw) < MGMT_HEADER_LEN or (raw[0] >> 2) & 0x03 != 0:
        return FrameParts(subtype=-1, unparsed=raw, fcs=fcs)

    subtype    = (raw[0] >> 4) & 0x0F
    header_len = MGMT_HEADER_LEN
    if raw[1] & 0x80:                       # +HTC/Order: HT Control follows seq
        header_len += HT_CONTROL_LEN
    header, body = raw[:header_len], raw[header_len:]

    if subtype in (13, 14):                 # Action, Action No Ack
        fixed, elements, unparsed = _split_action_body(body)
    else:
        fixed_len = MGMT_FIXED_BODY_LEN.get(subtype)
        if fixed_len is None:
            # Reserved subtype: the standard defines no body, so nothing can be
            # attributed. The bytes are still kept and reported.
            fixed, elements, unparsed = b"", b"", body
        else:
            fixed_len = min(fixed_len, len(body))
            fixed, rest = body[:fixed_len], body[fixed_len:]
            _found, consumed = _walk_tlvs(rest)
            elements, unparsed = rest[:consumed], rest[consumed:]

    return FrameParts(subtype, header, fixed, elements, unparsed, fcs)


def _iter_ies(pkt):
    """
    Yield ``(ie_id, info_bytes)`` for every 802.11 information element in a frame.

    ``info_bytes`` is the element's full payload, exactly as it appeared on the
    wire — for a Vendor Specific element that includes the three OUI bytes.

    Only the element-structured region is yielded. Bytes that are not elements
    are not lost: they reach the per-IE report through dump_ie_details(), and
    the whole frame is preserved in the Frame_Hex column.
    """
    yield from _walk_tlvs(_frame_parts(pkt).elements)[0]


def extract_ie_details(pkt) -> dict[str, str]:
    """
    Extract stable 802.11 information-element evidence for later grouping.
    """
    sequence: list[str] = []
    fingerprint_parts: list[str] = []
    vendor_ies: set[str] = set()
    capability_flags: set[str] = set()

    for ie_id, info in _iter_ies(pkt):
        sequence.append(str(ie_id))
        if ie_id not in VOLATILE_IE_IDS:
            fingerprint_parts.append(f"{ie_id}:{len(info)}:{info.hex()}")

        if ie_id == 45:
            capability_flags.add("HT")
        elif ie_id == 48:
            capability_flags.add("RSN")
        elif ie_id == 50:
            capability_flags.add("EXT_RATES")
        elif ie_id in {191, 192}:
            capability_flags.add("VHT")
        elif ie_id == 127:
            capability_flags.add("EXT_CAP")
        elif ie_id == 255 and info:
            # Tag 255 is a container, not a leaf element: the first payload byte
            # selects which element it carries. Ext IDs per IEEE 802.11-2024.
            # The `and info` guard matters — a zero-length tag 255 is malformed
            # but reachable from a truncated frame, and info[0] would raise
            # IndexError inside the packet callback.
            ext_id = info[0]
            if ext_id in (35, 36):
                capability_flags.add("HE")
            elif ext_id == 108:
                capability_flags.add("EHT")   # marked *verify* in vendor_ie_reference.md
            else:
                # Unrecognised extensions become discovery data rather than
                # silence. `capabilities` is not an input to the merge scorer,
                # so this costs nothing beyond CSV column noise.
                capability_flags.add(f"EXT{ext_id}")
        elif ie_id == 221 and len(info) >= 3:
            oui = ":".join(f"{b:02x}" for b in info[:3])
            vendor_ies.add(oui)
            if len(info) >= 4 and info[:4] == b"\x00\x50\xf2\x04":
                capability_flags.add("WPS")

    raw_fingerprint = "|".join(fingerprint_parts)
    ie_fingerprint  = (
        f"fp{FINGERPRINT_VERSION}:"
        f"{hashlib.sha1(raw_fingerprint.encode('ascii')).hexdigest()[:16]}"
        if raw_fingerprint else ""
    )

    return {
        "ie_sequence":  ",".join(sequence),
        "ie_fingerprint": ie_fingerprint,
        "vendor_ies":   ";".join(sorted(vendor_ies)),
        "capabilities": ";".join(sorted(capability_flags)),
    }


def _decode_ie(ie_id: int, info: bytes) -> str:
    """
    Best-effort human-readable decode of a single information element's payload.

    Only the common, cheaply-decodable tags are expanded; everything else
    returns an empty string and callers fall back to the raw hex column.
    """
    try:
        if ie_id == 0:  # SSID
            return info.decode("utf-8", errors="ignore") or "(Wildcard/Hidden)"
        if ie_id in (1, 50):  # (Extended) Supported Rates, in 0.5 Mbps units
            rates = [f"{(b & 0x7f) / 2:g}" for b in info]
            return "Mbps: " + ",".join(rates) if rates else ""
        if ie_id == 3 and info:  # DS Parameter Set
            return f"Channel {info[0]}"
        if ie_id == 7 and len(info) >= 2:  # Country
            return "Country " + info[:2].decode("ascii", errors="ignore")
        if ie_id == 42 and info:  # ERP Info
            return f"ERP 0x{info[0]:02x}"
        if ie_id == 221 and len(info) >= 3:  # Vendor Specific
            oui = ":".join(f"{b:02x}" for b in info[:3])
            return f"OUI {oui} ({lookup_oui(oui)})"
    except Exception:
        return ""
    return ""


def _decode_fixed(subtype: int, fixed: bytes) -> str:
    """
    Best-effort label for a frame's fixed parameters, for the per-IE report.

    Only the fields that are cheap and unambiguous are named; the full bytes are
    in the IE_Raw_Hex column of the same row either way, so anything not decoded
    here is still recoverable.
    """
    try:
        if subtype in (13, 14) and len(fixed) >= 2:      # Action, Action No Ack
            category, action = fixed[0], fixed[1]
            name = ACTION_CATEGORY_NAMES.get(category, f"Category {category}")
            return f"{name}, action {action}"
        if subtype in (0, 2) and len(fixed) >= 4:        # (Re)Assoc Request
            return f"cap 0x{int.from_bytes(fixed[0:2], 'little'):04x}, " \
                   f"listen interval {int.from_bytes(fixed[2:4], 'little')}"
        if subtype in (1, 3) and len(fixed) >= 6:        # (Re)Assoc Response
            return f"cap 0x{int.from_bytes(fixed[0:2], 'little'):04x}, " \
                   f"status {int.from_bytes(fixed[2:4], 'little')}, " \
                   f"AID {int.from_bytes(fixed[4:6], 'little')}"
        if subtype in (5, 8) and len(fixed) >= 12:       # Probe Response, Beacon
            return f"beacon interval {int.from_bytes(fixed[8:10], 'little')} TU, " \
                   f"cap 0x{int.from_bytes(fixed[10:12], 'little'):04x}"
        if subtype == 11 and len(fixed) >= 6:            # Authentication
            return f"algo {int.from_bytes(fixed[0:2], 'little')}, " \
                   f"seq {int.from_bytes(fixed[2:4], 'little')}, " \
                   f"status {int.from_bytes(fixed[4:6], 'little')}"
        if subtype in (10, 12) and len(fixed) >= 2:      # Disassoc, Deauth
            return f"reason {int.from_bytes(fixed[0:2], 'little')}"
    except Exception:
        return ""
    return ""


def dump_ie_details(pkt, timestamp: str, pkt_type: str, mac_addr: str) -> None:
    """
    Append one row per region of the frame body to IE_DETAILS_FILE.

    Where the main recon log records a single row per packet, this breaks each
    frame down region by region so its raw content can be inspected offline.

    Every byte of the body appears in exactly one row. Information elements get
    a row each, as before. The fixed parameters ahead of them, and any region
    that is not element-structured — a reserved subtype's body, an Action
    category with no offset entry, a snaplen-truncated tail — get their own rows
    under the pseudo-IDs below, rather than being dropped because nothing here
    knows how to decode them yet. Concatenating IE_Raw_Hex across a frame's rows
    reproduces the body exactly.
    """
    parts = _frame_parts(pkt)
    rows  = []
    index = 0

    if parts.fixed:
        rows.append([
            timestamp, pkt_type, mac_addr, index, PSEUDO_IE_FIXED,
            "Fixed Parameters", len(parts.fixed), parts.fixed.hex(),
            _decode_fixed(parts.subtype, parts.fixed),
        ])
        index += 1

    for ie_id, info in _walk_tlvs(parts.elements)[0]:
        rows.append([
            timestamp, pkt_type, mac_addr, index, ie_id,
            IE_NAMES.get(ie_id, f"Unknown({ie_id})"),
            len(info), info.hex(), _decode_ie(ie_id, info),
        ])
        index += 1

    if parts.unparsed:
        rows.append([
            timestamp, pkt_type, mac_addr, index, PSEUDO_IE_UNPARSED,
            "Unparsed Bytes", len(parts.unparsed), parts.unparsed.hex(),
            "not element-structured; kept verbatim",
        ])
        index += 1

    if not rows:
        return
    with _writer_lock:
        handle = _writer_for(IE_DETAILS_FILE)
        csv.writer(handle).writerows(rows)
        handle.flush()


def extract_ssid(pkt, fallback: str) -> str:
    """
    Read an SSID only from the tag-0 information element.

    Sourced from the same walk as everything else rather than from Scapy's
    layer chain, so it reads the SSID of any subtype that carries one.
    """
    for ie_id, info in _iter_ies(pkt):
        if ie_id == 0:
            return info.decode("utf-8", errors="ignore") or fallback
    return fallback


def get_correlation_identity(pkt) -> str:
    """
    Derive a human-readable device identity from a Probe Request or Beacon.
    Priority: Vendor Specific Tag (221) > MAC OUI > generic fallback.
    """
    vendor       = "Generic"
    region       = "Unknown"
    is_apple     = False
    found_oui    = "None"

    try:
        src_mac = _safe_upper_mac(getattr(pkt, "addr2", None))
        if not src_mac:
            src_mac = _safe_upper_mac(getattr(pkt, "addr3", None))
        mac_oui = oui_from_mac(src_mac)
        vendor  = lookup_oui(mac_oui)
    except Exception:
        pass

    # Element access goes through the same raw walk as the rest of the file.
    # Scapy's Dot11EltVendorSpecific chain stops at the first element it cannot
    # dissect, and vendor elements sit late in a frame — exactly where that
    # truncation bites. The decision logic below is unchanged: `info` here is
    # the element's full payload, which is what el.info returned too.
    for ie_id, info in _iter_ies(pkt):
        try:
            if ie_id == 221 and len(info) >= 3:
                raw_oui    = int.from_bytes(info[:3], "big")
                oui_str    = oui_int_to_str(raw_oui)
                found_oui  = oui_str
                # The vendor type is the octet AFTER the three OUI octets.
                # This previously read info[0], which is the first byte of the
                # OUI and therefore never 0x02 or 0x04 — so the WMM/WPS guard
                # below could never fire and any device advertising WMM or WPS
                # was reported as "Microsoft (Surface/WPS)". The behaviour
                # asserted by test_wmm_vendor_tag_does_not_imply_windows_or_
                # microsoft only held because that test's fake element supplied
                # info without the OUI.
                vendor_type = info[3] if len(info) >= 4 else None
                is_wmm_or_wps = (raw_oui, vendor_type) in {
                    (0x0050F2, 0x02),
                    (0x0050F2, 0x04),
                }
                if not is_wmm_or_wps and not (
                    raw_oui == 0x0050F2 and vendor_type is None
                ):
                    tag_vendor = lookup_oui(oui_str)
                    if "Unknown" not in tag_vendor:
                        vendor = tag_vendor
                if raw_oui == 0x0017F2:
                    is_apple = True
            elif ie_id == 50:
                ch_list = list(info)
                region  = "TH/EU" if (12 in ch_list or 13 in ch_list) else "US/Global"
        except Exception:
            pass

    if is_apple:
        return f"Apple Device ({region})"
    if "Tuya Smart" in vendor or "Espressif" in vendor:
        return f"Smart Home/IoT ({vendor})"
    if vendor != "Generic":
        return f"{vendor} ({region})"
    return f"Unknown Device [OUI:{found_oui}]"


def auth_tier(algo: int, tags: set[int]) -> str:
    """Map auth algorithm (+ present tag IDs) to a security tier. Pure."""
    if algo == 3:
        return "WPA3-SAE"
    if algo == 2:
        return "FT"
    if algo == 0:
        # FT can ride an open-auth frame; Mobility Domain (54) + FTE (55) present
        return "FT" if {54, 55} & tags else "Open"
    return f"algo:{algo}"


def frame_direction(pkt) -> str:
    """AP- vs client-originated, from transmitter (addr2) vs BSSID (addr3)."""
    addr2 = _safe_upper_mac(getattr(pkt, "addr2", None))
    addr3 = _safe_upper_mac(getattr(pkt, "addr3", None))
    if not addr2 or not addr3:
        return "unknown"
    return "from-AP" if addr2 == addr3 else "from-client"


def parse_frame_body(pkt, pkt_type: str) -> dict:
    """Subtype-specific fixed fields (NOT the seq number — Phase 0 owns that).

    Assoc/Reassoc -> listen interval, capability info, (reassoc) current AP.
    Auth          -> security tier + status + direction.
    Deauth/Disas  -> reason code + direction.
    Real SSID is already correct via extract_ssid() (Phase 0 tag-0 fix), so it
    is not re-extracted here.
    """
    out = {"listen_interval": None, "cap_info": None, "current_ap": None,
           "security_tier": None, "auth_status": None, "reason": None,
           "direction": None}
    try:
        if pkt_type == "ASSOC_REQ":
            a = pkt[Dot11AssoReq]
            out["cap_info"], out["listen_interval"] = int(a.cap), a.listen_interval
        elif pkt_type == "REASSOC_REQ":
            r = pkt[Dot11ReassoReq]
            out["cap_info"], out["listen_interval"] = int(r.cap), r.listen_interval
            out["current_ap"] = _safe_upper_mac(r.current_AP)
        elif pkt_type == "AUTH":
            au = pkt[Dot11Auth]
            tags = {tag_id for tag_id, _ in _iter_ies(pkt)}
            out["security_tier"] = auth_tier(au.algo, tags)
            out["auth_status"]   = au.status
            out["direction"]     = frame_direction(pkt)
        elif pkt_type in ("DEAUTH", "DISASSOC"):
            body = pkt.getlayer(Dot11Deauth) or pkt.getlayer(Dot11Disas)
            out["reason"]    = getattr(body, "reason", None)
            out["direction"] = frame_direction(pkt)
    except Exception:
        pass  # malformed frame -> keep None fields; never raise into prn
    return out


# ---------------------------------------------------------------------------
# Session tracking
# ---------------------------------------------------------------------------

def _expire_sessions(now: float) -> None:
    """Remove sessions that have been idle beyond SESSION_TIMEOUT."""
    expired = [sid for sid, s in active_sessions.items()
               if now - s.last_ts > SESSION_TIMEOUT]
    for sid in expired:
        del active_sessions[sid]


def _update_rssi_stats(session: Session, power: int) -> None:
    """Update RSSI min/max/average inputs for a session."""
    if not power:
        return
    if session.rssi_count == 0:
        session.rssi_min = power
        session.rssi_max = power
    else:
        session.rssi_min = min(session.rssi_min, power)
        session.rssi_max = max(session.rssi_max, power)
    session.rssi        = power
    session.rssi_total += power
    session.rssi_count += 1


def _parse_set(value: str) -> set[str]:
    """Parse semicolon/comma-separated evidence into a clean set."""
    if not value:
        return set()
    normalized = value.replace(",", ";")
    return {part.strip() for part in normalized.split(";") if part.strip()}


def _sessions_overlap(left: Session, right_first_ts: float, right_last_ts: float) -> bool:
    """Return True when two session windows overlap within the tolerance."""
    return (
        left.first_ts <= right_last_ts  + OVERLAP_TOLERANCE_SECONDS
        and right_first_ts <= left.last_ts + OVERLAP_TOLERANCE_SECONDS
    )


def _time_gap_seconds(left: Session, right_first_ts: float, right_last_ts: float) -> float:
    """Return the gap between two non-overlapping windows, or 0 when touching."""
    if left.last_ts <= right_first_ts:
        return right_first_ts - left.last_ts
    if right_last_ts <= left.first_ts:
        return left.first_ts - right_last_ts
    return 0


def _same_randomized_session_score(
    session: Session,
    power: int,
    zone: str,
    ssids: set[str],
    frame_type: str,
    ie_fingerprint: str,
    vendor_ies: set[str],
    now: float,
) -> tuple[int, list[str]]:
    """Score whether a randomized MAC observation belongs to a prior session."""
    score   = 0
    reasons: list[str] = []

    if ie_fingerprint and session.ie_fingerprints:
        if ie_fingerprint in session.ie_fingerprints:
            score += 3
            reasons.append("same IE fingerprint")
        else:
            score -= 3
            reasons.append("different IE fingerprint")

    if vendor_ies and session.vendor_ies:
        if vendor_ies & session.vendor_ies:
            score += 2
            reasons.append("vendor IE overlap")
        else:
            score -= 1

    if ssids and session.ssids:
        if ssids & session.ssids:
            score += 2
            reasons.append("probe SSID overlap")
        else:
            score -= 1

    if power and session.rssi:
        rssi_delta = abs(session.rssi - power)
        if rssi_delta <= 6:
            score += 2
            reasons.append("close RSSI")
        elif rssi_delta <= 10:
            score += 1
            reasons.append("similar RSSI")
        elif rssi_delta > 15:
            score -= 1

    if zone and zone != "unknown" and session.zone == zone:
        score += 1
        reasons.append("same zone")

    if frame_type and frame_type in session.frame_types:
        score += 1
        reasons.append("frame type overlap")

    gap = _time_gap_seconds(session, now, now)
    if gap <= 120:
        score += 1
        reasons.append("nearby time window")
    elif gap > 1800:
        score -= 2

    return score, reasons


def _can_merge_randomized_session(
    session: Session,
    power: int,
    zone: str,
    ssids: set[str],
    frame_type: str,
    ie_fingerprint: str,
    vendor_ies: set[str],
    now: float,
) -> tuple[bool, int, list[str]]:
    """Apply the conservative randomized-session grouping rules."""
    if _sessions_overlap(session, now, now):
        return False, 0, ["overlapping randomized sessions"]

    score, reasons = _same_randomized_session_score(
        session, power, zone, ssids, frame_type, ie_fingerprint, vendor_ies, now
    )
    if score < GROUP_SCORE_THRESHOLD:
        return False, score, reasons

    supporting_reasons = {
        "vendor IE overlap", "probe SSID overlap", "close RSSI",
        "similar RSSI", "same zone", "frame type overlap", "nearby time window",
    }
    support_count = len(supporting_reasons & set(reasons))
    return support_count >= 2, score, reasons


def _store_frame_body_evidence(
    session: Session,
    current_ap: str | None,
    listen_interval: int | None,
    security_tier: str | None,
) -> None:
    """Retain Phase 1 subtype fields on the session (store-only, no scoring)."""
    if current_ap:
        session.current_aps.add(current_ap)
    if listen_interval is not None:
        session.listen_intervals.add(listen_interval)
    if security_tier is not None:
        session.security_tiers.add(security_tier)


def _update_session(
    session: Session,
    mac: str,
    power: int,
    zone: str,
    ssids: set[str],
    frame_type: str,
    ie_fingerprint: str,
    vendor_ies: set[str],
    seq: int | None,
    now: float,
    current_ap: str | None = None,
    listen_interval: int | None = None,
    security_tier: str | None = None,
) -> None:
    """Merge one observation into an existing session."""
    session.last_mac = mac
    _update_rssi_stats(session, power)
    if zone != "unknown":
        session.zone = zone
    session.last_seq = seq
    session.last_ts = now
    session.all_macs.add(mac)
    session.ssids.update(ssids)
    session.frame_types.add(frame_type)
    if ie_fingerprint:
        session.ie_fingerprints.add(ie_fingerprint)
    session.vendor_ies.update(vendor_ies)
    _store_frame_body_evidence(session, current_ap, listen_interval, security_tier)


def track_session(
    mac: str,
    identity: str,
    power: int,
    zone: str,
    ssids: list[str],
    frame_type: str,
    ie_fingerprint: str,
    vendor_ies: str,
    mac_type: str,
    seq: int | None = None,
    current_ap: str | None = None,
    listen_interval: int | None = None,
    security_tier: str | None = None,
) -> str:
    """
    Match this observation to an existing session or create a new one.
    Returns a label like 'New-User-3' or 'Existing-User-1'.
    """
    now            = _now()
    fingerprint    = identity.split("[OUI:")[0].strip()
    ssid_set       = {ssid for ssid in ssids if ssid}
    vendor_ie_set  = _parse_set(vendor_ies)

    with _session_lock:
        _expire_sessions(now)

        for sid, session in active_sessions.items():
            if mac in session.all_macs:
                _update_session(
                    session, mac, power, zone, ssid_set, frame_type,
                    ie_fingerprint, vendor_ie_set, seq, now,
                    current_ap, listen_interval, security_tier,
                )
                return f"Existing-User-{sid}"

        if mac_type == "Randomized":
            best_sid    = None
            best_score  = -99
            best_reasons: list[str] = []
            for sid, session in active_sessions.items():
                if session.mac_type != "Randomized":
                    continue
                allowed, score, reasons = _can_merge_randomized_session(
                    session, power, zone, ssid_set, frame_type,
                    ie_fingerprint, vendor_ie_set, now
                )
                if allowed and score > best_score:
                    best_sid     = sid
                    best_score   = score
                    best_reasons = reasons

            if best_sid is not None:
                session     = active_sessions[best_sid]
                _update_session(
                    session, mac, power, zone, ssid_set, frame_type,
                    ie_fingerprint, vendor_ie_set, seq, now,
                    current_ap, listen_interval, security_tier,
                )
                reason_text = ", ".join(best_reasons) if best_reasons else "matched evidence"
                log.debug("Merged randomized MAC %s into User-%s: %s", mac, best_sid, reason_text)
                return f"Existing-User-{best_sid}"

        new_id  = max(active_sessions.keys(), default=0) + 1
        session = Session(
            last_mac        = mac,
            last_seq        = seq,
            all_macs        = {mac},
            fingerprint     = fingerprint,
            ie_fingerprints = {ie_fingerprint} if ie_fingerprint else set(),
            vendor_ies      = vendor_ie_set,
            mac_type        = mac_type,
            frame_types     = {frame_type},
            ssids           = ssid_set,
            zone            = zone,
            first_ts        = now,
            last_ts         = now,
        )
        _update_rssi_stats(session, power)
        _store_frame_body_evidence(session, current_ap, listen_interval, security_tier)
        active_sessions[new_id] = session
        return f"New-User-{new_id}"


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def generate_session_report() -> None:
    """Write a human-friendly daily summary CSV of active sessions."""
    report_file = os.path.join(SUMMARY_DIR, f"{SUMMARY_PREFIX}_{time.strftime('%Y%m%d')}.csv")
    with _session_lock:
        rows = list(active_sessions.items())

    with open(report_file, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "User_ID", "First_Seen_Full", "Last_Seen_Full", "Stay_Mins",
            "Device_Type", "MAC_Count", "Frame_Types", "IE_Fingerprints",
            "Vendor_IEs", "RSSI_Min", "RSSI_Max", "RSSI_Avg", "Top_SSID",
        ])
        for sid, s in rows:
            stay_min = round((s.last_ts - s.first_ts) / 60, 1)
            rssi_avg = (
                round(s.rssi_total / s.rssi_count, 1)
                if s.rssi_count else 0
            )
            clean_id  = s.fingerprint.split("(")[0].strip()
            ssid_list = list(s.ssids)
            top_ssid  = ssid_list[0] if ssid_list else "-"
            if len(ssid_list) > 1:
                top_ssid = f"{top_ssid} (+{len(ssid_list) - 1})"
            writer.writerow([
                f"User_{sid}", _format_ts(s.first_ts), _format_ts(s.last_ts),
                f"{stay_min}m", clean_id, len(s.all_macs),
                ";".join(sorted(s.frame_types)),
                ";".join(sorted(s.ie_fingerprints)),
                ";".join(sorted(s.vendor_ies)),
                s.rssi_min, s.rssi_max, rssi_avg, top_ssid,
            ])


def _append_csv_row(row: list) -> None:
    """Thread-safe append of a single row to the main log file."""
    with _writer_lock:
        handle = _writer_for(LOG_FILE)
        csv.writer(handle).writerow(row)
        handle.flush()


# ---------------------------------------------------------------------------
# Packet handler
# ---------------------------------------------------------------------------

def _freq_to_channel(freq: int) -> int | str:
    """Convert Wi-Fi frequency (MHz) to channel number."""
    if 2412 <= freq <= 2484:
        return 1 if freq == 2484 else (freq - 2407) // 5
    if 5000 <= freq <= 5900:
        return (freq - 5000) // 5
    return "N/A"


def _freq_to_band(freq: int) -> str:
    """Return Wi-Fi band name from frequency."""
    if 2412 <= freq <= 2484:
        return "2.4GHz"
    if 5000 <= freq <= 5900:
        return "5GHz"
    if 5925 <= freq <= 7125:
        return "6GHz"
    return "N/A"


def _pick_colour(identity: str) -> str:
    """Return ANSI colour code based on the identified device type."""
    if "Apple"   in identity: return COLOUR_RED
    if "Samsung" in identity: return COLOUR_BLUE
    if "Unknown" in identity: return COLOUR_GREY
    return COLOUR_YELLOW


def classify_frame(pkt) -> tuple[str | None, str]:
    """
    Identify an 802.11 management frame and the address to attribute it to.

    Returns ``(pkt_type, mac_addr)`` for every management frame — all sixteen
    subtypes, per MGMT_SUBTYPE_LABELS — or ``(None, "")`` for control and data
    frames, which are out of scope and which dumpcap's `type mgt` filter would
    not have kept either.

    The address is the transmitter (addr2), falling back to addr3 then addr1 so
    a frame with a malformed transmitter address is still recorded rather than
    discarded. Beacons keep reading addr3 (the BSSID) first, as they always
    have: on a normal AP addr2 and addr3 are the same address, but they differ
    on a repeater or mesh node, and wifi_full_recon_report.csv accumulates
    across runs — switching the column's meaning mid-file would leave old and
    new beacon rows quietly incomparable.

    ``mac_addr`` can still come back empty for a badly truncated frame — that is
    for handle_packet() to interpret, not a reason to lose the frame here.
    """
    dot11 = pkt.getlayer(Dot11)
    if dot11 is None:
        return None, ""

    try:
        frame_type = int(dot11.type)
        subtype    = int(dot11.subtype)
    except (AttributeError, TypeError, ValueError):
        # A frame mangled badly enough that the control field will not resolve.
        # Returning rather than raising matters: Scapy closes the capture socket
        # on any exception escaping the packet callback.
        return None, ""

    if frame_type != 0:
        return None, ""

    # .get() with a computed default rather than a bare lookup: subtype is a
    # 4-bit field so the table is exhaustive today, but a label is cheaper than
    # a dropped frame if that ever stops being true.
    label = MGMT_SUBTYPE_LABELS.get(subtype, f"MGMT_{subtype}")

    # Beacons: BSSID first, preserving the column's historical meaning. Every
    # other subtype: transmitter first, which is what it has always used.
    order = ("addr3", "addr2", "addr1") if label == "BEACON" else \
            ("addr2", "addr3", "addr1")
    mac_addr = ""
    for field in order:
        mac_addr = _safe_upper_mac(getattr(dot11, field, None))
        if mac_addr:
            break
    return label, mac_addr


_frame_error_count = 0


def handle_packet(pkt) -> None:
    """
    Process one captured frame, absorbing any failure it causes.

    This guard is the difference between losing a frame and losing the capture.
    Scapy's sniff loop wraps the packet callback in a broad ``except Exception``
    that closes the capture socket and removes it from its socket set; with one
    interface that ends the loop and ``sniff()`` returns normally, which the
    retry logic in main() reads as the adapter dropping out of monitor mode. One
    malformed frame therefore cost a monitor-mode reset and RETRY_DELAY seconds
    of blindness, and MAX_RETRIES of them ended the run — all reported as a
    hardware problem.

    ``except Exception`` deliberately does not catch KeyboardInterrupt, so Ctrl+C
    still stops the capture immediately.
    """
    global _frame_error_count
    try:
        _process_frame(pkt)
    except Exception as exc:
        _frame_error_count += 1
        if _frame_error_count <= MAX_FRAME_ERROR_LOGS:
            log.warning(
                "Frame dropped (%s: %s)%s",
                type(exc).__name__, exc,
                " — further frame errors will be counted, not logged"
                if _frame_error_count == MAX_FRAME_ERROR_LOGS else "",
            )


def _process_frame(pkt) -> None:
    """Process each captured 802.11 frame."""
    pkt_type, mac_addr = classify_frame(pkt)
    # Only non-management frames are skipped. A management frame whose address
    # could not be read is still a frame dumpcap would have recorded, so it is
    # logged with an empty MAC_Address rather than discarded.
    if pkt_type is None:
        return

    seq = (
        pkt[Dot11].SC >> 4
        if pkt.haslayer(Dot11) and pkt[Dot11].SC is not None
        else None
    )

    # A zero-length SSID element means different things by subtype: from an AP
    # advertising a BSS it is a hidden network, from a client it is a wildcard
    # probe. Probe Responses are AP-originated and carry the same hidden-SSID
    # convention as beacons.
    ssid = extract_ssid(
        pkt,
        "(Hidden SSID)" if pkt_type in ("BEACON", "PROBE_RESP") else "(Wildcard)",
    )

    power: int   = 0
    channel      = "N/A"
    band         = "N/A"
    if pkt.haslayer(RadioTap):
        rtap    = pkt.getlayer(RadioTap)
        power   = getattr(rtap, "dBm_AntSignal", 0) or 0
        if hasattr(rtap, "Channel"):
            channel = _freq_to_channel(rtap.Channel)
            band    = _freq_to_band(rtap.Channel)

    # Live: the wall clock, identical to the previous time.strftime() with no
    # argument. Replay: the frame's own capture time, so the CSV describes the
    # capture rather than the moment the replay happened to run.
    now          = _frame_time(pkt)
    timestamp    = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
    dist_m       = calculate_distance(power)
    zone         = proximity_zone(dist_m)
    mac_type     = check_mac_type(mac_addr)
    interval     = round(now - _last_seen.get(mac_addr, now), 2)
    _last_seen[mac_addr] = now

    identity     = get_correlation_identity(pkt)
    ie_details   = extract_ie_details(pkt)
    body         = parse_frame_body(pkt, pkt_type)

    # Vendor column: a real (burned-in) MAC has a genuine OUI, so look it up
    # in the vendor database. A randomized MAC has no real OUI to resolve —
    # instead surface the vendor advertised in its tag-221 Vendor Specific
    # IEs. The raw OUIs stay in the separate Vendor_IEs column either way.
    if mac_type == "Real":
        vendor = get_vendor(mac_addr, mac_type)
    else:
        vendor = vendor_from_ie_ouis(ie_details["vendor_ies"])
    # A frame with no readable address cannot be attributed to a device at all,
    # so it is logged and goes no further. Otherwise session tracking runs for
    # the client subtypes it was tuned against; everything else — beacons, the
    # response frames, and the subtypes added alongside them — is logged only.
    if not mac_addr:
        session_note = "No-Address"
    elif pkt_type in CLIENT_FRAME_TYPES:
        session_note = track_session(
            mac_addr, identity, power, zone, [ssid], pkt_type,
            ie_details["ie_fingerprint"], ie_details["vendor_ies"], mac_type, seq,
            body["current_ap"], body["listen_interval"], body["security_tier"],
        )
    else:
        session_note = "AP-Logged-Only"

    final_note = f"{session_note} | {identity}"
    colour     = _pick_colour(identity)

    # Print tracked frame types in real time. Client frames are tagged [C];
    # AP/other management frames (beacons today, anything new added to
    # classify_frame() in future) are tagged [A]. The --frames flag can suppress
    # BEACON frames from the terminal; CSV logging below is unaffected.
    show_in_terminal = TERMINAL_FRAME_FILTER == "all" or pkt_type != "BEACON"
    if show_in_terminal:
        frame_tag = "[C]" if pkt_type in CLIENT_FRAME_TYPES else "[A]"
        try:
            print(
                f"{colour}{frame_tag} {timestamp} | {pkt_type:<11} | {mac_addr} | "
                f"CH:{str(channel):<3}| {power:>4}dBm | {dist_m:>5}m | "
                f"SSID: {ssid:<20} | {identity}{COLOUR_RESET}"
            )
        except UnicodeEncodeError:
            # SSIDs are arbitrary bytes and routinely contain emoji or CJK. Under
            # nohup or cron stdout is often not UTF-8, and the frame must not be
            # lost just because its name cannot be printed.
            pass

    _append_csv_row([
        timestamp, pkt_type, mac_addr, mac_type,
        vendor, ssid, channel, band, power, dist_m,
        interval, ie_details["ie_sequence"], ie_details["ie_fingerprint"],
        ie_details["vendor_ies"], ie_details["capabilities"], identity,
        final_note, seq,
        body["listen_interval"], body["cap_info"], body["current_ap"],
        body["security_tier"], body["auth_status"], body["reason"],
        body["direction"],
        _frame_parts(pkt).frame.hex() if CAPTURE_RAW_FRAMES else "",
    ])

    dump_ie_details(pkt, timestamp, pkt_type, mac_addr)


# ---------------------------------------------------------------------------
# Background threads
# ---------------------------------------------------------------------------

def channel_hopper(iface: str, channels: list[int]) -> None:
    """
    Rotate ``iface`` through ``channels`` continuously, dwelling on each one
    for CHANNEL_HOP_INTERVAL seconds.

    The list is built by build_hop_channels() from the selected band and, when
    PROBE_HOP_CHANNELS is on, already filtered down to channels this adapter
    accepts. Because every pass re-issues the channel set, hop mode also
    self-heals after a monitor-mode reset — unlike camp mode, which has to be
    re-applied explicitly.
    """
    sweep = len(channels) * CHANNEL_HOP_INTERVAL
    log.info(
        "Channel hopper started on %s — %d channels, %.1fs per sweep",
        iface, len(channels), sweep,
    )
    while True:
        for ch in channels:
            set_channel(iface, ch)
            time.sleep(CHANNEL_HOP_INTERVAL)


def auto_report_worker() -> None:
    """Periodically save a session summary to disk."""
    while True:
        time.sleep(AUTO_SAVE_INTERVAL)
        generate_session_report()
        log.info("Auto-saved session summary (%s)", time.strftime("%H:%M:%S"))


# ---------------------------------------------------------------------------
# Startup prompts
# ---------------------------------------------------------------------------
# Every setting below is also reachable as a CLI flag. The flag always wins;
# these prompts only run for the settings whose flag was omitted, and only when
# stdin is a terminal — an unattended run falls straight through to the
# DEFAULT_* constants instead of blocking forever on input().

def _stdin_is_interactive() -> bool:
    """True when startup prompts can be shown (stdin is a real terminal)."""
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except (AttributeError, ValueError):
        # Detached or already-closed stdin: treat as non-interactive.
        return False


def _ask(question: str, default: str) -> str:
    """Read one line, returning ``default`` on a bare Enter or closed stdin."""
    try:
        answer = input(f"{question} [{default}]: ").strip()
    except EOFError:
        # stdin vanished mid-prompt — fall back rather than kill the run.
        print()
        return default
    except KeyboardInterrupt:
        print()
        raise SystemExit("Cancelled at startup prompt.")
    return answer or default


def prompt_choice(title: str, options: list[tuple[str, str]], default_key: str) -> str:
    """
    Ask the user to pick one of ``options``, a list of ``(key, label)`` pairs.

    Accepts either the 1-based menu number or the key itself, and a bare Enter
    takes ``default_key``. Re-asks until the answer is valid.
    """
    while True:
        print(f"\n{title}")
        for index, (key, label) in enumerate(options, start=1):
            marker = "   <- default" if key == default_key else ""
            print(f"  [{index}] {label}{marker}")
        answer = _ask("Choice", default_key).lower()
        for index, (key, _label) in enumerate(options, start=1):
            if answer in (key, str(index)):
                return key
        print(f"  '{answer}' is not one of the choices — try again.")


def prompt_interface() -> str:
    """Ask which adapter to capture on."""
    print()
    return _ask("Capture interface", INTERFACE)


def prompt_capture_mode() -> str:
    """Ask whether to sit on a single channel or rotate through a band."""
    return prompt_choice(
        "Capture mode:",
        [
            ("camp", "Camp on one channel"),
            ("hop",  "Hop across a band"),
        ],
        DEFAULT_CAPTURE_MODE,
    )


def prompt_band() -> str:
    """Ask which channel range the hopper should sweep."""
    count_2ghz = len(CHANNELS_2GHZ)
    count_5ghz = len(CHANNELS_5GHZ)
    return prompt_choice(
        "Band to hop:",
        [
            ("2.4",  f"2.4 GHz  ({count_2ghz} channels, "
                     f"{count_2ghz * CHANNEL_HOP_INTERVAL:.1f}s sweep)"),
            ("5",    f"5 GHz    ({count_5ghz} channels before DFS probe, "
                     f"{count_5ghz * CHANNEL_HOP_INTERVAL:.1f}s sweep)"),
            ("both", f"Both     ({count_2ghz + count_5ghz} channels, "
                     f"{(count_2ghz + count_5ghz) * CHANNEL_HOP_INTERVAL:.1f}s sweep)"),
        ],
        DEFAULT_BAND,
    )


def prompt_camp_channel() -> int:
    """Ask which single channel to camp on, re-asking until it parses."""
    while True:
        print()
        answer = _ask("Channel to camp on", str(DEFAULT_CAMP_CHANNEL))
        try:
            channel = int(answer)
        except ValueError:
            print(f"  '{answer}' is not a number — try again.")
            continue
        if channel <= 0:
            print("  Channel must be a positive number — try again.")
            continue
        if _channel_band_label(channel) == "unknown":
            # Outside the configured lists, but the driver is the real
            # authority here — let it through and let set_channel() rule on it.
            print(f"  Note: channel {channel} is outside the configured "
                  f"2.4/5 GHz lists.")
        return channel


# ---------------------------------------------------------------------------
# Offline replay
# ---------------------------------------------------------------------------

def sniff_filtered(**kwargs) -> None:
    """
    Run sniff() with CAPTURE_BPF_FILTER, falling back to unfiltered on refusal.

    Live capture only. Two things can refuse the filter: `type mgt` compiles
    only for an 802.11 link type, so an adapter that is not actually in monitor
    mode presents as Ethernet and rejects it; and Scapy needs libpcap (or
    tcpdump) to compile a BPF at all. Either way, capturing unfiltered is far
    better than not capturing, so the failure is reported and the run continues
    without the throughput benefit.
    """
    if not CAPTURE_BPF_FILTER:
        sniff(**kwargs)
        return

    # Only a failure *before any frame arrived* counts as the filter being
    # refused. Once frames are flowing the filter is known good, so a later
    # exception is an adapter problem and belongs to the retry loop in main() —
    # silently dropping the filter there would mask a real fault.
    delivered = 0
    inner_prn = kwargs.pop("prn")

    def counting_prn(pkt) -> None:
        nonlocal delivered
        delivered += 1
        inner_prn(pkt)

    try:
        sniff(filter=CAPTURE_BPF_FILTER, prn=counting_prn, **kwargs)
        return
    except Exception as exc:
        if delivered:
            raise
        # Scapy raises its own Scapy_Exception subclass here, not just OSError.
        log.warning("BPF filter %r rejected (%s: %s) — capturing unfiltered.",
                    CAPTURE_BPF_FILTER, type(exc).__name__, exc)
        log.warning("  Check that %s is in monitor mode and that libpcap or "
                    "tcpdump is installed.", kwargs.get("iface", "the interface"))

    sniff(prn=inner_prn, **kwargs)


def run_replay(pcap_path: str, parser: argparse.ArgumentParser) -> None:
    """
    Feed ``pcap_path`` through handle_packet() exactly as a live capture would.

    This is the measurement path the tool previously lacked: with it, the same
    dumpcap file can be run through this tool and through tshark, so coverage
    claims can be checked against a fixed input instead of against a second
    capture taken at a different time.

    Strictly read-only with respect to the radio — no interface is opened, no
    channel is tuned, and the hopper thread is never started. The auto-save
    thread is skipped too: it sleeps on the wall clock, which no longer matches
    the frame clock during replay, and a single report is written at the end
    anyway.
    """
    global REPLAY_MODE

    if not os.path.isfile(pcap_path):
        parser.error(f"--pcap: no such file: {pcap_path}")

    REPLAY_MODE = True
    setup_csv()
    setup_ie_csv()

    log.info("Replaying capture file          : %s", pcap_path)
    log.info("Logging packets to              : %s", LOG_FILE)
    log.info("Logging IE breakdown to         : %s", IE_DETAILS_FILE)
    log.info("Terminal frame filter           : %s", TERMINAL_FRAME_FILTER)
    log.info("Raw frame bytes (Frame_Hex)     : %s",
             "on" if CAPTURE_RAW_FRAMES else "off")

    sep = "-" * 110
    print(sep)
    print(f"{'Type':11} | {'Timestamp':19} | {'MAC Address':17} | {'CH':<4}| "
          f"{'Pwr':>4} | {'Dist':>5} | SSID")
    print(sep)

    # Counted out here rather than inside handle_packet so the live path keeps
    # its current shape. `total` is every frame scapy handed us; handle_packet
    # decides on its own which of those reach the CSV.
    total = 0

    def count_and_handle(pkt) -> None:
        nonlocal total
        total += 1
        handle_packet(pkt)

    try:
        # No BPF filter here on purpose. It exists to keep data frames from
        # consuming the live capture ring; a file has no ring to protect,
        # _process_frame() already ignores non-management frames, and Scapy's
        # offline filter path shells out to tcpdump, which would make replay
        # depend on a tool the live path does not need.
        sniff(offline=pcap_path, prn=count_and_handle, store=False)
    except KeyboardInterrupt:
        log.info("Interrupted – saving report for the frames read so far …")
    except (OSError, ValueError) as exc:
        # Unreadable or non-pcap input: report it plainly rather than dumping a
        # scapy traceback, and still write whatever was parsed before the error.
        log.error("Could not read %s: %s", pcap_path, exc)

    log.info("Replay finished — %d frame(s) read from %s", total, pcap_path)
    if _frame_error_count:
        log.warning("%d frame(s) raised while being processed.", _frame_error_count)
    generate_session_report()
    close_output_files()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Passive Wi-Fi reconnaissance capture.")
    parser.add_argument(
        "--iface",
        default=None,
        help="Capture interface. Prompted for when omitted; falls back to "
             f"'{INTERFACE}' when stdin is not a terminal.",
    )
    parser.add_argument(
        "--mode",
        choices=CAPTURE_MODES,
        default=None,
        help="Capture mode: 'camp' stays on a single channel, 'hop' rotates "
             "through a band. Prompted for when omitted; falls back to "
             f"'{DEFAULT_CAPTURE_MODE}' when stdin is not a terminal.",
    )
    parser.add_argument(
        "--band",
        choices=BANDS,
        default=None,
        help="Channel range to hop, hop mode only: '2.4', '5', or 'both' for "
             "one continuous sweep across the two. Prompted for when omitted; "
             f"falls back to '{DEFAULT_BAND}' when stdin is not a terminal.",
    )
    parser.add_argument(
        "--channel",
        type=int,
        default=None,
        help="Channel to camp on, camp mode only. Prompted for when omitted; "
             f"falls back to {DEFAULT_CAMP_CHANNEL} when stdin is not a terminal.",
    )
    parser.add_argument(
        "--hop",
        action="store_true",
        help="Backwards-compatible alias for --mode hop.",
    )
    parser.add_argument(
        "--pcap",
        default=None,
        help="Replay a previously recorded pcap through the normal packet "
             "handler instead of capturing live. Opens no interface and tunes "
             "no channel, so --iface/--mode/--band/--channel/--hop are ignored. "
             "Timestamps come from the pcap, not the wall clock. Pair with "
             "--out-dir so the replay does not overwrite live capture output.",
    )
    parser.add_argument(
        "--raw-frames",
        choices=["on", "off"],
        default="off",
        help="Whether to record the complete frame bytes in the Frame_Hex "
             "column (default: off). Off keeps the CSV small, at the cost of "
             "losing anything the other columns do not capture. Turn it on to "
             "keep everything this tool cannot decode yet recoverable from the "
             "log without re-capturing.",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help="Write all three reports into this directory instead of the "
             "configured defaults. Created if missing; filenames are unchanged.",
    )
    parser.add_argument(
        "--frames",
        choices=["all", "no-beacon"],
        default="all",
        help="Which frame types to show in the real-time terminal log: "
             "'all' (default) shows every frame; 'no-beacon' hides BEACON "
             "frames. Does not affect CSV logging.",
    )
    args = parser.parse_args()

    if args.hop and args.mode == "camp":
        parser.error("--hop contradicts --mode camp; pass only one of them.")

    global TERMINAL_FRAME_FILTER, CAPTURE_RAW_FRAMES
    TERMINAL_FRAME_FILTER = args.frames
    CAPTURE_RAW_FRAMES    = args.raw_frames == "on"

    if args.out_dir:
        apply_output_dir(args.out_dir)

    # ── Offline replay ───────────────────────────────────────────────────────
    # Handled before any settings resolution: replay owns no radio, so none of
    # the interface / channel questions apply and none of their prompts should
    # ever be shown.
    if args.pcap:
        # Say so rather than silently ignoring them, matching how camp/hop mode
        # already reports flags that do not apply to the selected mode.
        radio_flags = [
            name for name, value in (
                ("--iface",   args.iface),
                ("--mode",    args.mode),
                ("--band",    args.band),
                ("--channel", args.channel),
                ("--hop",     args.hop or None),
            ) if value is not None
        ]
        if radio_flags:
            log.warning("%s ignored in --pcap replay mode (no radio is used).",
                        ", ".join(radio_flags))
        run_replay(args.pcap, parser)
        return

    # ── Settings resolution ──────────────────────────────────────────────────
    # For each setting: the CLI flag wins, otherwise ask if there is a terminal
    # to ask on, otherwise fall back to the module-level DEFAULT_* constant so
    # unattended runs never block on input().
    interactive = _stdin_is_interactive()
    if not interactive:
        log.info("stdin is not a terminal — skipping startup prompts, "
                 "using CLI flags and code defaults.")

    iface = args.iface or (prompt_interface() if interactive else INTERFACE)

    if args.mode:
        mode = args.mode
    elif args.hop:
        mode = "hop"
    elif interactive:
        mode = prompt_capture_mode()
    else:
        mode = DEFAULT_CAPTURE_MODE

    camp_channel: int | None = None
    band:         str | None = None
    hop_channels: list[int]  = []

    if mode == "camp":
        if args.band:
            log.warning("--band is ignored in camp mode.")
        camp_channel = (
            args.channel if args.channel is not None
            else (prompt_camp_channel() if interactive else DEFAULT_CAMP_CHANNEL)
        )
    else:
        if args.channel is not None:
            log.warning("--channel is ignored in hop mode.")
        band = args.band or (prompt_band() if interactive else DEFAULT_BAND)
        hop_channels = build_hop_channels(band)

    setup_csv()
    setup_ie_csv()

    log.info("Starting WiFi Recon on interface: %s", iface)
    log.info("Logging packets to            : %s", LOG_FILE)
    log.info("Logging IE breakdown to       : %s", IE_DETAILS_FILE)
    log.info("Max reconnect attempts        : %d", MAX_RETRIES)
    log.info("Terminal frame filter         : %s", TERMINAL_FRAME_FILTER)
    log.info("Raw frame bytes (Frame_Hex)   : %s",
             "on" if CAPTURE_RAW_FRAMES else "off")
    log.info("Capture mode                  : %s", mode)

    # ── Apply the channel plan ───────────────────────────────────────────────
    if mode == "camp":
        log.info("Camped channel                : %d (%s)",
                 camp_channel, _channel_band_label(camp_channel))
        if not set_channel(iface, camp_channel):
            # Camping on a channel the driver refused would silently capture
            # whatever the radio happened to be tuned to, which is worse than
            # stopping — so bail out with the fix spelled out.
            log.error("Could not tune %s to channel %d.", iface, camp_channel)
            log.error("Check the adapter is in monitor mode and up:")
            log.error("  sudo ip link set %s down && sudo iw dev %s set type "
                      "monitor && sudo ip link set %s up", iface, iface, iface)
            raise SystemExit(1)
    else:
        if PROBE_HOP_CHANNELS:
            hop_channels = probe_channels(iface, hop_channels)
        log.info("Hop band                      : %s", band)
        log.info("Hop channels                  : %d (%.1fs per sweep)",
                 len(hop_channels), len(hop_channels) * CHANNEL_HOP_INTERVAL)

    sep = "-" * 110
    print(sep)
    print(f"{'Type':11} | {'Timestamp':19} | {'MAC Address':17} | {'CH':<4}| "
          f"{'Pwr':>4} | {'Dist':>5} | SSID")
    print(sep)

    if mode == "hop":
        threading.Thread(
            target=channel_hopper, args=(iface, hop_channels), daemon=True
        ).start()
    threading.Thread(target=auto_report_worker, daemon=True).start()

    def recover_interface() -> None:
        """
        Reset monitor mode, then restore the channel plan on top of it.

        A monitor-mode reset drops the radio back to the driver's default
        channel. The hopper re-issues its channel every CHANNEL_HOP_INTERVAL
        so it heals itself, but a camped channel would otherwise be silently
        lost and the rest of the run would capture the wrong channel.
        """
        reset_monitor_mode(iface)
        if mode == "camp" and not set_channel(iface, camp_channel):
            log.error("Could not re-camp on channel %d after reset.", camp_channel)

    # ── Capture loop with automatic interface recovery ────────────────────────
    # sniff() exits silently (returns normally without raising) when the adapter
    # drops out of monitor mode — the same "Network is down" scenario we handle
    # in wifi_sniffer.py. The outer while loop detects this and calls
    # reset_monitor_mode() before trying again, up to MAX_RETRIES times.
    # A clean Ctrl+C raises KeyboardInterrupt which breaks out of the loop
    # immediately into the final report save below.
    retry_count = 0
    try:
        while True:
            try:
                sniff_filtered(iface=iface, prn=handle_packet, store=False)

                # sniff() returned without an exception — adapter likely dropped.
                retry_count += 1
                if retry_count > MAX_RETRIES:
                    log.error("Gave up after %d reconnect attempts.", MAX_RETRIES)
                    break

                log.warning(
                    "Capture socket closed unexpectedly. "
                    "Reconnect attempt %d/%d in %ds …",
                    retry_count, MAX_RETRIES, RETRY_DELAY,
                )
                time.sleep(RETRY_DELAY)
                recover_interface()

            except OSError as exc:
                # Some adapter failures raise here instead of returning silently.
                retry_count += 1
                if retry_count > MAX_RETRIES:
                    log.error("Gave up after %d reconnect attempts: %s", MAX_RETRIES, exc)
                    break
                log.warning(
                    "Socket error: %s — reconnect attempt %d/%d in %ds …",
                    exc, retry_count, MAX_RETRIES, RETRY_DELAY,
                )
                time.sleep(RETRY_DELAY)
                recover_interface()

    except KeyboardInterrupt:
        log.info("Interrupted – saving final session report …")

    if _frame_error_count:
        log.warning("%d frame(s) raised while being processed and were skipped.",
                    _frame_error_count)
    generate_session_report()
    close_output_files()


if __name__ == "__main__":
    main()
