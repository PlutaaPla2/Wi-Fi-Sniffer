#!/usr/bin/env python3
"""
WiFi Full Reconnaissance Tool
Passively captures and fingerprints WiFi clients and access points.
"""

import os
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
    Dot11, Dot11ProbeReq, Dot11Beacon,
    Dot11AssoReq, Dot11AssoResp, Dot11ReassoReq, Dot11ReassoResp,
    Dot11Auth, Dot11Deauth, Dot11Disas, RadioTap,
    Dot11Elt, Dot11EltVendorSpecific
)
from mac_vendor_lookup import MacLookup

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

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

# ── Interface recovery ────────────────────────────────────────────────────────
# When sniff() exits unexpectedly (the adapter drops out of monitor mode),
# the script waits RETRY_DELAY seconds, resets the interface, then tries again.
# It gives up after MAX_RETRIES consecutive failures.
MAX_RETRIES  = 10   # maximum reconnect attempts before giving up
RETRY_DELAY  = 3    # seconds to wait between each attempt

CLIENT_FRAME_TYPES = {
    "PROBE", "ASSOC_REQ", "REASSOC_REQ", "AUTH", "DEAUTH", "DISASSOC",
}

# Which frame types appear in the real-time terminal log. This affects the
# terminal output only — every frame is still written to the CSV regardless.
#   "all"       → print every tracked frame type
#   "no-beacon" → print every frame except BEACON
# Set from the --frames CLI flag in main().
TERMINAL_FRAME_FILTER = "all"

CSV_FIELDS = [
    "Timestamp", "Pkt_Type", "MAC_Address", "Device_Type",
    "Vendor", "SSID", "Channel", "Band", "Power_dBm", "Distance_m",
    "Interval_sec", "IE_Sequence", "IE_Fingerprint", "Vendor_IEs",
    "Capabilities", "Note", "Session_Note", "Seq_Num",
    "Listen_Interval", "Cap_Info", "Current_AP",
    "Security_Tier", "Auth_Status", "Reason_Code", "Direction",
]

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

def setup_csv() -> None:
    """Create CSV with header row if the file does not yet exist."""
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
# Packet fingerprinting
# ---------------------------------------------------------------------------

def _iter_ies(pkt):
    """
    Yield ``(ie_id, info_bytes)`` for every 802.11 information element in a frame.

    Walks raw TLV bytes instead of Scapy's Dot11Elt chain — Scapy can stop
    producing Dot11Elt objects after an unknown element and fall back to Raw,
    silently dropping later IEs. The raw [ID][len][data] walk recovers all of them.
    """
    first_elt = pkt.getlayer(Dot11Elt)
    if first_elt is None:
        return

    raw_bytes = bytes(first_elt)
    i = 0
    while i + 1 < len(raw_bytes):
        ie_id      = raw_bytes[i]
        ie_len     = raw_bytes[i + 1]
        data_start = i + 2
        data_end   = data_start + ie_len
        if data_end > len(raw_bytes):
            break
        yield ie_id, raw_bytes[data_start:data_end]
        i = data_end


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
        fingerprint_parts.append(f"{ie_id}:{len(info)}:{info[:8].hex()}")

        if ie_id == 45:
            capability_flags.add("HT")
        elif ie_id == 48:
            capability_flags.add("RSN")
        elif ie_id == 50:
            capability_flags.add("EXT_RATES")
        elif ie_id in {191, 192}:
            capability_flags.add("VHT")
        elif ie_id == 255:
            capability_flags.add("EXT_CAP")
        elif ie_id == 221 and len(info) >= 3:
            oui = ":".join(f"{b:02x}" for b in info[:3])
            vendor_ies.add(oui)
            if len(info) >= 4 and info[:4] == b"\x00\x50\xf2\x04":
                capability_flags.add("WPS")

    raw_fingerprint = "|".join(fingerprint_parts)
    ie_fingerprint  = (
        hashlib.sha1(raw_fingerprint.encode("ascii")).hexdigest()[:16]
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


def dump_ie_details(pkt, timestamp: str, pkt_type: str, mac_addr: str) -> None:
    """
    Append one row per 802.11 information element to IE_DETAILS_FILE.

    Where the main recon log records a single row per packet, this breaks each
    frame down tag-by-tag so the raw content of every IE can be inspected
    offline — especially useful for the richer association/probe frames.
    """
    rows = []
    for index, (ie_id, info) in enumerate(_iter_ies(pkt)):
        rows.append([
            timestamp, pkt_type, mac_addr, index, ie_id,
            IE_NAMES.get(ie_id, f"Unknown({ie_id})"),
            len(info), info.hex(), _decode_ie(ie_id, info),
        ])
    if not rows:
        return
    with open(IE_DETAILS_FILE, "a", newline="") as fh:
        csv.writer(fh).writerows(rows)


def extract_ssid(pkt, fallback: str) -> str:
    """Read an SSID only from the tag-0 information element."""
    ssid_el = pkt.getlayer(Dot11Elt, ID=0)
    raw = getattr(ssid_el, "info", b"") if ssid_el else b""
    return raw.decode("utf-8", errors="ignore") or fallback


def get_correlation_identity(pkt) -> str:
    """
    Derive a human-readable device identity from a Probe Request or Beacon.
    Priority: Vendor Specific Tag (221) > MAC OUI > generic fallback.
    """
    vendor       = "Generic"
    region       = "Unknown"
    device_class = "IoT/Low-End"
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

    if pkt.haslayer(Dot11Elt):
        el = pkt.getlayer(Dot11EltVendorSpecific)
        while el:
            try:
                raw_oui = el.oui
                if isinstance(raw_oui, int):
                    oui_str    = oui_int_to_str(raw_oui)
                    found_oui  = oui_str
                    info = getattr(el, "info", b"") or b""
                    vendor_type = info[0] if info else None
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
            except Exception:
                pass
            el = el.payload.getlayer(Dot11EltVendorSpecific)

        tag50 = pkt.getlayer(Dot11Elt, ID=50)
        if tag50:
            ch_list      = list(tag50.info)
            region       = "TH/EU" if (12 in ch_list or 13 in ch_list) else "US/Global"
            if len(ch_list) > 11:
                device_class = "High-End"

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
    now            = time.time()
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
    with open(LOG_FILE, "a", newline="") as fh:
        csv.writer(fh).writerow(row)


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
    Identify a supported 802.11 management frame and its source MAC.

    Catches the association family in full, including the rarely-captured
    association/reassociation *response* frames the AP sends back to a client
    (ASSOC_RESP / REASSOC_RESP) — these only appear during the brief connection
    handshake, so they seldom show up in a passive capture. Returns
    ``(pkt_type, mac_addr)`` or ``(None, "")`` for frames we don't track.

    Ordered so the more specific *response* checks run before the request
    layers they subclass, avoiding misclassification.
    """
    if pkt.haslayer(Dot11Beacon):
        return "BEACON", _safe_upper_mac(pkt.addr3)
    if pkt.haslayer(Dot11ProbeReq):
        return "PROBE", _safe_upper_mac(pkt.addr2)
    if pkt.haslayer(Dot11AssoResp):
        return "ASSOC_RESP", _safe_upper_mac(pkt.addr2)
    if pkt.haslayer(Dot11AssoReq):
        return "ASSOC_REQ", _safe_upper_mac(pkt.addr2)
    if pkt.haslayer(Dot11ReassoResp):
        return "REASSOC_RESP", _safe_upper_mac(pkt.addr2)
    if pkt.haslayer(Dot11ReassoReq):
        return "REASSOC_REQ", _safe_upper_mac(pkt.addr2)
    if pkt.haslayer(Dot11Auth):
        return "AUTH", _safe_upper_mac(pkt.addr2)
    if pkt.haslayer(Dot11Deauth):
        return "DEAUTH", _safe_upper_mac(pkt.addr2)
    if pkt.haslayer(Dot11Disas):
        return "DISASSOC", _safe_upper_mac(pkt.addr2)
    return None, ""


def handle_packet(pkt) -> None:
    """Process each captured 802.11 frame."""
    pkt_type, mac_addr = classify_frame(pkt)
    if pkt_type is None or not mac_addr:
        return

    seq = (
        pkt[Dot11].SC >> 4
        if pkt.haslayer(Dot11) and pkt[Dot11].SC is not None
        else None
    )

    ssid = extract_ssid(
        pkt,
        "(Hidden SSID)" if pkt_type == "BEACON" else "(Wildcard)",
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

    timestamp    = time.strftime("%Y-%m-%d %H:%M:%S")
    dist_m       = calculate_distance(power)
    zone         = proximity_zone(dist_m)
    mac_type     = check_mac_type(mac_addr)
    now          = time.time()
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
    if pkt_type in CLIENT_FRAME_TYPES:
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
        print(
            f"{colour}{frame_tag} {timestamp} | {pkt_type:<11} | {mac_addr} | "
            f"CH:{str(channel):<3}| {power:>4}dBm | {dist_m:>5}m | "
            f"SSID: {ssid:<20} | {identity}{COLOUR_RESET}"
        )

    _append_csv_row([
        timestamp, pkt_type, mac_addr, mac_type,
        vendor, ssid, channel, band, power, dist_m,
        interval, ie_details["ie_sequence"], ie_details["ie_fingerprint"],
        ie_details["vendor_ies"], ie_details["capabilities"], identity,
        final_note, seq,
        body["listen_interval"], body["cap_info"], body["current_ap"],
        body["security_tier"], body["auth_status"], body["reason"],
        body["direction"],
    ])

    dump_ie_details(pkt, timestamp, pkt_type, mac_addr)


# ---------------------------------------------------------------------------
# Background threads
# ---------------------------------------------------------------------------

def channel_hopper() -> None:
    """Rotate through channels 1–13 continuously."""
    log.info("Channel hopper started on %s", INTERFACE)
    while True:
        for ch in range(1, 14):
            result = subprocess.run(
                ["iw", "dev", INTERFACE, "set", "channel", str(ch)],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.returncode != 0:
                log.warning("Channel hop to %s failed: %s", ch, result.stderr.strip())
            time.sleep(CHANNEL_HOP_INTERVAL)


def auto_report_worker() -> None:
    """Periodically save a session summary to disk."""
    while True:
        time.sleep(AUTO_SAVE_INTERVAL)
        generate_session_report()
        log.info("Auto-saved session summary (%s)", time.strftime("%H:%M:%S"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Passive Wi-Fi reconnaissance capture.")
    parser.add_argument(
        "--hop",
        action="store_true",
        help="Enable active channel hopping with iw. Disabled by default.",
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

    global TERMINAL_FRAME_FILTER
    TERMINAL_FRAME_FILTER = args.frames

    setup_csv()
    setup_ie_csv()

    log.info("Starting WiFi Recon on interface: %s", INTERFACE)
    log.info("Logging packets to            : %s", LOG_FILE)
    log.info("Logging IE breakdown to       : %s", IE_DETAILS_FILE)
    log.info("Max reconnect attempts        : %d", MAX_RETRIES)
    log.info("Terminal frame filter         : %s", TERMINAL_FRAME_FILTER)

    sep = "-" * 110
    print(sep)
    print(f"{'Type':11} | {'Timestamp':19} | {'MAC Address':17} | {'CH':<4}| "
          f"{'Pwr':>4} | {'Dist':>5} | SSID")
    print(sep)

    if args.hop:
        threading.Thread(target=channel_hopper, daemon=True).start()
    else:
        log.info("Channel hopping disabled — use --hop to rotate channels.")
    threading.Thread(target=auto_report_worker, daemon=True).start()

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
                sniff(iface=INTERFACE, prn=handle_packet, store=False)

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
                reset_monitor_mode(INTERFACE)

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
                reset_monitor_mode(INTERFACE)

    except KeyboardInterrupt:
        log.info("Interrupted – saving final session report …")

    generate_session_report()


if __name__ == "__main__":
    main()
