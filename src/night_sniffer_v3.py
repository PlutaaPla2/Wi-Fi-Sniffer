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
    Dot11, Dot11ProbeReq, Dot11Beacon, Dot11AssoReq, Dot11ReassoReq,
    Dot11Auth, Dot11Deauth, Dot11Disas, RadioTap,
    Dot11Elt, Dot11EltVendorSpecific
)
from mac_vendor_lookup import MacLookup

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

INTERFACE       = "wlan1"
LOG_FILE        = "wifi_full_recon_report.csv"
SUMMARY_PREFIX  = "daily_summary"
P0              = -35     # Reference RSSI at 1 metre
N               = 3.0     # Path-loss exponent (2.0 = open space, 3.0 = indoors)
SESSION_TIMEOUT = 600     # Seconds before a session is considered expired
AUTO_SAVE_INTERVAL = 60   # Seconds between auto-save of session summary
GROUP_SCORE_THRESHOLD = 6
OVERLAP_TOLERANCE_SECONDS = 5
CHANNEL_HOP_INTERVAL = 0.5

CLIENT_FRAME_TYPES = {
    "PROBE", "ASSOC_REQ", "REASSOC_REQ", "AUTH", "DEAUTH", "DISASSOC",
}

CSV_FIELDS = [
    "Timestamp", "Pkt_Type", "MAC_Address", "Device_Type",
    "Vendor", "SSID", "Channel", "Band", "Power_dBm", "Distance_m",
    "Interval_sec", "IE_Sequence", "IE_Fingerprint", "Vendor_IEs",
    "Capabilities", "Note", "Session_Note",
]

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

# ANSI colour codes
COLOUR_RESET  = "\033[0m"
COLOUR_RED    = "\033[91m"   # Apple
COLOUR_BLUE   = "\033[94m"   # Samsung
COLOUR_YELLOW = "\033[93m"   # Other known vendors
COLOUR_GREY   = "\033[90m"   # Unknown / generic

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


def calculate_distance(rssi: int) -> float:
    """Estimate distance (metres) from RSSI using the log-distance path-loss model."""
    if not rssi:
        return 0.0
    try:
        return round(math.pow(10, (P0 - rssi) / (10 * N)), 2)
    except (ValueError, ZeroDivisionError):
        return 0.0


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
# Packet fingerprinting
# ---------------------------------------------------------------------------

def extract_ie_details(pkt) -> dict[str, str]:
    """
    Extract stable 802.11 information-element evidence for later grouping.
    The fingerprint is a weak signal, not a unique device identity.

    This walks raw IE TLV bytes instead of Scapy's parsed Dot11Elt chain.
    Scapy can stop exposing Dot11Elt layers after an unknown element, but the
    bytes still follow [ID][length][data], so raw parsing preserves later IEs.
    """
    sequence: list[str] = []
    fingerprint_parts: list[str] = []
    vendor_ies: set[str] = set()
    capability_flags: set[str] = set()

    first_elt = pkt.getlayer(Dot11Elt)
    if first_elt is None:
        return {
            "ie_sequence": "",
            "ie_fingerprint": "",
            "vendor_ies": "",
            "capabilities": "",
        }

    raw_bytes = bytes(first_elt)
    i = 0
    while i + 1 < len(raw_bytes):
        ie_id = raw_bytes[i]
        ie_len = raw_bytes[i + 1]
        data_start = i + 2
        data_end = data_start + ie_len
        if data_end > len(raw_bytes):
            break

        info = raw_bytes[data_start:data_end]

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

        i = data_end

    raw_fingerprint = "|".join(fingerprint_parts)
    ie_fingerprint = (
        hashlib.sha1(raw_fingerprint.encode("ascii")).hexdigest()[:16]
        if raw_fingerprint else ""
    )

    return {
        "ie_sequence": ",".join(sequence),
        "ie_fingerprint": ie_fingerprint,
        "vendor_ies": ";".join(sorted(vendor_ies)),
        "capabilities": ";".join(sorted(capability_flags)),
    }


def extract_ssid(pkt, fallback: str) -> str:
    """Read SSID from packet info or SSID information element."""
    raw_ssid = getattr(pkt, "info", b"") or b""
    if not raw_ssid:
        ssid_el = pkt.getlayer(Dot11Elt, ID=0)
        raw_ssid = getattr(ssid_el, "info", b"") if ssid_el else b""
    try:
        return raw_ssid.decode("utf-8", errors="ignore") or fallback
    except AttributeError:
        return fallback


def get_correlation_identity(pkt) -> str:
    """
    Derive a human-readable device identity from a Probe Request or Beacon.
    Priority: Vendor Specific Tag (221) > MAC OUI > generic fallback.
    """
    vendor = "Generic"
    region = "Unknown"
    device_class = "IoT/Low-End"
    is_apple = False
    is_windows = False
    found_oui = "None"

    # --- Step 1: MAC OUI as baseline ---
    try:
        src_mac = _safe_upper_mac(getattr(pkt, "addr2", None))
        if not src_mac:
            src_mac = _safe_upper_mac(getattr(pkt, "addr3", None))
        mac_oui = oui_from_mac(src_mac)
        vendor = lookup_oui(mac_oui)
    except Exception:
        pass

    if pkt.haslayer(Dot11Elt):
        # --- Step 2: Vendor Specific Tag (ID 221) ---
        el = pkt.getlayer(Dot11EltVendorSpecific)
        while el:
            try:
                raw_oui = el.oui
                if isinstance(raw_oui, int):
                    oui_str = oui_int_to_str(raw_oui)
                    found_oui = oui_str
                    tag_vendor = lookup_oui(oui_str)
                    if "Unknown" not in tag_vendor:
                        vendor = tag_vendor          # Tag trumps MAC OUI
                    if raw_oui == 0x0017F2:
                        is_apple = True
                    if raw_oui == 0x0050F2:
                        is_windows = True
            except Exception:
                pass
            el = el.payload.getlayer(Dot11EltVendorSpecific)

        # --- Step 3: Extended-supported-rates Tag (ID 50) → region hint ---
        tag50 = pkt.getlayer(Dot11Elt, ID=50)
        if tag50:
            ch_list = list(tag50.info)
            region = "TH/EU" if (12 in ch_list or 13 in ch_list) else "US/Global"
            if len(ch_list) > 11:
                device_class = "High-End"

    # --- Decision logic ---
    if is_apple:
        return f"Apple Device ({region})"
    if is_windows:
        return f"Windows/PC ({vendor})"
    if "Tuya Smart" in vendor or "Espressif" in vendor:
        return f"Smart Home/IoT ({vendor})"
    if vendor != "Generic":
        return f"{vendor} ({region})"
    return f"Unknown Device [OUI:{found_oui}]"


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
    session.rssi = power
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
        left.first_ts <= right_last_ts + OVERLAP_TOLERANCE_SECONDS
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
    score = 0
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
        "vendor IE overlap",
        "probe SSID overlap",
        "close RSSI",
        "similar RSSI",
        "same zone",
        "frame type overlap",
        "nearby time window",
    }
    support_count = len(supporting_reasons & set(reasons))
    return support_count >= 2, score, reasons


def _update_session(
    session: Session,
    mac: str,
    power: int,
    zone: str,
    ssids: set[str],
    frame_type: str,
    ie_fingerprint: str,
    vendor_ies: set[str],
    now: float,
) -> None:
    """Merge one observation into an existing session."""
    session.last_mac = mac
    _update_rssi_stats(session, power)
    if zone != "unknown":
        session.zone = zone
    session.last_ts = now
    session.all_macs.add(mac)
    session.ssids.update(ssids)
    session.frame_types.add(frame_type)
    if ie_fingerprint:
        session.ie_fingerprints.add(ie_fingerprint)
    session.vendor_ies.update(vendor_ies)


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
) -> str:
    """
    Match this observation to an existing session or create a new one.
    Returns a label like 'New-User-3' or 'Existing-User-1'.
    """
    now = time.time()
    # Strip OUI noise for fingerprint comparison
    fingerprint = identity.split("[OUI:")[0].strip()
    ssid_set = {ssid for ssid in ssids if ssid}
    vendor_ie_set = _parse_set(vendor_ies)

    with _session_lock:
        _expire_sessions(now)

        # The same source MAC is always the same live session while unexpired.
        for sid, session in active_sessions.items():
            if mac in session.all_macs:
                _update_session(
                    session, mac, power, zone, ssid_set, frame_type,
                    ie_fingerprint, vendor_ie_set, now
                )
                return f"Existing-User-{sid}"

        # Real MACs are stable enough to avoid identity/RSSI merging.
        if mac_type == "Randomized":
            best_sid: int | None = None
            best_score = -99
            best_reasons: list[str] = []
            for sid, session in active_sessions.items():
                if session.mac_type != "Randomized":
                    continue
                allowed, score, reasons = _can_merge_randomized_session(
                    session, power, zone, ssid_set, frame_type,
                    ie_fingerprint, vendor_ie_set, now
                )
                if allowed and score > best_score:
                    best_sid = sid
                    best_score = score
                    best_reasons = reasons

            if best_sid is not None:
                session = active_sessions[best_sid]
                _update_session(
                    session, mac, power, zone, ssid_set, frame_type,
                    ie_fingerprint, vendor_ie_set, now
                )
                reason_text = ", ".join(best_reasons) if best_reasons else "matched evidence"
                log.debug("Merged randomized MAC %s into User-%s: %s", mac, best_sid, reason_text)
                return f"Existing-User-{best_sid}"

        # No match → new session
        new_id = max(active_sessions.keys(), default=0) + 1
        session = Session(
            last_mac=mac,
            all_macs={mac},
            fingerprint=fingerprint,
            ie_fingerprints={ie_fingerprint} if ie_fingerprint else set(),
            vendor_ies=vendor_ie_set,
            mac_type=mac_type,
            frame_types={frame_type},
            ssids=ssid_set,
            zone=zone,
            first_ts=now,
            last_ts=now,
        )
        _update_rssi_stats(session, power)
        active_sessions[new_id] = session
        return f"New-User-{new_id}"


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def generate_session_report() -> None:
    """Write a human-friendly daily summary CSV of active sessions."""
    report_file = f"{SUMMARY_PREFIX}_{time.strftime('%Y%m%d')}.csv"
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
            clean_id = s.fingerprint.split("(")[0].strip()
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
    if "Apple" in identity:
        return COLOUR_RED
    if "Samsung" in identity:
        return COLOUR_BLUE
    if "Unknown" in identity:
        return COLOUR_GREY
    return COLOUR_YELLOW


def handle_packet(pkt) -> None:
    """Process each captured 802.11 frame."""
    # --- Classify frame type ---
    if pkt.haslayer(Dot11Beacon):
        pkt_type = "BEACON"
        mac_addr = _safe_upper_mac(pkt.addr3)
    elif pkt.haslayer(Dot11ProbeReq):
        pkt_type = "PROBE"
        mac_addr = _safe_upper_mac(pkt.addr2)
    elif pkt.haslayer(Dot11AssoReq):
        pkt_type = "ASSOC_REQ"
        mac_addr = _safe_upper_mac(pkt.addr2)
    elif pkt.haslayer(Dot11ReassoReq):
        pkt_type = "REASSOC_REQ"
        mac_addr = _safe_upper_mac(pkt.addr2)
    elif pkt.haslayer(Dot11Auth):
        pkt_type = "AUTH"
        mac_addr = _safe_upper_mac(pkt.addr2)
    elif pkt.haslayer(Dot11Deauth):
        pkt_type = "DEAUTH"
        mac_addr = _safe_upper_mac(pkt.addr2)
    elif pkt.haslayer(Dot11Disas):
        pkt_type = "DISASSOC"
        mac_addr = _safe_upper_mac(pkt.addr2)
    else:
        return

    if not mac_addr:
        return

    ssid = extract_ssid(
        pkt,
        "(Hidden SSID)" if pkt_type == "BEACON" else "(Wildcard)",
    )

    # --- Radio metadata ---
    power: int = 0
    channel: int | str = "N/A"
    band = "N/A"
    if pkt.haslayer(RadioTap):
        rtap = pkt.getlayer(RadioTap)
        power = getattr(rtap, "dBm_AntSignal", 0) or 0
        if hasattr(rtap, "Channel"):
            channel = _freq_to_channel(rtap.Channel)
            band = _freq_to_band(rtap.Channel)

    # --- Derived fields ---
    timestamp    = time.strftime("%Y-%m-%d %H:%M:%S")
    dist_m       = calculate_distance(power)
    zone         = proximity_zone(dist_m)
    mac_type     = check_mac_type(mac_addr)
    vendor       = get_vendor(mac_addr, mac_type)
    now          = time.time()
    interval     = round(now - _last_seen.get(mac_addr, now), 2)
    _last_seen[mac_addr] = now

    identity     = get_correlation_identity(pkt)
    ie_details   = extract_ie_details(pkt)
    if pkt_type in CLIENT_FRAME_TYPES:
        session_note = track_session(
            mac_addr, identity, power, zone, [ssid], pkt_type,
            ie_details["ie_fingerprint"], ie_details["vendor_ies"], mac_type,
        )
    else:
        session_note = "AP-Logged-Only"
    final_note   = f"{session_note} | {identity}"
    colour       = _pick_colour(identity)

    # --- Terminal output (clients only) ---
    if pkt_type in CLIENT_FRAME_TYPES:
        print(
            f"{colour}[C] {timestamp} | {pkt_type:<11} | {mac_addr} | "
            f"CH:{str(channel):<3}| {power:>4}dBm | {dist_m:>5}m | "
            f"SSID: {ssid:<20} | {identity}{COLOUR_RESET}"
        )

    # --- CSV logging ---
    _append_csv_row([
        timestamp, pkt_type, mac_addr, mac_type,
        vendor, ssid, channel, band, power, dist_m,
        interval, ie_details["ie_sequence"], ie_details["ie_fingerprint"],
        ie_details["vendor_ies"], ie_details["capabilities"], identity,
        final_note,
    ])


# ---------------------------------------------------------------------------
# Background threads
# ---------------------------------------------------------------------------

def channel_hopper() -> None:
    """Rotate through channels 1–13 continuously."""
    log.info(f"Channel hopper started on {INTERFACE}")
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
        log.info(f"Auto-saved session summary ({time.strftime('%H:%M:%S')})")


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
    args = parser.parse_args()

    setup_csv()

    log.info(f"Starting WiFi Recon on interface: {INTERFACE}")
    log.info(f"Logging packets to: {LOG_FILE}")

    sep = "-" * 110
    print(sep)
    print(f"{'Type':11} | {'Timestamp':19} | {'MAC Address':17} | {'CH':<4}| "
          f"{'Pwr':>4} | {'Dist':>5} | SSID")
    print(sep)

    if args.hop:
        threading.Thread(target=channel_hopper, daemon=True).start()
    else:
        log.info("Channel hopping disabled. Use --hop to rotate channels.")
    threading.Thread(target=auto_report_worker, daemon=True).start()

    try:
        sniff(iface=INTERFACE, prn=handle_packet, store=False)
    except KeyboardInterrupt:
        log.info("Interrupted – saving final session report …")
        generate_session_report()


if __name__ == "__main__":
    main()
