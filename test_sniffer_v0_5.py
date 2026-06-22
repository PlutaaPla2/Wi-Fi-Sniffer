#!/usr/bin/env python3
"""
Passive WiFi Sniffer — Scapy
-------------------------------
Captures 802.11 (WiFi) management frames passively.
Extracts: MAC addresses, device names (from Probe Requests),
          SSIDs, signal strength, and frame types.

Requirements:
  - Kali Linux / Linux with wireless card
  - Interface must be in MONITOR MODE before running
  - Run with sudo

Setup:
  sudo ip link set wlan0 down
  sudo iw dev wlan0 set type monitor
  sudo ip link set wlan0 up
  sudo python3 wifi_sniffer.py --iface wlan0

CSV export:
  sudo python3 wifi_sniffer.py --iface wlan1 --csv results.csv
  sudo python3 wifi_sniffer.py --iface wlan1 --hop --csv results.csv --save capture.pcap

Distance estimation:
  sudo python3 wifi_sniffer.py --iface wlan1 --env office
  Environments: open (outdoors), office (default), indoor (walls/obstacles)
  Note: RSSI-based distance is an estimate (±3–5 m). Use for proximity, not exact location.

MAC analysis & IE fingerprinting (always on, no flag needed):
  - Detects whether each MAC is randomized (LA bit) or a real OUI
  - Looks up manufacturer name for real (non-randomized) MACs — checks a
    small curated table (KNOWN_OUIS) of common consumer brands first, then
    falls back to Scapy's full IEEE OUI database (conf.manufdb)
  - Builds a short hash "fingerprint" from each device's Information Element
    sequence (Probe Request / Beacon) — useful for spotting the same physical
    device across different randomized MACs. This does NOT reverse the MAC;
    it's indirect fingerprinting based on chipset/OS behaviour.

Adapter drop recovery (always on, no flag needed):
  - Some USB WiFi adapters drop out of monitor mode mid-capture, surfacing as:
      "Socket ... failed with '[Errno 100] Network is down'. It was closed."
  - When this happens, sniff() exits silently rather than raising. main() now
    detects this, runs `ip link down/up` + `iw set type monitor` to recover,
    waits a few seconds, and resumes capturing automatically (up to
    MAX_RETRIES attempts) without losing devices already in seen_devices.
"""

import argparse
import csv
import hashlib
import os
import time
from datetime import datetime
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Elt, RadioTap, conf


# ─── Distance estimation — Log-Distance Path Loss model ──────────────────────
#
# Formula:  distance = 10 ^ ( (TX_POWER - rssi) / (10 * N) )
#
# TX_POWER  : Expected RSSI at exactly 1 metre from the device (in dBm).
#             -59 dBm is a widely-used default for consumer WiFi devices.
#             You can calibrate this by measuring a known device at 1 m.
#
# N (path loss exponent): How much signal degrades with distance.
#   - Lower N = signal travels further per dB drop (open air)
#   - Higher N = signal drops faster (walls, furniture absorb it)
#
# These are the three presets selectable via --env:
ENVIRONMENTS = {
    #  name       N     description
    "open":   (2.0, "open air / outdoors"),
    "office": (2.7, "typical office with some walls"),   # default
    "indoor": (3.5, "dense indoor, many walls/obstacles"),
}

# Assumed transmit power at 1 metre (dBm). Adjust if you know your devices.
TX_POWER_DBM = -59

def estimate_distance(rssi, env="office"):
    """
    Convert an RSSI value (dBm) to an estimated distance in metres.

    Uses the Log-Distance Path Loss model:
        distance = 10 ^ ( (TX_POWER - rssi) / (10 * N) )

    Parameters
    ----------
    rssi : int or float
        Received signal strength in dBm (negative number, e.g. -65).
        Closer to 0 = stronger signal = closer device.
    env  : str
        One of "open", "office", "indoor". Controls the path loss exponent N.

    Returns
    -------
    dist_m : float
        Estimated distance in metres, rounded to 1 decimal place.
    zone   : str
        Human-readable proximity zone: "immediate", "near", "mid", or "far".
    """
    # Look up the path loss exponent N for the chosen environment.
    # .get() returns the "office" preset as fallback if env is unrecognised.
    N, _ = ENVIRONMENTS.get(env, ENVIRONMENTS["office"])

    # The core formula — all in one line, broken into readable parts:
    #   numerator   = TX_POWER - rssi  (how many dB below the 1m reference)
    #   denominator = 10 * N           (scaled by environment factor)
    #   exponent    = numerator / denominator
    #   distance    = 10 raised to that exponent
    exponent = (TX_POWER_DBM - rssi) / (10 * N)
    dist_m   = 10 ** exponent          # Python: ** is "to the power of"
    dist_m   = round(dist_m, 1)        # 1 decimal place is precise enough

    # ── Proximity zone ───────────────────────────────────────────────────────
    # Converts the raw number into a meaningful label for your report.
    # Thresholds are approximate — tune to your environment if needed.
    if dist_m <= 2:
        zone = "immediate  (<2 m)"
    elif dist_m <= 7:
        zone = "near       (2–7 m)"
    elif dist_m <= 20:
        zone = "mid        (7–20 m)"
    else:
        zone = "far        (>20 m)"

    return dist_m, zone


# ─── MAC address analysis ────────────────────────────────────────────────────
#
# Every MAC address is 6 bytes (12 hex digits), e.g. AA:BB:CC:DD:EE:FF.
# The first byte contains two special bits we care about:
#
#   Bit 0 (rightmost bit of first byte) = "Multicast" bit — ignore for our case
#   Bit 1                                = "Locally Administered" (LA) bit
#
# If the LA bit is 1, the OS generated this MAC itself — i.e. it's RANDOMIZED.
# If the LA bit is 0, it's the device's REAL, manufacturer-assigned MAC,
# and the first 3 bytes (the OUI) can be looked up to reveal the manufacturer.

def is_locally_administered(mac):
    """
    Check the Locally Administered (LA) bit of a MAC address.

    Returns
    -------
    True  -> MAC is randomized (software-generated, not from the factory)
    False -> MAC is the real, manufacturer-assigned address
    """
    # mac looks like "aa:bb:cc:dd:ee:ff" — take the first byte ("aa")
    first_byte = int(mac.split(":")[0], 16)

    # 0b00000010 is binary for "bit 1 set". The & operator checks if that
    # specific bit is set in first_byte, ignoring all other bits.
    return bool(first_byte & 0b00000010)


# ── Curated OUI table ─────────────────────────────────────────────────────────
# Scapy's conf.manufdb (the full IEEE registry) is comprehensive but its names
# are often formal/legal entity strings and it can be slow to search through
# thousands of entries. This small hand-picked table covers the consumer
# device brands most relevant to a WiFi sniffing project — phones, laptops,
# routers, and IoT/smart-home gear — with clean, recognisable names.
#
# Keys MUST be lowercase "xx:xx:xx" to match the normalised MAC string format
# used everywhere else in this script (see lookup_vendor below).
KNOWN_OUIS: dict[str, str] = {
    "00:17:f2": "Apple, Inc.",
    "00:00:f0": "Samsung Electronics",
    "00:e0:fc": "Huawei Technologies",
    "ac:f7:f3": "Xiaomi Communications",
    #"f8:a4:5f": "Oppo Mobile",                  # NOT MATCH manufdb
    #"d4:f5:13": "Vivo Mobile",                  # NOT MATCH manufdb
    "00:1a:11": "Google (Pixel/Nest)",
    "00:16:ea": "Intel Corp (Laptop)",
    "00:50:f2": "Microsoft (Surface/WPS)",
    "00:10:18": "Broadcom",
    #"00:23:45": "Foxconn",                      # NOT MATCH manufdb
    #"4c:ed:de": "AzureWave (IoT/Laptop)",       # NOT MATCH manufdb
    "50:c7:bf": "TP-Link",
    "00:00:0c": "Cisco Systems",
    "00:0f:3d": "D-Link",
    "00:bb:3a": "Amazon (Echo/Kindle)",
    "24:b2:de": "Espressif (IoT/SmartHome)",
    "84:e1:ba": "Tuya Smart (IoT)",             # NOT FOUND ON manufdb
    "00:04:1f": "Sony Interactive (PS)",
    "00:1f:32": "Nintendo (Switch)",
    #"44:fb:42": "Tesla, Inc.",                 # NOT MATCH manufdb
}


def lookup_vendor(mac):
    """
    Look up the manufacturer name from a MAC's OUI (first 3 bytes).

    Only meaningful if is_locally_administered(mac) is False — a randomized
    MAC's "OUI" is just noise and won't match a real manufacturer.

    Lookup order:
      1. KNOWN_OUIS — our curated table, checked first because its names
         are cleaner and more relevant to consumer WiFi devices.
      2. conf.manufdb — Scapy's full IEEE OUI database, used as a fallback
         for any OUI not in our curated list.
      3. "Unknown" — neither source recognised the OUI.
    """
    # Normalise to "xx:xx:xx" lowercase to match KNOWN_OUIS key format,
    # regardless of how the MAC string was capitalised when passed in.
    oui = ":".join(mac.split(":")[:3]).lower()

    # ── 1. Check our curated table first ─────────────────────────────────────
    if oui in KNOWN_OUIS:
        return KNOWN_OUIS[oui]

    # ── 2. Fall back to Scapy's full IEEE database ───────────────────────────
    try:
        vendor = conf.manufdb._get_manuf(mac)
    except Exception:
        vendor = None

    # _get_manuf() returns the MAC itself unchanged if it doesn't know the OUI
    if not vendor or vendor == mac:
        return "Unknown"
    return vendor


# ─── IE (Information Element) fingerprinting ────────────────────────────────
#
# Every Probe Request / Beacon carries a list of "Information Elements" (IEs)
# after the fixed header — things like supported data rates, HT capabilities,
# vendor-specific tags, etc. Each IE has a numeric ID.
#
# The SET and ORDER of IE IDs a device sends is largely determined by its
# WiFi chipset and OS/driver — NOT randomized like the MAC address. This means
# even when the MAC changes, the IE sequence often stays the same for that
# device, giving us a "fingerprint" we can use to:
#   1. Guess the device's OS/chipset family (educational — not exact)
#   2. Notice when two different randomized MACs are probably the same
#      physical device (same fingerprint seen twice)
#
# This is a passive, well-documented technique used in academic WiFi research
# (sometimes called "probe request fingerprinting").

# A few common IE IDs and what they represent — used to make the printed
# fingerprint human-readable. Not exhaustive; unknown IDs just show as numbers.
IE_NAMES = {
    0:   "SSID",
    1:   "Rates",
    3:   "DSSS",
    7:   "Country",
    32:  "PowerCap",
    33:  "TPC",
    36:  "Channels",
    45:  "HT-Cap",
    50:  "ExtRates",
    61:  "HT-Info",
    127: "ExtCap",
    191: "VHT-Cap",
    221: "Vendor",
}


def get_ie_fingerprint(pkt):
    """
    Walk the Information Elements in a packet and build a fingerprint.

    Parameters
    ----------
    pkt : Scapy packet
        Must contain at least one Dot11Elt layer (Probe Requests and
        Beacons both qualify).

    Returns
    -------
    dict with:
      "ie_ids"      : list of raw IE ID numbers, in the order they appeared
                      e.g. [0, 1, 50, 45, 127, 221, 221]
      "readable"    : the same list using IE_NAMES where known
                      e.g. "SSID-Rates-ExtRates-HT-Cap-ExtCap-Vendor-Vendor"
      "fingerprint" : short hash of ie_ids — a compact ID for comparing
                      devices (same hash = same IE sequence = likely same
                      chipset/OS, possibly same physical device)
      "vendor_ies"  : list of OUIs found inside Vendor Specific (ID 221)
                      elements — e.g. Microsoft's WMM tag, Apple tags, etc.
    """
    ie_ids = []
    vendor_ies = []

    # Dot11Elt layers are chained together like a linked list:
    # each element's .payload is the next element (or the end of the packet).
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None and elt.__class__.__name__ == "Dot11Elt":
        ie_ids.append(elt.ID)

        # ID 221 = "Vendor Specific" — the first 3 bytes of its content
        # are an OUI identifying who defined this particular extension
        # (e.g. Microsoft for WMM/WPS, or a phone manufacturer's own tag).
        if elt.ID == 221 and elt.info and len(elt.info) >= 3:
            vendor_ies.append(elt.info[:3].hex(":"))

        elt = elt.payload.getlayer(Dot11Elt)

    # Build a readable version using IE_NAMES, falling back to "ID<n>"
    readable = "-".join(IE_NAMES.get(i, f"ID{i}") for i in ie_ids)

    # Hash the ID sequence into a short, fixed-length string.
    # This makes it easy to compare two devices: same fingerprint string
    # => identical hash, easy to spot in a CSV or printed table.
    id_string = "-".join(str(i) for i in ie_ids)
    fingerprint = hashlib.md5(id_string.encode()).hexdigest()[:8]

    return {
        "ie_ids":      ie_ids,
        "readable":    readable,
        "fingerprint": fingerprint,
        "vendor_ies":  vendor_ies,
    }



# Dictionary keyed by MAC address.
# Each entry stores everything we've learned about that device.
seen_devices = {}

# Environment preset used by estimate_distance() — set in main() via --env.
_ENV = "office"

# Scan timing — set in main() just before sniff() starts.
# Using datetime objects here (not strings) so we can do maths on them
# to calculate duration. We convert to strings only when printing/exporting.
scan_start: datetime = None   # moment sniff() begins
scan_stop:  datetime = None   # moment sniff() ends (Ctrl+C or count reached)


# ─── 802.11 frame type reference ─────────────────────────────────────────────
# WiFi management frames have a 'subtype' number.
# These are the ones most useful for passive sniffing.
FRAME_TYPES = {
    0:  "Association Request",
    1:  "Association Response",
    2:  "Reassociation Request",
    4:  "Probe Request",      # Device scanning for known networks → reveals device name
    5:  "Probe Response",
    8:  "Beacon",             # AP broadcasting its existence → reveals SSID
    10: "Disassociation",
    11: "Authentication",
    12: "Deauthentication",
}


# ─── Packet handler ──────────────────────────────────────────────────────────
def handle_packet(pkt):
    """Called for every captured packet."""

    # We only care about 802.11 management frames (type=0)
    if not pkt.haslayer(Dot11):
        return
    if pkt[Dot11].type != 0:  # type 0 = management frame
        return

    subtype = pkt[Dot11].subtype
    frame_name = FRAME_TYPES.get(subtype, f"Unknown({subtype})")

    # Source MAC — the device that sent this frame
    src_mac = pkt[Dot11].addr2
    if not src_mac:
        return  # Some frames don't have a source

    # ── Signal strength (RSSI) ───────────────────────────────────────────────
    # RadioTap header contains signal info (if your card supports it)
    rssi = None
    if pkt.haslayer(RadioTap):
        # dBm_AntSignal is the received signal strength in dBm
        # e.g. -45 dBm = strong, -80 dBm = weak
        rssi = getattr(pkt[RadioTap], "dBm_AntSignal", None)

    # ── Device name from Probe Requests ─────────────────────────────────────
    # When a device scans for WiFi networks it knows, it sends Probe Requests.
    # These contain the SSID the device is looking for.
    # By collecting these, you build a "preferred network list" — very revealing.
    probe_ssid = None
    if subtype == 4 and pkt.haslayer(Dot11Elt):  # 4 = Probe Request
        ssid_element = pkt[Dot11Elt]
        if ssid_element.ID == 0:  # ID 0 = SSID element
            raw = ssid_element.info
            if raw:  # empty = wildcard probe (scanning for any network)
                try:
                    probe_ssid = raw.decode("utf-8", errors="replace")
                except Exception:
                    probe_ssid = str(raw)

    # ── Beacon SSID ──────────────────────────────────────────────────────────
    # Access Points broadcast Beacon frames every ~100ms with their SSID.
    beacon_ssid = None
    if subtype == 8 and pkt.haslayer(Dot11Beacon):  # 8 = Beacon
        # Walk the information elements to find SSID (ID=0)
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == 0:
                try:
                    beacon_ssid = elt.info.decode("utf-8", errors="replace")
                except Exception:
                    beacon_ssid = str(elt.info)
                break
            # Move to the next information element
            elt = elt.payload.getlayer(Dot11Elt)

    # ── IE fingerprint ───────────────────────────────────────────────────────
    # Probe Requests and Beacons both carry a list of Information Elements.
    # We fingerprint them to help characterize the device/chipset — see the
    # get_ie_fingerprint() docstring above for the full explanation.
    ie_fp = None
    if pkt.haslayer(Dot11Elt):
        ie_fp = get_ie_fingerprint(pkt)

    # ── Update device record ─────────────────────────────────────────────────
    if src_mac not in seen_devices:
        seen_devices[src_mac] = {
            "mac":         src_mac,
            "first_seen":  datetime.now().strftime("%H:%M:%S"),
            "last_seen":   datetime.now().strftime("%H:%M:%S"),
            "rssi":        rssi,
            "distance_m":  None,       # estimated distance in metres
            "zone":        None,       # proximity zone label
            "randomized":  is_locally_administered(src_mac),  # MAC analysis
            "vendor":      None,       # manufacturer name, only if not randomized
            "ie_fingerprint": None,    # short hash of IE sequence
            "ie_readable":    None,    # human-readable IE sequence
            "vendor_ies":     set(),   # OUIs seen in Vendor Specific (221) IEs
            "frame_types": set(),
            "probe_ssids": set(),   # Networks this device has looked for
            "beacon_ssid": None,    # If it's an AP, its network name
            "packet_count": 0,
        }
        # Only look up a vendor name if the MAC is NOT randomized —
        # a randomized MAC's OUI is meaningless noise.
        if not seen_devices[src_mac]["randomized"]:
            seen_devices[src_mac]["vendor"] = lookup_vendor(src_mac)
    else:
        seen_devices[src_mac]["last_seen"] = datetime.now().strftime("%H:%M:%S")
        if rssi:
            seen_devices[src_mac]["rssi"] = rssi  # Update with latest signal

    dev = seen_devices[src_mac]
    dev["packet_count"] += 1
    dev["frame_types"].add(frame_name)

    # ── Recalculate distance whenever we have a fresh RSSI reading ───────────
    # We recalculate every packet so the distance stays current as the
    # device moves. _ENV is set in main() from the --env argument.
    if rssi is not None:
        dev["distance_m"], dev["zone"] = estimate_distance(rssi, _ENV)

    # ── Store IE fingerprint ─────────────────────────────────────────────────
    # We overwrite with the latest fingerprint each time — for a given
    # device the IE sequence is normally stable across packets, so this
    # just keeps the record current. vendor_ies accumulates across packets
    # since not every frame includes the same Vendor Specific tags.
    if ie_fp is not None:
        dev["ie_fingerprint"] = ie_fp["fingerprint"]
        dev["ie_readable"]    = ie_fp["readable"]
        dev["vendor_ies"].update(ie_fp["vendor_ies"])

    if probe_ssid:
        dev["probe_ssids"].add(probe_ssid)

    if beacon_ssid:
        dev["beacon_ssid"] = beacon_ssid

    # ── Print live update ────────────────────────────────────────────────────
    print_device_update(src_mac, frame_name, probe_ssid, beacon_ssid, rssi)


def print_device_update(mac, frame_name, probe_ssid, beacon_ssid, rssi):
    """Print a single line summary when we see something interesting."""
    dev = seen_devices[mac]
    count = dev["packet_count"]

    # Only print on first sighting, or when we learn something new
    is_first = count == 1
    has_new_info = probe_ssid or beacon_ssid

    if not (is_first or has_new_info):
        return

    rssi_str = f"{rssi} dBm" if rssi else "N/A"

    if is_first:
        print(f"\n[+] NEW DEVICE  {mac}")
        print(f"    Frame type : {frame_name}")
        print(f"    Signal     : {rssi_str}")
        # Show distance if we were able to calculate it
        if dev["distance_m"] is not None:
            print(f"    Distance   : ~{dev['distance_m']} m  [{dev['zone']}]")
        # MAC analysis — randomized or real, and vendor if known
        if dev["randomized"]:
            print(f"    MAC type   : Randomized (LA bit set) — vendor not derivable")
        else:
            print(f"    MAC type   : Real OUI — Vendor: {dev['vendor']}")
        # IE fingerprint — helps characterize device even if MAC is random
        if dev["ie_fingerprint"]:
            print(f"    IE fingerprint : {dev['ie_fingerprint']}  ({dev['ie_readable']})")
        print(f"    Time       : {dev['first_seen']}")

    if beacon_ssid:
        print(f"    AP SSID    : \"{beacon_ssid}\"  ← This is an Access Point")

    if probe_ssid:
        print(f"    Probing for: \"{probe_ssid}\"  ← Network this device knows")


# ─── Summary printer ──────────────────────────────────────────────────────────
def print_summary():
    """Print a final summary table of all discovered devices."""
    print("\n" + "=" * 70)
    print(f"  SUMMARY — {len(seen_devices)} unique devices discovered")
    print("=" * 70)

    # ── Scan timing block ────────────────────────────────────────────────────
    # scan_start and scan_stop are datetime objects set in main().
    # We guard with 'if' in case main() exited before sniff() even started
    # (e.g. permission error), so scan_start could still be None.
    if scan_start and scan_stop:
        # timedelta is what you get when you subtract two datetime objects.
        # total_seconds() converts it to a plain float (e.g. 142.7 seconds).
        duration = scan_stop - scan_start          # timedelta object
        total_s  = int(duration.total_seconds())   # whole seconds only

        # Break into hours / minutes / seconds for a readable format.
        # The // operator is integer division (drops the remainder).
        # The % operator gives the remainder — so 142 % 60 = 22 seconds.
        hours   =  total_s // 3600
        minutes = (total_s % 3600) // 60
        seconds =  total_s % 60

        # Format: "0h 02m 22s" — zero-pad minutes and seconds to 2 digits
        # using the :02d format spec (d = integer, 02 = pad to width 2 with zeros)
        duration_str = f"{hours}h {minutes:02d}m {seconds:02d}s"

        print(f"\n  Scan started : {scan_start.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Scan stopped : {scan_stop.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Duration     : {duration_str}")

    # Separate APs (have beacon_ssid) from client devices
    aps      = {m: d for m, d in seen_devices.items() if d["beacon_ssid"]}
    clients  = {m: d for m, d in seen_devices.items() if not d["beacon_ssid"]}

    if aps:
        print(f"\n  ACCESS POINTS ({len(aps)})")
        print(f"  {'MAC':<20} {'SSID':<28} {'Signal':<10} {'Distance':<12} {'Pkts'}")
        print(f"  {'-'*18:<20} {'-'*26:<28} {'-'*8:<10} {'-'*10:<12} {'-'*4}")
        for mac, d in sorted(aps.items()):
            rssi_str = f"{d['rssi']} dBm" if d['rssi'] else "N/A"
            dist_str = f"~{d['distance_m']} m" if d['distance_m'] is not None else "N/A"
            print(f"  {mac:<20} {(d['beacon_ssid'] or ''):<28} {rssi_str:<10} {dist_str:<12} {d['packet_count']}")

    if clients:
        print(f"\n  CLIENT DEVICES ({len(clients)})")
        print(f"  {'MAC':<20} {'Signal':<8} {'Dist':<8} {'MAC Type / Vendor':<22} {'IE-FP':<10} {'Pkts':<5} {'Probed SSIDs'}")
        print(f"  {'-'*18:<20} {'-'*6:<8} {'-'*6:<8} {'-'*20:<22} {'-'*8:<10} {'-'*3:<5} {'-'*20}")
        for mac, d in sorted(clients.items()):
            rssi_str = f"{d['rssi']} dBm" if d['rssi'] else "N/A"
            dist_str = f"~{d['distance_m']}m" if d['distance_m'] is not None else "N/A"

            # MAC type / vendor column:
            #   - Randomized MAC  -> "Random (LA bit)"
            #   - Real MAC        -> the manufacturer name (e.g. "Apple, Inc.")
            if d["randomized"]:
                mac_type = "Random (LA bit)"
            else:
                mac_type = d["vendor"] or "Unknown"

            # IE fingerprint hash — short identifier for the IE sequence.
            # Two devices sharing this hash likely share a chipset/OS,
            # and the same device seen twice (different random MACs) will
            # usually show the SAME hash both times.
            ie_fp_str = d["ie_fingerprint"] or "N/A"

            probes = ", ".join(list(d["probe_ssids"])[:3])
            if len(d["probe_ssids"]) > 3:
                probes += f" (+{len(d['probe_ssids'])-3} more)"
            probes = probes or "(none captured)"

            print(f"  {mac:<20} {rssi_str:<8} {dist_str:<8} {mac_type:<22} {ie_fp_str:<10} {d['packet_count']:<5} {probes}")

    print()


# ─── CSV exporter ─────────────────────────────────────────────────────────────
# Python's built-in csv module writes rows to a file.
# csv.DictWriter lets you write dicts directly using column header names —
# no need to manually keep field order consistent.

# These are the column headers that will appear in row 1 of the CSV.
CSV_FIELDS = [
    "scan_start",    # when the capture session began
    "scan_stop",     # when the capture session ended
    "scan_duration", # total duration as a human-readable string (e.g. 0h 02m 22s)
    "mac",           # hardware address
    "type",          # "Access Point" or "Client Device"
    "ssid",          # AP name (if it's an AP), else blank
    "probe_ssids",   # semicolon-separated list of networks a client looked for
    "rssi_dbm",      # signal strength (negative number; closer to 0 = stronger)
    "distance_m",    # estimated distance in metres (Log-Distance Path Loss model)
    "zone",          # proximity zone: immediate / near / mid / far
    "mac_randomized",   # True if LA bit set (software-generated MAC)
    "vendor",           # manufacturer name from OUI (only if MAC is not randomized)
    "ie_fingerprint",   # short hash of the Information Element sequence
    "ie_sequence",      # human-readable IE sequence (e.g. SSID-Rates-HT-Cap-...)
    "vendor_ies",       # OUIs seen inside Vendor Specific (221) elements
    "packet_count",  # how many frames we captured from this device
    "frame_types",   # semicolon-separated list of management frame types seen
    "first_seen",    # timestamp of first packet from this device
    "last_seen",     # timestamp of most recent packet from this device
]

def export_csv(filepath):
    """Write the seen_devices dict to a CSV file."""

    # How many devices do we have?
    if not seen_devices:
        print("[!] No devices to export.")
        return

    # ── Pre-compute scan timing strings once ─────────────────────────────────
    # Same logic as print_summary — reuse scan_start / scan_stop globals.
    # These go into every row of the CSV so the file is self-contained:
    # anyone opening it later immediately knows when the scan ran.
    if scan_start and scan_stop:
        start_str    = scan_start.strftime("%Y-%m-%d %H:%M:%S")
        stop_str     = scan_stop.strftime("%Y-%m-%d %H:%M:%S")
        total_s      = int((scan_stop - scan_start).total_seconds())
        hours        =  total_s // 3600
        minutes      = (total_s % 3600) // 60
        seconds      =  total_s % 60
        duration_str = f"{hours}h {minutes:02d}m {seconds:02d}s"
    else:
        start_str = stop_str = duration_str = ""

    # Open the file for writing.
    # newline="" is required by Python's csv module on all platforms
    # to prevent it adding extra blank lines on Windows.
    # encoding="utf-8" handles special characters in SSIDs.
    with open(filepath, "w", newline="", encoding="utf-8") as f:

        # DictWriter takes: the file, and the list of column names
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)

        # writeheader() writes the column names as the first row
        writer.writeheader()

        for mac, d in sorted(seen_devices.items()):
            is_ap = bool(d["beacon_ssid"])

            # Build the row as a plain dict — keys match CSV_FIELDS exactly.
            # scan_start / scan_stop / scan_duration repeat on every row —
            # this is intentional so the file stays self-contained and each
            # row can be filtered / exported independently without losing context.
            row = {
                "scan_start":    start_str,
                "scan_stop":     stop_str,
                "scan_duration": duration_str,
                "mac":          mac,
                "type":         "Access Point" if is_ap else "Client Device",
                "ssid":         d["beacon_ssid"] or "",
                "probe_ssids":  "; ".join(sorted(d["probe_ssids"])),
                "rssi_dbm":     d["rssi"] if d["rssi"] is not None else "",
                "distance_m":   d["distance_m"] if d["distance_m"] is not None else "",
                "zone":         d["zone"] or "",
                "mac_randomized": d["randomized"],
                "vendor":         d["vendor"] or "",
                "ie_fingerprint": d["ie_fingerprint"] or "",
                "ie_sequence":    d["ie_readable"] or "",
                "vendor_ies":     "; ".join(sorted(d["vendor_ies"])),
                "packet_count": d["packet_count"],
                "frame_types":  "; ".join(sorted(d["frame_types"])),
                "first_seen":   d["first_seen"],
                "last_seen":    d["last_seen"],
            }

            # writerow() writes one dict as one CSV row
            writer.writerow(row)

    print(f"[*] CSV saved → {filepath}  ({len(seen_devices)} devices)")


# ─── Channel hopper (optional) ───────────────────────────────────────────────
def start_channel_hopper(iface, interval=0.5):
    """
    Optionally hop between WiFi channels so you see more devices.
    Devices transmit on different channels (1–13 for 2.4GHz, more for 5GHz).
    If you stay on one channel, you only see traffic on that channel.

    Run this in a separate thread (see main below).
    """
    import os
    import time
    channels = list(range(1, 14))  # 2.4 GHz channels
    print(f"[*] Channel hopper started on {iface} (2.4 GHz, channels 1-13)")
    while True:
        for ch in channels:
            os.system(f"iwconfig {iface} channel {ch} 2>/dev/null")
            time.sleep(interval)


# ─── Adapter recovery ─────────────────────────────────────────────────────────
def reset_monitor_mode(iface):
    """
    Attempt to re-establish monitor mode on an interface that dropped out.

    This mirrors the manual recovery commands from the setup instructions:
        sudo ip link set <iface> down
        sudo iw dev <iface> set type monitor
        sudo ip link set <iface> up

    We call os.system() for each step rather than a Linux-specific library —
    keeps this dependency-free and matches exactly what you'd type by hand.
    Each command's exit status isn't checked individually; if the interface
    truly disappeared (e.g. USB adapter unplugged), the next sniff() attempt
    will simply fail again and the retry loop in main() will keep trying.
    """
    print(f"[*] Attempting to reset monitor mode on {iface}...")
    os.system(f"ip link set {iface} down")
    os.system(f"iw dev {iface} set type monitor")
    os.system(f"ip link set {iface} up")
    # Small pause to let the kernel/driver settle before sniff() retries.
    time.sleep(1)


# ─── Entry point ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Passive WiFi sniffer — captures 802.11 management frames"
    )
    parser.add_argument(
        "--iface", "-i",
        default="wlan1",
        help="Wireless interface in monitor mode (default: wlan1)"
    )
    parser.add_argument(
        "--count", "-c",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited, Ctrl+C to stop)"
    )
    parser.add_argument(
        "--hop", "-H",
        action="store_true",
        help="Enable channel hopping (sees more devices, requires threading)"
    )
    parser.add_argument(
        "--save", "-s",
        default=None,
        help="Save captured packets to a .pcap file (e.g. --save capture.pcap)"
    )
    parser.add_argument(
        "--csv",
        default=None,
        metavar="FILE",
        help="Export device summary to a CSV file after capture (e.g. --csv results.csv)"
    )
    parser.add_argument(
        "--env",
        default="office",
        choices=["open", "office", "indoor"],
        help=(
            "Environment preset for distance estimation (default: office).\n"
            "  open   — outdoors, N=2.0\n"
            "  office — typical office, N=2.7\n"
            "  indoor — dense walls, N=3.5"
        )
    )
    args = parser.parse_args()

    # ── Store chosen environment in a module-level variable ──────────────────
    # handle_packet() calls estimate_distance() for every packet, and it needs
    # to know which environment preset to use. Rather than passing args all the
    # way down, we set a simple global here. This is a common pattern for
    # configuration values that are set once and read many times.
    global _ENV
    _ENV = args.env
    _, env_desc = ENVIRONMENTS[_ENV]
    print(f"[*] Distance model  : {_ENV}  ({env_desc},  TX ref = {TX_POWER_DBM} dBm)")

    # ── Optional: start channel hopper in background thread ──────────────────
    if args.hop:
        import threading
        hopper = threading.Thread(
            target=start_channel_hopper,
            args=(args.iface,),
            daemon=True  # dies when main thread exits
        )
        hopper.start()

    print(f"\n[*] Starting passive WiFi sniff on interface: {args.iface}")
    print(f"[*] Capturing {'unlimited' if args.count == 0 else args.count} packets")
    print("[*] Press Ctrl+C to stop and see summary\n")
    print("-" * 50)

    captured_packets = []

    # ── Retry settings for adapter drops ──────────────────────────────────────
    # USB WiFi adapters occasionally drop out of monitor mode — common causes:
    # power management resets, the adapter briefly disconnecting/reconnecting,
    # or another process (NetworkManager, wpa_supplicant) touching the interface.
    # When this happens, Scapy's socket layer catches the OSError itself,
    # prints a "Socket ... failed ... Network is down" warning, and returns
    # normally from sniff() — it does NOT raise an exception we can catch.
    # So instead of relying on try/except alone, we wrap sniff() in a loop
    # that re-enters monitor mode and restarts capture automatically.
    MAX_RETRIES = 10        # give up after this many consecutive failures
    RETRY_DELAY = 3         # seconds to wait before retrying
    retry_count = 0

    # Total packets captured across ALL attempts (including before a drop).
    # A plain int can't be reassigned from inside handler() without `nonlocal`,
    # so we use a single-item list as a simple mutable counter — a common
    # Python pattern for sharing a counter between a closure and its outer scope.
    packets_captured = [0]

    # Record start time once, before the retry loop — this should reflect
    # the whole session's start, not just the most recent successful attempt.
    global scan_start, scan_stop
    scan_start = datetime.now()

    try:
        def handler(pkt):
            handle_packet(pkt)
            packets_captured[0] += 1
            if args.save:
                captured_packets.append(pkt)

        # ── Outer loop: keep restarting sniff() until count is reached,
        #    the user hits Ctrl+C, or we exceed MAX_RETRIES failures ──────────
        while True:
            # If a packet limit was set, only ask sniff() for the remaining
            # amount — otherwise a retry after a drop would over-capture.
            if args.count > 0:
                remaining = args.count - packets_captured[0]
                if remaining <= 0:
                    break  # already reached the requested count
            else:
                remaining = 0  # 0 = unlimited, same meaning sniff() expects

            try:
                sniff(
                    iface=args.iface,
                    prn=handler,
                    count=remaining,
                    store=False,          # memory-efficient for long captures
                    monitor=True,         # confirm monitor mode
                )

                # sniff() returned. If we had a count limit and reached it,
                # we're done — exit cleanly. Otherwise (unlimited mode, or
                # count not yet reached) this means the adapter dropped out.
                if args.count > 0 and packets_captured[0] >= args.count:
                    break

                retry_count += 1
                if retry_count > MAX_RETRIES:
                    print(f"\n[!] Gave up after {MAX_RETRIES} reconnect attempts.")
                    break

                print(f"\n[!] Capture socket closed unexpectedly "
                      f"(adapter may have dropped out of monitor mode).")
                print(f"[*] Reconnect attempt {retry_count}/{MAX_RETRIES} "
                      f"in {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
                reset_monitor_mode(args.iface)

            except OSError as e:
                # Some adapter failures DO raise here instead of just
                # printing Scapy's internal warning — covers both cases.
                retry_count += 1
                if retry_count > MAX_RETRIES:
                    print(f"\n[!] Gave up after {MAX_RETRIES} reconnect attempts: {e}")
                    break
                print(f"\n[!] Socket error: {e}")
                print(f"[*] Reconnect attempt {retry_count}/{MAX_RETRIES} "
                      f"in {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
                reset_monitor_mode(args.iface)

    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")

    except PermissionError:
        print("\n[!] Permission denied — run with sudo")
        return

    except Exception as e:
        print(f"\n[!] Error: {e}")
        print("    Make sure the interface is in monitor mode:")
        print(f"    sudo iw dev {args.iface} set type monitor")
        return

    finally:
        # Record stop time as soon as the capture loop exits (for any reason).
        scan_stop = datetime.now()

        # Always print summary, even if interrupted
        print_summary()

        # Save to pcap if requested
        if args.save and captured_packets:
            from scapy.all import wrpcap
            wrpcap(args.save, captured_packets)
            print(f"[*] Packets saved to: {args.save}")

        # Export CSV if requested
        if args.csv:
            export_csv(args.csv)


if __name__ == "__main__":
    main()
