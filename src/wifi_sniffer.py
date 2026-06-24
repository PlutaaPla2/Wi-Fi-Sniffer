#!/usr/bin/env python3
"""
wifi_sniffer.py — Passive 802.11 WiFi sniffer (logic + entry point)
---------------------------------------------------------------------
Captures WiFi management frames passively and extracts:
  MAC addresses, probe SSIDs, signal strength, distance estimates,
  MAC randomization status, vendor names, and IE fingerprints.

All user-editable settings live in config.py — edit that file,
not this one.

Requirements:
  - Kali Linux with a WiFi adapter that supports monitor mode
  - Run with sudo
  - wlan1 must be in monitor mode before starting

Setup (one-time):
  sudo ip link set wlan1 down
  sudo iw dev wlan1 set type monitor
  sudo ip link set wlan1 up

Usage:
  sudo python3 wifi_sniffer.py --iface wlan1
  sudo python3 wifi_sniffer.py --iface wlan1 --hop
  sudo python3 wifi_sniffer.py --iface wlan1 --hop --env office
  sudo python3 wifi_sniffer.py --iface wlan1 --count 500
  sudo python3 wifi_sniffer.py --iface wlan1 --hop --save capture.pcap
"""

import argparse
import csv
import hashlib
import os
import time
from datetime import datetime

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, RadioTap, conf, sniff

# Import every setting from config.py.
# Using "from config import *" would also work but explicit imports make it
# clear exactly what this file depends on, which is better practice.
from config import (
    CSV_FIELDS,
    ENVIRONMENTS,
    FRAME_TYPES,
    IE_NAMES,
    KNOWN_OUIS,
    MAX_RETRIES,
    OUTPUT_DIR,
    RETRY_DELAY,
    TX_POWER_DBM,
    ZONE_IMMEDIATE_M,
    ZONE_MID_M,
    ZONE_NEAR_M,
)


# ─── Runtime state ────────────────────────────────────────────────────────────
# These are NOT config — they change as the script runs.
# They live here (not in config.py) because config.py is a static settings
# file and should never be modified at runtime.

# All discovered devices, keyed by MAC address.
seen_devices: dict = {}

# Active environment preset — set from --env arg in main(), read by handle_packet().
_ENV: str = "office"

# Scan timing — set in main() around the sniff() call.
# datetime objects so we can subtract them to get duration.
scan_start: datetime = None
scan_stop:  datetime = None


# ─── Distance estimation ──────────────────────────────────────────────────────
def estimate_distance(rssi: int, env: str = "office") -> tuple[float, str]:
    """
    Convert RSSI (dBm) to an estimated distance using the
    Log-Distance Path Loss model:

        distance = 10 ^ ( (TX_POWER_DBM - rssi) / (10 * N) )

    Parameters
    ----------
    rssi : int
        Received signal strength in dBm (negative, e.g. -65).
    env  : str
        Environment preset key from config.ENVIRONMENTS.

    Returns
    -------
    dist_m : float   — estimated distance in metres (1 decimal place)
    zone   : str     — proximity label (immediate / near / mid / far)
    """
    N, _ = ENVIRONMENTS.get(env, ENVIRONMENTS["office"])
    exponent = (TX_POWER_DBM - rssi) / (10 * N)
    dist_m   = round(10 ** exponent, 1)

    # Proximity zone — thresholds come from config.py so you can tune them.
    if dist_m <= ZONE_IMMEDIATE_M:
        zone = f"immediate  (<{ZONE_IMMEDIATE_M} m)"
    elif dist_m <= ZONE_NEAR_M:
        zone = f"near       ({ZONE_IMMEDIATE_M}–{ZONE_NEAR_M} m)"
    elif dist_m <= ZONE_MID_M:
        zone = f"mid        ({ZONE_NEAR_M}–{ZONE_MID_M} m)"
    else:
        zone = f"far        (>{ZONE_MID_M} m)"

    return dist_m, zone


# ─── MAC analysis ─────────────────────────────────────────────────────────────
def is_locally_administered(mac: str) -> bool:
    """
    Return True if the MAC's LA (Locally Administered) bit is set,
    meaning the address was software-generated (randomized).

    Bit 1 of the first byte is the LA bit.
    0b00000010 isolates it via a bitwise AND.
    """
    first_byte = int(mac.split(":")[0], 16)
    return bool(first_byte & 0b00000010)


def lookup_vendor(mac: str) -> str:
    """
    Look up the manufacturer name from a MAC's OUI (first 3 bytes).

    Priority order:
      1. config.KNOWN_OUIS  — curated table with clean consumer-brand names
      2. Scapy conf.manufdb — full IEEE OUI database as a fallback
      3. "Unknown"          — if neither source knows the OUI
    """
    oui = ":".join(mac.split(":")[:3]).lower()

    if oui in KNOWN_OUIS:
        return KNOWN_OUIS[oui]

    try:
        vendor = conf.manufdb._get_manuf(mac)
    except Exception:
        vendor = None

    if not vendor or vendor == mac:
        return "Unknown"
    return vendor


# ─── IE fingerprinting ────────────────────────────────────────────────────────
def get_ie_fingerprint(pkt) -> dict:
    """
    Walk Information Elements via raw TLV bytes and build a fingerprint.

    Returns a dict with keys:
      ie_ids      — list of IE ID numbers in order
      readable    — same IDs mapped through config.IE_NAMES
      fingerprint — 8-char MD5 hash of the ID sequence
      vendor_ies  — list of OUI strings from Vendor Specific (ID 221) IEs

    Why raw bytes instead of Scapy's layer chain:
      Scapy stops producing Dot11Elt objects the moment it hits an IE type
      it can't fully dissect — dropping the rest as a Raw blob. Walking the
      raw bytes instead means we recover ALL IEs regardless of whether Scapy
      recognises each one, since every IE follows the same fixed TLV layout:
          [1 byte ID][1 byte Length][Length bytes Data]
    """
    ie_ids     = []
    vendor_ies = []

    first_elt = pkt.getlayer(Dot11Elt)
    if first_elt is None:
        return {"ie_ids": [], "readable": "", "fingerprint": "", "vendor_ies": []}

    raw_bytes = bytes(first_elt)
    i = 0

    while i + 1 < len(raw_bytes):
        ie_id      = raw_bytes[i]
        ie_len     = raw_bytes[i + 1]
        data_start = i + 2
        data_end   = data_start + ie_len

        if data_end > len(raw_bytes):
            break   # truncated frame — stop safely

        ie_ids.append(ie_id)

        if ie_id == 221 and ie_len >= 3:
            vendor_oui = raw_bytes[data_start:data_start + 3]
            vendor_ies.append(vendor_oui.hex(":"))

        i = data_end

    readable    = "-".join(IE_NAMES.get(x, f"ID{x}") for x in ie_ids)
    id_string   = "-".join(str(x) for x in ie_ids)
    fingerprint = hashlib.md5(id_string.encode()).hexdigest()[:8]

    return {
        "ie_ids":      ie_ids,
        "readable":    readable,
        "fingerprint": fingerprint,
        "vendor_ies":  vendor_ies,
    }


# ─── Packet handler ───────────────────────────────────────────────────────────
def handle_packet(pkt) -> None:
    """Called by sniff() for every captured frame."""

    if not pkt.haslayer(Dot11):
        return
    if pkt[Dot11].type != 0:        # 0 = management frame
        return

    subtype    = pkt[Dot11].subtype
    frame_name = FRAME_TYPES.get(subtype, f"Unknown({subtype})")
    src_mac    = pkt[Dot11].addr2

    if not src_mac:
        return

    # ── RSSI ─────────────────────────────────────────────────────────────────
    rssi = None
    if pkt.haslayer(RadioTap):
        rssi = getattr(pkt[RadioTap], "dBm_AntSignal", None)

    # ── Probe Request SSID ───────────────────────────────────────────────────
    probe_ssid = None
    if subtype == 4 and pkt.haslayer(Dot11Elt):
        ssid_elt = pkt[Dot11Elt]
        if ssid_elt.ID == 0 and ssid_elt.info:
            try:
                probe_ssid = ssid_elt.info.decode("utf-8", errors="replace")
            except Exception:
                probe_ssid = str(ssid_elt.info)

    # ── Beacon SSID ──────────────────────────────────────────────────────────
    beacon_ssid = None
    if subtype == 8 and pkt.haslayer(Dot11Beacon):
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == 0:
                try:
                    beacon_ssid = elt.info.decode("utf-8", errors="replace")
                except Exception:
                    beacon_ssid = str(elt.info)
                break
            elt = elt.payload.getlayer(Dot11Elt)

    # ── IE fingerprint ───────────────────────────────────────────────────────
    ie_fp = get_ie_fingerprint(pkt) if pkt.haslayer(Dot11Elt) else None

    # ── Create or update device record ───────────────────────────────────────
    if src_mac not in seen_devices:
        is_rand = is_locally_administered(src_mac)
        seen_devices[src_mac] = {
            "mac":            src_mac,
            "first_seen":     datetime.now().strftime("%H:%M:%S"),
            "last_seen":      datetime.now().strftime("%H:%M:%S"),
            "rssi":           rssi,
            "distance_m":     None,
            "zone":           None,
            "randomized":     is_rand,
            "vendor":         None if is_rand else lookup_vendor(src_mac),
            "ie_fingerprint": None,
            "ie_readable":    None,
            "vendor_ies":     set(),
            "frame_types":    set(),
            "probe_ssids":    set(),
            "beacon_ssid":    None,
            "packet_count":   0,
        }
    else:
        seen_devices[src_mac]["last_seen"] = datetime.now().strftime("%H:%M:%S")
        if rssi:
            seen_devices[src_mac]["rssi"] = rssi

    dev = seen_devices[src_mac]
    dev["packet_count"] += 1
    dev["frame_types"].add(frame_name)

    if rssi is not None:
        dev["distance_m"], dev["zone"] = estimate_distance(rssi, _ENV)

    if ie_fp:
        dev["ie_fingerprint"] = ie_fp["fingerprint"]
        dev["ie_readable"]    = ie_fp["readable"]
        dev["vendor_ies"].update(ie_fp["vendor_ies"])

    if probe_ssid:
        dev["probe_ssids"].add(probe_ssid)

    if beacon_ssid:
        dev["beacon_ssid"] = beacon_ssid

    print_device_update(src_mac, frame_name, probe_ssid, beacon_ssid, rssi)


# ─── Live print ───────────────────────────────────────────────────────────────
def print_device_update(mac, frame_name, probe_ssid, beacon_ssid, rssi) -> None:
    """Print to terminal only on first sighting or when new info arrives."""
    dev      = seen_devices[mac]
    is_first = dev["packet_count"] == 1

    if not (is_first or probe_ssid or beacon_ssid):
        return

    rssi_str = f"{rssi} dBm" if rssi else "N/A"

    if is_first:
        print(f"\n[+] NEW DEVICE  {mac}")
        print(f"    Frame type : {frame_name}")
        print(f"    Signal     : {rssi_str}")
        if dev["distance_m"] is not None:
            print(f"    Distance   : ~{dev['distance_m']} m  [{dev['zone']}]")
        if dev["randomized"]:
            print(f"    MAC type   : Randomized (LA bit set) — vendor not derivable")
        else:
            print(f"    MAC type   : Real OUI — Vendor: {dev['vendor']}")
        if dev["ie_fingerprint"]:
            print(f"    IE fp      : {dev['ie_fingerprint']}  ({dev['ie_readable']})")
        print(f"    Time       : {dev['first_seen']}")

    if beacon_ssid:
        print(f"    AP SSID    : \"{beacon_ssid}\"")
    if probe_ssid:
        print(f"    Probing for: \"{probe_ssid}\"")


# ─── Summary ──────────────────────────────────────────────────────────────────
def print_summary() -> None:
    """Print final table to terminal after capture ends."""
    print("\n" + "=" * 70)
    print(f"  SUMMARY — {len(seen_devices)} unique devices discovered")
    print("=" * 70)

    if scan_start and scan_stop:
        total_s      = int((scan_stop - scan_start).total_seconds())
        hours        =  total_s // 3600
        minutes      = (total_s % 3600) // 60
        seconds      =  total_s % 60
        duration_str = f"{hours}h {minutes:02d}m {seconds:02d}s"
        print(f"\n  Scan started : {scan_start.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Scan stopped : {scan_stop.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Duration     : {duration_str}")

    aps     = {m: d for m, d in seen_devices.items() if d["beacon_ssid"]}
    clients = {m: d for m, d in seen_devices.items() if not d["beacon_ssid"]}

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
            dist_str = f"~{d['distance_m']}m"  if d['distance_m'] is not None else "N/A"
            mac_type = "Random (LA bit)" if d["randomized"] else (d["vendor"] or "Unknown")
            ie_fp    = d["ie_fingerprint"] or "N/A"
            probes   = ", ".join(list(d["probe_ssids"])[:3])
            if len(d["probe_ssids"]) > 3:
                probes += f" (+{len(d['probe_ssids'])-3} more)"
            probes = probes or "(none captured)"
            print(f"  {mac:<20} {rssi_str:<8} {dist_str:<8} {mac_type:<22} {ie_fp:<10} {d['packet_count']:<5} {probes}")

    print()


# ─── CSV export ───────────────────────────────────────────────────────────────
def export_csv(filepath: str) -> None:
    """Write seen_devices to a CSV file at filepath."""
    if not seen_devices:
        print("[!] No devices to export.")
        return

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

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()

        for mac, d in sorted(seen_devices.items()):
            is_ap = bool(d["beacon_ssid"])
            writer.writerow({
                "scan_start":     start_str,
                "scan_stop":      stop_str,
                "scan_duration":  duration_str,
                "mac":            mac,
                "type":           "Access Point" if is_ap else "Client Device",
                "ssid":           d["beacon_ssid"] or "",
                "probe_ssids":    "; ".join(sorted(d["probe_ssids"])),
                "rssi_dbm":       d["rssi"] if d["rssi"] is not None else "",
                "distance_m":     d["distance_m"] if d["distance_m"] is not None else "",
                "zone":           d["zone"] or "",
                "mac_randomized": d["randomized"],
                "vendor":         d["vendor"] or "",
                "ie_fingerprint": d["ie_fingerprint"] or "",
                "ie_sequence":    d["ie_readable"] or "",
                "vendor_ies":     "; ".join(sorted(d["vendor_ies"])),
                "packet_count":   d["packet_count"],
                "frame_types":    "; ".join(sorted(d["frame_types"])),
                "first_seen":     d["first_seen"],
                "last_seen":      d["last_seen"],
            })

    print(f"[*] CSV saved → {filepath}  ({len(seen_devices)} devices)")


# ─── Channel hopper ───────────────────────────────────────────────────────────
def start_channel_hopper(iface: str, interval: float = 0.5) -> None:
    """
    Cycle through 2.4 GHz channels 1-13 on a background daemon thread.
    Each channel is held for `interval` seconds before switching.
    Runs forever — stopped automatically when the main thread exits
    because the thread is marked daemon=True in main().
    """
    channels = list(range(1, 14))
    print(f"[*] Channel hopper started on {iface} (channels 1-13)")
    while True:
        for ch in channels:
            os.system(f"iwconfig {iface} channel {ch} 2>/dev/null")
            time.sleep(interval)


# ─── Adapter recovery ─────────────────────────────────────────────────────────
def reset_monitor_mode(iface: str) -> None:
    """
    Re-establish monitor mode after an adapter drop.
    Runs the same three shell commands as the manual setup instructions.
    """
    print(f"[*] Resetting monitor mode on {iface}...")
    os.system(f"ip link set {iface} down")
    os.system(f"iw dev {iface} set type monitor")
    os.system(f"ip link set {iface} up")
    time.sleep(1)


# ─── Entry point ──────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Passive WiFi sniffer — captures 802.11 management frames"
    )
    parser.add_argument("--iface", "-i", default="wlan1",
                        help="Monitor-mode interface (default: wlan1)")
    parser.add_argument("--count", "-c", type=int, default=0,
                        help="Packets to capture (0 = unlimited)")
    parser.add_argument("--hop",   "-H", action="store_true",
                        help="Enable channel hopping across 2.4 GHz channels 1-13")
    parser.add_argument("--save",  "-s", default=None,
                        help="Save raw packets to a .pcap file")
    parser.add_argument("--env",         default="office",
                        choices=list(ENVIRONMENTS.keys()),
                        help="Distance model environment (default: office)")
    args = parser.parse_args()

    # Push chosen env into module-level state so handle_packet() can read it
    global _ENV, scan_start, scan_stop
    _ENV = args.env
    _, env_desc = ENVIRONMENTS[_ENV]

    print(f"[*] Interface       : {args.iface}")
    print(f"[*] Distance model  : {_ENV}  ({env_desc},  TX ref = {TX_POWER_DBM} dBm)")
    print(f"[*] Channel hopping : {'on' if args.hop else 'off'}")
    print(f"[*] Output dir      : {OUTPUT_DIR}/")
    print(f"[*] Packets to cap  : {'unlimited' if args.count == 0 else args.count}")
    print("[*] Press Ctrl+C to stop\n" + "-" * 50)

    if args.hop:
        import threading
        threading.Thread(
            target=start_channel_hopper,
            args=(args.iface,),
            daemon=True
        ).start()

    captured_packets = []
    packets_captured = [0]   # mutable counter accessible from handler() closure
    retry_count      = 0
    scan_start       = datetime.now()

    def handler(pkt):
        handle_packet(pkt)
        packets_captured[0] += 1
        if args.save:
            captured_packets.append(pkt)

    try:
        while True:
            remaining = (args.count - packets_captured[0]) if args.count > 0 else 0
            if args.count > 0 and remaining <= 0:
                break

            try:
                sniff(iface=args.iface, prn=handler, count=remaining,
                      store=False, monitor=True)

                if args.count > 0 and packets_captured[0] >= args.count:
                    break

                # sniff() returned early — adapter likely dropped out
                retry_count += 1
                if retry_count > MAX_RETRIES:
                    print(f"\n[!] Gave up after {MAX_RETRIES} reconnect attempts.")
                    break
                print(f"\n[!] Socket closed unexpectedly.")
                print(f"[*] Reconnect attempt {retry_count}/{MAX_RETRIES} in {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
                reset_monitor_mode(args.iface)

            except OSError as e:
                retry_count += 1
                if retry_count > MAX_RETRIES:
                    print(f"\n[!] Gave up after {MAX_RETRIES} attempts: {e}")
                    break
                print(f"\n[!] Socket error: {e}")
                print(f"[*] Reconnect attempt {retry_count}/{MAX_RETRIES} in {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
                reset_monitor_mode(args.iface)

    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
    except PermissionError:
        print("\n[!] Permission denied — run with sudo")
        return
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        return

    finally:
        scan_stop = datetime.now()
        print_summary()

        if args.save and captured_packets:
            from scapy.all import wrpcap
            wrpcap(args.save, captured_packets)
            print(f"[*] Packets saved to: {args.save}")

        # Auto-generate timestamped CSV filename from scan_start
        csv_filename = scan_start.strftime("%Y_%m_%d_%H_%M_%S") + ".csv"
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        export_csv(os.path.join(OUTPUT_DIR, csv_filename))


if __name__ == "__main__":
    main()