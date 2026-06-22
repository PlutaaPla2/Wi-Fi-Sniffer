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
"""

import argparse
import csv
import os
from datetime import datetime
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Elt, RadioTap


# ─── Seen devices tracker ────────────────────────────────────────────────────
# Dictionary keyed by MAC address.
# Each entry stores everything we've learned about that device.
seen_devices = {}


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

    # ── Update device record ─────────────────────────────────────────────────
    if src_mac not in seen_devices:
        seen_devices[src_mac] = {
            "mac":         src_mac,
            "first_seen":  datetime.now().strftime("%H:%M:%S"),
            "last_seen":   datetime.now().strftime("%H:%M:%S"),
            "rssi":        rssi,
            "frame_types": set(),
            "probe_ssids": set(),   # Networks this device has looked for
            "beacon_ssid": None,    # If it's an AP, its network name
            "packet_count": 0,
        }
    else:
        seen_devices[src_mac]["last_seen"] = datetime.now().strftime("%H:%M:%S")
        if rssi:
            seen_devices[src_mac]["rssi"] = rssi  # Update with latest signal

    dev = seen_devices[src_mac]
    dev["packet_count"] += 1
    dev["frame_types"].add(frame_name)

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

    # Separate APs (have beacon_ssid) from client devices
    aps      = {m: d for m, d in seen_devices.items() if d["beacon_ssid"]}
    clients  = {m: d for m, d in seen_devices.items() if not d["beacon_ssid"]}

    if aps:
        print(f"\n  ACCESS POINTS ({len(aps)})")
        print(f"  {'MAC':<20} {'SSID':<30} {'Signal':<10} {'Pkts'}")
        print(f"  {'-'*18:<20} {'-'*28:<30} {'-'*8:<10} {'-'*4}")
        for mac, d in sorted(aps.items()):
            rssi_str = f"{d['rssi']} dBm" if d['rssi'] else "N/A"
            print(f"  {mac:<20} {d['beacon_ssid']:<30} {rssi_str:<10} {d['packet_count']}")

    if clients:
        print(f"\n  CLIENT DEVICES ({len(clients)})")
        print(f"  {'MAC':<20} {'Probed SSIDs':<40} {'Signal':<10} {'Pkts'}")
        print(f"  {'-'*18:<20} {'-'*38:<40} {'-'*8:<10} {'-'*4}")
        for mac, d in sorted(clients.items()):
            rssi_str = f"{d['rssi']} dBm" if d['rssi'] else "N/A"
            probes = ", ".join(list(d["probe_ssids"])[:3])  # show up to 3
            if len(d["probe_ssids"]) > 3:
                probes += f" (+{len(d['probe_ssids'])-3} more)"
            probes = probes or "(no probes captured)"
            print(f"  {mac:<20} {probes:<40} {rssi_str:<10} {d['packet_count']}")

    print()


# ─── CSV exporter ─────────────────────────────────────────────────────────────
# Python's built-in csv module writes rows to a file.
# csv.DictWriter lets you write dicts directly using column header names —
# no need to manually keep field order consistent.

# These are the column headers that will appear in row 1 of the CSV.
CSV_FIELDS = [
    "mac",           # hardware address
    "type",          # "Access Point" or "Client Device"
    "ssid",          # AP name (if it's an AP), else blank
    "probe_ssids",   # semicolon-separated list of networks a client looked for
    "rssi_dbm",      # signal strength (negative number; closer to 0 = stronger)
    "packet_count",  # how many frames we captured from this device
    "frame_types",   # semicolon-separated list of management frame types seen
    "first_seen",    # timestamp of first packet
    "last_seen",     # timestamp of most recent packet
]

def export_csv(filepath):
    """Write the seen_devices dict to a CSV file."""

    # How many devices do we have?
    if not seen_devices:
        print("[!] No devices to export.")
        return

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

            # Build the row as a plain dict — keys match CSV_FIELDS exactly
            row = {
                "mac":          mac,
                "type":         "Access Point" if is_ap else "Client Device",
                "ssid":         d["beacon_ssid"] or "",
                # Sets aren't ordered, so sort them before joining
                # We use ";" as separator because SSIDs can contain commas
                "probe_ssids":  "; ".join(sorted(d["probe_ssids"])),
                "rssi_dbm":     d["rssi"] if d["rssi"] is not None else "",
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


# ─── Entry point ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Passive WiFi sniffer — captures 802.11 management frames"
    )
    parser.add_argument(
        "--iface", "-i",
        default="wlan0",
        help="Wireless interface in monitor mode (default: wlan0)"
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
    args = parser.parse_args()

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

    try:
        # BPF filter "wlan" captures all 802.11 frames
        # store=False means don't keep packets in RAM (saves memory on the Pi)
        def handler(pkt):
            handle_packet(pkt)
            if args.save:
                captured_packets.append(pkt)

        sniff(
            iface=args.iface,
            prn=handler,
            count=args.count,
            store=False,          # memory-efficient for long captures
            monitor=True,         # confirm monitor mode
        )

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
