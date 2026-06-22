# 📡 Wi-Fi Sniffer

A passive Wi-Fi monitoring tool built with Python and Scapy. It captures IEEE
802.11 management frames from a wireless adapter in monitor mode and produces a
live view, a session summary, and a CSV report of nearby access points and
client devices.

> [!IMPORTANT]
> Use this project only on networks and in locations where you have permission
> to monitor wireless traffic. Captured MAC addresses, probe requests, and
> network names may contain sensitive information.

## ✨ Features

- 📶 Captures 802.11 management frames without connecting to a network
- 🔎 Identifies access points, client devices, SSIDs, and probe requests
- 📊 Reports RSSI signal strength, packet counts, and first/last-seen times
- 📍 Estimates device distance and proximity using configurable environment
  profiles
- 🏷️ Detects randomized MAC addresses and looks up vendors for real OUIs
- 🧬 Creates Information Element (IE) fingerprints to help compare device
  behavior across frames
- 🔄 Optionally hops across 2.4 GHz channels 1–13
- 🛠️ Attempts to restore monitor mode automatically after an adapter drop
- 💾 Automatically exports results to CSV and can optionally save raw packets
  as PCAP

## 🧭 How it works

The sniffer listens for management frames such as beacons, probe requests,
authentication frames, and association frames. It does not decrypt payloads or
join a Wi-Fi network.

For each observed source MAC address, it records:

- whether the device appears to be an access point or client;
- advertised and probed SSIDs;
- RSSI and an approximate distance/proximity zone;
- real or locally administered (randomized) MAC status;
- manufacturer information when a real OUI is available;
- the IE sequence, vendor-specific IE OUIs, frame types, and packet count.

Distance is calculated from RSSI with a log-distance path-loss model. It is a
rough proximity estimate, not a precise location measurement; walls,
interference, antenna characteristics, and transmit power can significantly
affect the result.

## 🧰 Requirements

- Linux (developed for Kali Linux on Raspberry Pi 4)
- Python 3.10 or newer
- A wireless adapter and driver that support monitor mode, such as an Atheros
  AR9271-based adapter
- Root privileges for packet capture and interface configuration
- `iw`, `iwconfig`, and `libpcap`

On Kali/Debian-based systems, install the system packages with:

```bash
sudo apt update
sudo apt install python3 python3-venv libpcap-dev iw wireless-tools
```

## 🚀 Installation

Clone the project and enter its directory:

```bash
git clone <repository-url>
cd Wi-Fi-Sniffer
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the Python dependencies:

```bash
python -m pip install -r requirements.txt
```

When you are finished working in the environment, run `deactivate`.

## ⚙️ Configuration

Before the first scan, open `test_sniffer_v0_7.py` and change `OUTPUT_DIR` to
a writable location for generated CSV reports:

```python
OUTPUT_DIR = "csv_logs"
```

The current value is an absolute path for the original Raspberry Pi setup and
may not exist on another machine. A relative value such as `"csv_logs"` keeps
reports inside the project directory.

## 📡 Enable monitor mode

Find the wireless interface name:

```bash
iw dev
```

Replace `wlan1` below if your adapter uses a different name:

```bash
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
iwconfig wlan1
```

The repository also includes `scripts/wlan1monitor.sh`, which runs these steps
for an interface named `wlan1`:

```bash
bash scripts/wlan1monitor.sh
```

## ▶️ Usage

Run an unlimited capture and press <kbd>Ctrl</kbd>+<kbd>C</kbd> to stop:

```bash
sudo .venv/bin/python test_sniffer_v0_7.py --iface wlan1
```

Common options:

| Option | Description |
| --- | --- |
| `-i`, `--iface` | Monitor-mode interface; default: `wlan1` |
| `-c`, `--count` | Stop after this many packets; `0` means unlimited |
| `-H`, `--hop` | Hop across 2.4 GHz channels 1–13 |
| `-s`, `--save` | Save captured packets to the specified PCAP file |
| `--env` | Distance profile: `open`, `office`, or `indoor` |
| `-h`, `--help` | Show all command-line options |

Examples:

```bash
# Scan 500 packets
sudo .venv/bin/python test_sniffer_v0_7.py -i wlan1 -c 500

# Enable channel hopping and use the office distance profile
sudo .venv/bin/python test_sniffer_v0_7.py -i wlan1 --hop --env office

# Export the automatic CSV report and also retain raw packets
sudo .venv/bin/python test_sniffer_v0_7.py -i wlan1 --save capture.pcap
```

> [!NOTE]
> PCAP packets are retained in memory until the scan stops. Use a packet limit
> for long captures when `--save` is enabled.

## 📄 Output

During a scan, the terminal reports newly discovered devices and newly learned
SSID information. When capture stops, it prints separate summaries for access
points and clients.

A timestamped CSV file is always created in `OUTPUT_DIR`, for example:

```text
2026_06_17_14_32_10.csv
```

The report includes session times, MAC address, device type, SSIDs, RSSI,
estimated distance, proximity zone, randomized-MAC status, vendor, IE
fingerprint, packet count, frame types, and first/last-seen timestamps.

To inspect a report as an aligned terminal table:

```bash
bash scripts/show_csv.sh csv_logs/2026_06_17_14_32_10.csv
```

## 🗂️ Project structure

```text
Wi-Fi-Sniffer/
├── test_sniffer_v0_7.py   # Current sniffer implementation
├── requirements.txt       # Pinned Python dependencies
├── scripts/
│   ├── wlan1monitor.sh    # Enables monitor mode on wlan1
│   └── show_csv.sh        # Displays a CSV report in the terminal
└── archive/               # Earlier development versions
```

## 🧯 Troubleshooting

### Permission denied

Run the sniffer with `sudo` and use the virtual environment's Python executable:

```bash
sudo .venv/bin/python test_sniffer_v0_7.py -i wlan1
```

### Interface not found or no packets captured

Confirm the interface name, state, and monitor-mode type:

```bash
iw dev
ip link show wlan1
iwconfig wlan1
```

Also verify that the adapter supports monitor mode and is not being controlled
by another network-management service.

### CSV output fails

Set `OUTPUT_DIR` in `test_sniffer_v0_7.py` to a directory that exists or can be
created by the user running the sniffer.

### Distance values look inaccurate

Choose the closest environment profile with `--env`, or calibrate
`TX_POWER_DBM` in the script using a reference device measured at one metre.

## ⚖️ Responsible use

This project is intended for education, authorized wireless assessment, and
troubleshooting. Follow applicable privacy and communications laws, minimize
data collection, protect generated CSV/PCAP files, and delete them when they
are no longer needed.
