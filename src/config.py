"""
config.py — All user-editable settings for wifi_sniffer.py
-----------------------------------------------------------
This file contains ONLY configuration — no logic, no functions.
Edit values here freely without touching the main script.

Sections:
  1. Output
  2. Adapter recovery
  3. Distance estimation
  4. OUI / vendor lookup
  5. IE element names
  6. 802.11 frame type names
  7. CSV column layout
"""

# ═══════════════════════════════════════════════════════════════════
# 1. OUTPUT
# ═══════════════════════════════════════════════════════════════════

# Directory where CSV result files are saved.
# The directory is created automatically if it doesn't exist.
# Filename is auto-generated from scan start time: YYYY_MM_DD_HH_MM_SS.csv
#
# Examples:
#   OUTPUT_DIR = "/home/pi/wifi_scans"     # absolute path (recommended)
#   OUTPUT_DIR = "scans"                   # relative to wherever you run the script
OUTPUT_DIR = "../csv_logs"         # ← edit this


# ═══════════════════════════════════════════════════════════════════
# 2. ADAPTER RECOVERY
# ═══════════════════════════════════════════════════════════════════

# How many times to attempt reconnecting if the adapter drops out of
# monitor mode mid-capture before giving up entirely.
MAX_RETRIES = 10

# Seconds to wait between each reconnect attempt.
# Give the kernel/driver time to settle after the interface is reset.
RETRY_DELAY = 3    # seconds


# ═══════════════════════════════════════════════════════════════════
# 3. DISTANCE ESTIMATION  (Log-Distance Path Loss model)
# ═══════════════════════════════════════════════════════════════════
#
# Formula:  distance = 10 ^ ( (TX_POWER_DBM - rssi) / (10 * N) )
#
# TX_POWER_DBM : Expected RSSI at exactly 1 metre from the device (dBm).
#   -59 dBm is the widely-used default for consumer WiFi.
#   To calibrate: place a known device exactly 1 m from the Pi, read the
#   RSSI it reports, and set that value here for more accurate results.
TX_POWER_DBM = -59

# Environment presets — select at runtime with --env open/office/indoor.
# Each entry: "name": (N, "description")
#   N = path loss exponent. Higher N = signal drops faster with distance.
ENVIRONMENTS = {
    "open":   (2.0, "open air / outdoors"),
    "office": (2.7, "typical office with some walls"),   # default
    "indoor": (3.5, "dense indoor, many walls/obstacles"),
}

# Proximity zone thresholds (metres).
# Tune these to your environment if the labels feel off.
ZONE_IMMEDIATE_M = 2     # <= this -> "immediate"
ZONE_NEAR_M      = 7     # <= this -> "near"
ZONE_MID_M       = 20    # <= this -> "mid"
                          # >  this -> "far"


# ═══════════════════════════════════════════════════════════════════
# 4. OUI / VENDOR LOOKUP
# ═══════════════════════════════════════════════════════════════════
#
# A hand-picked table of common consumer device brands.
# Checked BEFORE Scapy's full IEEE database so names stay clean
# and readable (Scapy's names can be overly formal/legal).
#
# Keys MUST be lowercase "xx:xx:xx" format.
# Add your own entries in the same format.
# Cross-check against https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries
# before adding — see the Tesla/Apple incident for why this matters.
KNOWN_OUIS: dict[str, str] = {
    "00:17:f2": "Apple, Inc.",
    "00:00:f0": "Samsung Electronics",
    "00:e0:fc": "Huawei Technologies",
    "ac:f7:f3": "Xiaomi Communications",
    #"f8:a4:5f": "Oppo Mobile",                  # Xiaomi
    # "d4:f5:13": "Vivo Mobile,                 # Texas Instruments
    "00:1a:11": "Google (Pixel/Nest)",
    "00:16:ea": "Intel Corp (Laptop)",
    "00:50:f2": "Microsoft (Surface/WPS)",
    "00:10:18": "Broadcom",
    # "00:23:45": "Foxconn",                    # SONY on https://standards-oui.ieee.org/
    # "4c:ed:de": "AzureWave (IoT/Laptop)",     # ASKEY
    "50:c7:bf": "TP-Link",
    "00:00:0c": "Cisco Systems",
    "00:0f:3d": "D-Link",
    "00:bb:3a": "Amazon (Echo/Kindle)",
    "24:b2:de": "Espressif (IoT/SmartHome)",
    "84:e1:ba": "Tuya Smart (IoT)",
    "00:04:1f": "Sony Interactive (PS)",
    "00:1f:32": "Nintendo (Switch)",
}


# ═══════════════════════════════════════════════════════════════════
# 5. IE ELEMENT NAMES
# ═══════════════════════════════════════════════════════════════════
#
# Maps numeric IE IDs to short human-readable labels used in the
# ie_sequence CSV column and terminal output.
# IDs not listed here appear as "ID<n>" (e.g. "ID255").
# Reference: IEEE 802.11-2020, Table 9-92
IE_NAMES: dict[int, str] = {
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


# ═══════════════════════════════════════════════════════════════════
# 6. 802.11 FRAME TYPE NAMES
# ═══════════════════════════════════════════════════════════════════
#
# Maps 802.11 management frame subtype numbers to readable names.
# These are the subtypes most relevant to passive sniffing.
# Reference: IEEE 802.11-2020, Table 9-1
FRAME_TYPES: dict[int, str] = {
    0:  "Association Request",
    1:  "Association Response",
    2:  "Reassociation Request",
    4:  "Probe Request",      # client scanning for known networks → reveals PNL
    5:  "Probe Response",
    8:  "Beacon",             # AP broadcasting its presence → reveals SSID
    10: "Disassociation",
    11: "Authentication",
    12: "Deauthentication",
}


# ═══════════════════════════════════════════════════════════════════
# 7. CSV COLUMN LAYOUT
# ═══════════════════════════════════════════════════════════════════
#
# Defines which columns appear in the output CSV, and their order.
# Reorder or remove entries here if you want a slimmer CSV.
# Do NOT rename entries without also updating export_csv() in wifi_sniffer.py.
CSV_FIELDS: list[str] = [
    "scan_start",       # when the capture session began
    "scan_stop",        # when the capture session ended
    "scan_duration",    # total duration e.g. "0h 22m 34s"
    "mac",              # source MAC address
    "type",             # "Access Point" or "Client Device"
    "ssid",             # AP's network name (APs only)
    "probe_ssids",      # semicolon-separated preferred network list (clients)
    "rssi_dbm",         # signal strength in dBm (negative; closer to 0 = stronger)
    "distance_m",       # estimated distance in metres
    "zone",             # proximity label: immediate / near / mid / far
    "mac_randomized",   # True if LA bit set (OS-generated MAC)
    "vendor",           # manufacturer name (only if MAC is not randomized)
    "ie_fingerprint",   # 8-char MD5 hash of the IE ID sequence
    "ie_sequence",      # human-readable IE sequence e.g. "SSID-Rates-HT-Cap-Vendor"
    "vendor_ies",       # semicolon-separated OUIs from Vendor Specific (ID 221) IEs
    "packet_count",     # total frames captured from this device
    "frame_types",      # semicolon-separated management frame types seen
    "first_seen",       # timestamp of first packet from this device
    "last_seen",        # timestamp of most recent packet from this device
]
