Kali Linux (Raspberry Pi 4)

# Wi-Fi Sniffer Project

## Requirements

* Python 3.10+ (or your project's version)
* Linux (tested on Kali Linux / Raspberry Pi)
* Wireless adapter with monitor mode support (e.g. Atheros AR9271)
* `libpcap` installed
* Root privileges to capture packets

## Setup

Create a virtual environment: (ONE TIME)

```bash
python3 -m venv .venv
source .venv/bin/activate
```
Later use:
$ source .venv/bin/activate

and
$ deactivate

to Enable and Disable Python .venv

Install dependencies:

```bash
pip install -r requirements.txt
```

## Running

Ensure the Wi-Fi adapter is in monitor mode (example: `wlan1`):

```bash
sudo python3 filename.py
```

## Notes

* `.venv` is intentionally excluded from this project archive.
* Recreate the virtual environment using `requirements.txt`.
* The monitor-mode interface name may differ (`wlan1`, `wlan1mon`, etc.). Check with:

```bash
iw dev
```

