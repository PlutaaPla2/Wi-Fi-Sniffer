# Task Log

## Main Objective

Detect Wi-Fi probe and client activity to estimate room occupancy for AC control.

## Research / Next Tasks

- Investigate IE fingerprint grouping for randomized client MACs. Current capture stores `ie_fingerprint`, `ie_sequence`, and `vendor_ies` per MAC, but counting still keys devices by MAC only.
- Avoid merging devices by IE fingerprint alone. Many phones with the same model/OS can share the same IE sequence, so this should be used as a weak grouping signal, not a unique identity.
- Consider a session-grouping score for randomized clients using IE fingerprint, vendor-specific IE OUIs, RSSI/zone similarity, time overlap, frame types, and probe SSID behavior.
- Add tests before changing counting logic to confirm the same MAC/session is not double-counted and multiple similar devices are not collapsed into one occupant.

## 2026-06-23 Randomized MAC counting notes

- Added a separate post-processing idea instead of changing `wifi_sniffer.py`: read the exported CSV, import `config.CSV_FIELDS`, and estimate occupants from the completed scan.
- This means the current workflow is two steps: run the sniffer to capture/export CSV, then run the randomized-session counter on that CSV. It is safer for review because it does not risk breaking live packet capture.
- Best conservative method from current CSV data: group randomized client MACs only when sessions do not overlap and several weak signals agree, such as IE fingerprint, vendor-specific IE OUIs, RSSI/zone similarity, frame types, probe SSIDs, and time gap.
- Important limitation: a physical person/device cannot be identified perfectly from passive probe/client metadata alone. Randomized MACs are designed to prevent stable tracking, and many similar devices can share the same IE fingerprint.
- Better future options to discuss:
  - Add rolling occupancy output inside `wifi_sniffer.py` after the post-processing logic is trusted.
  - Capture channel number and band per packet, because same RSSI on different channels is less comparable.
  - Track session windows continuously instead of only final CSV rows, so MAC rotations can be linked more accurately by timing.
  - Use multiple sniffers in different room positions and compare RSSI patterns; this is the strongest non-invasive improvement for room occupancy.
  - Calibrate RSSI thresholds with known devices in the actual room before using counts for AC control.
  - Keep conservative lower/upper estimates instead of one exact number, for example "3-5 likely occupants".
