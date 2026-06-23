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

## 2026-06-23 Randomized session counter update

- Improved `randomized_session_counter.py` as the first research-based occupancy estimator instead of changing live packet capture.
- The counter now keeps raw evidence visible by reporting raw unique MACs, ignored access points, real client MACs, randomized client MACs, conservative randomized session groups, and an estimated occupant range.
- Added a lower/upper estimate strategy:
  - Lower estimate = real client MACs + conservative randomized session groups.
  - Upper estimate = real client MACs + all randomized client MACs.
- Added low-confidence filtering for weak far randomized clients: one-packet far clients with no probe SSIDs are excluded from the lower estimate but still included in the upper bound.
- Kept the important safety rule that randomized MACs are not merged when their observed session windows overlap.
- Added/updated tests for:
  - Strong non-overlapping randomized sessions grouping into one occupant.
  - Overlapping randomized sessions staying separate.
  - IE fingerprint alone not being enough to merge devices.
  - Access points being ignored for occupancy.
  - Low-confidence far randomized MACs only widening the upper bound.
- Verification run:
  - `python3 -m unittest tests/test_randomized_session_counter.py` passed.
  - `python3 -m py_compile randomized_session_counter.py tests/test_randomized_session_counter.py` passed.
  - `python3 -m unittest discover` is blocked because `scapy` is not installed in the current environment.

## Important next tasks

- Add full timestamps and RSSI statistics to future CSV exports: `first_seen_full`, `last_seen_full`, `rssi_min`, `rssi_max`, and `rssi_avg`.
- Capture channel/band per packet if Scapy exposes it reliably, because research shows timing and channel behavior are stronger than IE fingerprint alone.
- Test the counter with controlled real-room captures: one phone, two similar phones, two same-model phones at the same time, empty room, and nearby hallway traffic.
- Tune the low-confidence filter and grouping threshold using real captures before using the output for AC control.
- After the post-processing estimator is trusted, consider adding rolling occupancy output to `wifi_sniffer.py`.
