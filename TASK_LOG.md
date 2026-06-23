# Task Log

## Main Objective

Detect Wi-Fi probe and client activity to estimate room occupancy for AC control.

## Research / Next Tasks

- Investigate IE fingerprint grouping for randomized client MACs. Current capture stores `ie_fingerprint`, `ie_sequence`, and `vendor_ies` per MAC, but counting still keys devices by MAC only.
- Avoid merging devices by IE fingerprint alone. Many phones with the same model/OS can share the same IE sequence, so this should be used as a weak grouping signal, not a unique identity.
- Consider a session-grouping score for randomized clients using IE fingerprint, vendor-specific IE OUIs, RSSI/zone similarity, time overlap, frame types, and probe SSID behavior.
- Add tests before changing counting logic to confirm the same MAC/session is not double-counted and multiple similar devices are not collapsed into one occupant.
