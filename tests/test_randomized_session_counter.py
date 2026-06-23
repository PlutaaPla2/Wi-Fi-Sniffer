import csv
import tempfile
import unittest
from pathlib import Path

from config import CSV_FIELDS
from randomized_session_counter import estimate_occupancy, load_observations


def base_row(**overrides):
    row = {field: "" for field in CSV_FIELDS}
    row.update(
        {
            "scan_start": "2026-06-23 10:00:00",
            "scan_stop": "2026-06-23 10:10:00",
            "scan_duration": "0h 10m 00s",
            "mac": "00:11:22:33:44:55",
            "type": "Client Device",
            "rssi_dbm": "-50",
            "distance_m": "1.0",
            "zone": "immediate  (<2 m)",
            "mac_randomized": "False",
            "ie_fingerprint": "abc12345",
            "ie_sequence": "SSID-Rates-Vendor",
            "vendor_ies": "00:50:f2",
            "packet_count": "3",
            "frame_types": "Probe Request",
            "first_seen": "10:00:00",
            "last_seen": "10:00:30",
        }
    )
    row.update(overrides)
    return row


def write_csv(rows):
    tmp = tempfile.NamedTemporaryFile("w", newline="", suffix=".csv", delete=False)
    with tmp:
        writer = csv.DictWriter(tmp, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return Path(tmp.name)


class RandomizedSessionCounterTests(unittest.TestCase):
    def test_groups_strong_non_overlapping_randomized_sessions(self):
        csv_path = write_csv(
            [
                base_row(
                    mac="02:11:22:33:44:55",
                    mac_randomized="True",
                    first_seen="10:00:00",
                    last_seen="10:00:30",
                ),
                base_row(
                    mac="06:11:22:33:44:55",
                    mac_randomized="True",
                    rssi_dbm="-53",
                    first_seen="10:01:20",
                    last_seen="10:01:50",
                ),
            ]
        )
        self.addCleanup(csv_path.unlink)

        result = estimate_occupancy(load_observations(csv_path))

        self.assertEqual(result["real_client_count"], 0)
        self.assertEqual(result["randomized_session_count"], 1)
        self.assertEqual(result["estimated_occupants"], 1)

    def test_does_not_merge_overlapping_randomized_sessions(self):
        csv_path = write_csv(
            [
                base_row(
                    mac="02:11:22:33:44:55",
                    mac_randomized="True",
                    first_seen="10:00:00",
                    last_seen="10:02:00",
                ),
                base_row(
                    mac="06:11:22:33:44:55",
                    mac_randomized="True",
                    first_seen="10:01:00",
                    last_seen="10:03:00",
                ),
            ]
        )
        self.addCleanup(csv_path.unlink)

        result = estimate_occupancy(load_observations(csv_path))

        self.assertEqual(result["randomized_session_count"], 2)
        self.assertEqual(result["estimated_occupants"], 2)

    def test_does_not_merge_ie_fingerprint_alone(self):
        csv_path = write_csv(
            [
                base_row(
                    mac="02:11:22:33:44:55",
                    mac_randomized="True",
                    vendor_ies="",
                    frame_types="Probe Request",
                    probe_ssids="",
                    rssi_dbm="-42",
                    zone="immediate  (<2 m)",
                    first_seen="10:00:00",
                    last_seen="10:00:30",
                ),
                base_row(
                    mac="06:11:22:33:44:55",
                    mac_randomized="True",
                    vendor_ies="",
                    frame_types="Authentication",
                    probe_ssids="",
                    rssi_dbm="-78",
                    zone="far        (>20 m)",
                    first_seen="10:05:00",
                    last_seen="10:05:30",
                ),
            ]
        )
        self.addCleanup(csv_path.unlink)

        result = estimate_occupancy(load_observations(csv_path))

        self.assertEqual(result["randomized_session_count"], 2)
        self.assertEqual(result["estimated_occupants"], 2)

    def test_counts_real_clients_separately_from_randomized_groups(self):
        csv_path = write_csv(
            [
                base_row(mac="00:11:22:33:44:55", mac_randomized="False"),
                base_row(
                    mac="02:11:22:33:44:55",
                    mac_randomized="True",
                    first_seen="10:02:00",
                    last_seen="10:02:30",
                ),
            ]
        )
        self.addCleanup(csv_path.unlink)

        result = estimate_occupancy(load_observations(csv_path))

        self.assertEqual(result["real_client_count"], 1)
        self.assertEqual(result["randomized_session_count"], 1)
        self.assertEqual(result["estimated_occupants"], 2)


if __name__ == "__main__":
    unittest.main()
