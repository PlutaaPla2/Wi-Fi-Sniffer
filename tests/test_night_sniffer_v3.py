import importlib
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

fake_scapy = types.ModuleType("scapy")
fake_scapy_all = types.ModuleType("scapy.all")
fake_scapy_all.sniff = lambda *args, **kwargs: None
fake_scapy_layers = types.ModuleType("scapy.layers")
fake_dot11 = types.ModuleType("scapy.layers.dot11")
for name in (
    "Dot11", "Dot11ProbeReq", "Dot11Beacon", "Dot11AssoReq",
    "Dot11ReassoReq", "Dot11Auth", "Dot11Deauth", "Dot11Disas",
    "RadioTap", "Dot11Elt", "Dot11EltVendorSpecific",
):
    setattr(fake_dot11, name, type(name, (), {}))

fake_vendor_lookup = types.ModuleType("mac_vendor_lookup")


class FakeMacLookup:
    def update_metadata(self):
        return None

    def lookup(self, mac):
        return "Unknown"


fake_vendor_lookup.MacLookup = FakeMacLookup
sys.modules.setdefault("scapy", fake_scapy)
sys.modules.setdefault("scapy.all", fake_scapy_all)
sys.modules.setdefault("scapy.layers", fake_scapy_layers)
sys.modules.setdefault("scapy.layers.dot11", fake_dot11)
sys.modules.setdefault("mac_vendor_lookup", fake_vendor_lookup)


with patch("mac_vendor_lookup.MacLookup.update_metadata"):
    night_sniffer_v3 = importlib.import_module("night_sniffer_v3")


class NightSnifferV3SessionTests(unittest.TestCase):
    def setUp(self):
        night_sniffer_v3.active_sessions.clear()
        night_sniffer_v3._last_seen.clear()

    def test_groups_strong_non_overlapping_randomized_macs(self):
        with patch.object(night_sniffer_v3.time, "time", return_value=1000.0):
            first = night_sniffer_v3.track_session(
                mac="02:11:22:33:44:55",
                identity="Apple Device (US/Global)",
                power=-50,
                zone="near",
                ssids=["Office"],
                frame_type="PROBE",
                ie_fingerprint="abc123",
                vendor_ies="00:17:f2",
                mac_type="Randomized",
            )

        with patch.object(night_sniffer_v3.time, "time", return_value=1070.0):
            second = night_sniffer_v3.track_session(
                mac="06:11:22:33:44:55",
                identity="Apple Device (US/Global)",
                power=-53,
                zone="near",
                ssids=["Office"],
                frame_type="PROBE",
                ie_fingerprint="abc123",
                vendor_ies="00:17:f2",
                mac_type="Randomized",
            )

        self.assertEqual(first, "New-User-1")
        self.assertEqual(second, "Existing-User-1")
        self.assertEqual(len(night_sniffer_v3.active_sessions), 1)

    def test_does_not_merge_overlapping_randomized_macs(self):
        with patch.object(night_sniffer_v3.time, "time", return_value=1000.0):
            night_sniffer_v3.track_session(
                mac="02:11:22:33:44:55",
                identity="Apple Device (US/Global)",
                power=-50,
                zone="near",
                ssids=["Office"],
                frame_type="PROBE",
                ie_fingerprint="abc123",
                vendor_ies="00:17:f2",
                mac_type="Randomized",
            )

        with patch.object(night_sniffer_v3.time, "time", return_value=1002.0):
            note = night_sniffer_v3.track_session(
                mac="06:11:22:33:44:55",
                identity="Apple Device (US/Global)",
                power=-51,
                zone="near",
                ssids=["Office"],
                frame_type="PROBE",
                ie_fingerprint="abc123",
                vendor_ies="00:17:f2",
                mac_type="Randomized",
            )

        self.assertEqual(note, "New-User-2")
        self.assertEqual(len(night_sniffer_v3.active_sessions), 2)

    def test_real_macs_do_not_merge_by_identity_and_rssi(self):
        with patch.object(night_sniffer_v3.time, "time", return_value=1000.0):
            night_sniffer_v3.track_session(
                mac="00:11:22:33:44:55",
                identity="Unknown Device [OUI:None]",
                power=-50,
                zone="near",
                ssids=["Office"],
                frame_type="PROBE",
                ie_fingerprint="abc123",
                vendor_ies="00:50:f2",
                mac_type="Real",
            )

        with patch.object(night_sniffer_v3.time, "time", return_value=1010.0):
            note = night_sniffer_v3.track_session(
                mac="00:11:22:33:44:66",
                identity="Unknown Device [OUI:None]",
                power=-54,
                zone="near",
                ssids=["Office"],
                frame_type="PROBE",
                ie_fingerprint="abc123",
                vendor_ies="00:50:f2",
                mac_type="Real",
            )

        self.assertEqual(note, "New-User-2")
        self.assertEqual(len(night_sniffer_v3.active_sessions), 2)


class NightSnifferV3IeTests(unittest.TestCase):
    def test_raw_ie_parser_keeps_vendor_ie_after_unknown_ie(self):
        class FakeElt:
            def __bytes__(self):
                return b"\x00\x00\xff\x01\x04\xdd\x03\x00\x50\xf2"

        class FakePkt:
            def getlayer(self, layer):
                if layer is night_sniffer_v3.Dot11Elt:
                    return FakeElt()
                return None

        details = night_sniffer_v3.extract_ie_details(FakePkt())

        self.assertEqual(details["ie_sequence"], "0,255,221")
        self.assertEqual(details["vendor_ies"], "00:50:f2")


if __name__ == "__main__":
    unittest.main()
