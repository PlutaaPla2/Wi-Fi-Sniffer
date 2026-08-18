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
    "Dot11", "Dot11ProbeReq", "Dot11Beacon", "Dot11AssoReq", "Dot11AssoResp",
    "Dot11ReassoReq", "Dot11ReassoResp", "Dot11Auth", "Dot11Deauth", "Dot11Disas",
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
                seq=100,
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
                seq=104,
            )

        self.assertEqual(first, "New-User-1")
        self.assertEqual(second, "Existing-User-1")
        self.assertEqual(len(night_sniffer_v3.active_sessions), 1)
        self.assertEqual(night_sniffer_v3.active_sessions[1].last_seq, 104)

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
                seq=200,
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
                seq=204,
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
                seq=300,
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
                seq=304,
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


class NightSnifferV3PacketHandlerTests(unittest.TestCase):
    def test_sequence_number_reaches_session_and_csv_seq_column(self):
        class FakePacket:
            dot11 = types.SimpleNamespace(SC=(321 << 4) | 7)

            def haslayer(self, layer):
                return layer is night_sniffer_v3.Dot11

            def __getitem__(self, layer):
                return self.dot11

        ie_details = {
            "ie_sequence": "",
            "ie_fingerprint": "",
            "vendor_ies": "",
            "capabilities": "",
        }
        with patch.object(
            night_sniffer_v3,
            "classify_frame",
            return_value=("PROBE", "02:11:22:33:44:55"),
        ), patch.object(
            night_sniffer_v3, "extract_ssid", return_value="(Wildcard)"
        ), patch.object(
            night_sniffer_v3, "get_correlation_identity", return_value="Unknown"
        ), patch.object(
            night_sniffer_v3, "extract_ie_details", return_value=ie_details
        ), patch.object(
            night_sniffer_v3, "track_session", return_value="New-User-1"
        ) as track_session, patch.object(
            night_sniffer_v3, "_append_csv_row"
        ) as append_row, patch.object(
            night_sniffer_v3, "dump_ie_details"
        ), patch("builtins.print"):
            night_sniffer_v3.handle_packet(FakePacket())

        # seq is passed to track_session as the 10th positional arg (index 9);
        # Phase 1 appends current_ap/listen_interval/security_tier after it.
        self.assertEqual(track_session.call_args.args[9], 321)
        # In the CSV row seq sits at the Seq_Num column, before the seven
        # Phase 1 frame-body columns, i.e. 8th from the end.
        self.assertEqual(append_row.call_args.args[0][-8], 321)
        self.assertEqual(
            night_sniffer_v3.CSV_FIELDS[-8], "Seq_Num"
        )

    def test_management_frame_without_an_address_is_logged_not_dropped(self):
        """A frame dumpcap would have kept must reach the CSV even unattributable."""

        class FakePacket:
            dot11 = types.SimpleNamespace(SC=(1 << 4) | 0)

            def haslayer(self, layer):
                return layer is night_sniffer_v3.Dot11

            def __getitem__(self, layer):
                return self.dot11

        ie_details = {
            "ie_sequence": "",
            "ie_fingerprint": "",
            "vendor_ies": "",
            "capabilities": "",
        }
        with patch.object(
            night_sniffer_v3, "classify_frame", return_value=("ACTION", "")
        ), patch.object(
            night_sniffer_v3, "extract_ssid", return_value="(Wildcard)"
        ), patch.object(
            night_sniffer_v3, "get_correlation_identity", return_value="Unknown"
        ), patch.object(
            night_sniffer_v3, "extract_ie_details", return_value=ie_details
        ), patch.object(
            night_sniffer_v3, "track_session"
        ) as track_session, patch.object(
            night_sniffer_v3, "_append_csv_row"
        ) as append_row, patch.object(
            night_sniffer_v3, "dump_ie_details"
        ), patch("builtins.print"):
            night_sniffer_v3.handle_packet(FakePacket())

        append_row.assert_called_once()
        row = append_row.call_args.args[0]
        self.assertEqual(row[night_sniffer_v3.CSV_FIELDS.index("Pkt_Type")], "ACTION")
        self.assertEqual(row[night_sniffer_v3.CSV_FIELDS.index("MAC_Address")], "")
        # Logged, but never fed to the device-count model: an address-less frame
        # cannot be attributed to a device.
        self.assertIn(
            "No-Address", row[night_sniffer_v3.CSV_FIELDS.index("Session_Note")]
        )
        track_session.assert_not_called()


class _FakeDot11:
    """Stand-in for a dissected Dot11 layer, carrying only what the classifier reads."""

    def __init__(self, type_=0, subtype=0, addr1=None, addr2=None, addr3=None):
        self.type = type_
        self.subtype = subtype
        self.addr1 = addr1
        self.addr2 = addr2
        self.addr3 = addr3


class _FakePkt:
    def __init__(self, dot11):
        self._dot11 = dot11

    def getlayer(self, layer):
        if layer is night_sniffer_v3.Dot11:
            return self._dot11
        return None


class NightSnifferV3ClassifyFrameTests(unittest.TestCase):
    """Every management subtype must be recognised, and labelled as itself."""

    @staticmethod
    def _classify(**kwargs):
        return night_sniffer_v3.classify_frame(_FakePkt(_FakeDot11(**kwargs)))

    def test_every_management_subtype_is_recognised(self):
        # The whole 4-bit space, so a frame can never fall through unclassified.
        for subtype in range(16):
            with self.subTest(subtype=subtype):
                label, mac = self._classify(
                    type_=0, subtype=subtype, addr2="aa:bb:cc:dd:ee:ff"
                )
                self.assertEqual(label, night_sniffer_v3.MGMT_SUBTYPE_LABELS[subtype])
                self.assertEqual(mac, "AA:BB:CC:DD:EE:FF")

    def test_reassociation_response_is_not_labelled_as_association_response(self):
        # Regression test for the Dot11ReassoResp/Dot11AssoResp subclass trap:
        # with an FCS present, haslayer(Dot11AssoResp) matched subtype 3 too.
        label, _mac = self._classify(type_=0, subtype=3, addr2="aa:bb:cc:dd:ee:ff")
        self.assertEqual(label, "REASSOC_RESP")

    def test_historical_labels_are_preserved(self):
        # Renaming any of these silently breaks comparison against CSVs written
        # before all sixteen subtypes were captured.
        expected = {
            0: "ASSOC_REQ", 1: "ASSOC_RESP", 2: "REASSOC_REQ", 3: "REASSOC_RESP",
            4: "PROBE", 8: "BEACON", 10: "DISASSOC", 11: "AUTH", 12: "DEAUTH",
        }
        for subtype, label in expected.items():
            with self.subTest(subtype=subtype):
                self.assertEqual(night_sniffer_v3.MGMT_SUBTYPE_LABELS[subtype], label)

    def test_control_and_data_frames_are_skipped(self):
        for frame_type in (1, 2, 3):
            with self.subTest(type=frame_type):
                self.assertEqual(
                    self._classify(type_=frame_type, subtype=8,
                                   addr2="aa:bb:cc:dd:ee:ff"),
                    (None, ""),
                )

    def test_address_falls_back_through_addr3_then_addr1(self):
        # addr2 unreadable: the frame is still attributable and must not be lost.
        _label, mac = self._classify(type_=0, subtype=8, addr2=None,
                                     addr3="11:22:33:44:55:66")
        self.assertEqual(mac, "11:22:33:44:55:66".upper())

        _label, mac = self._classify(type_=0, subtype=8, addr2=None, addr3=None,
                                     addr1="99:88:77:66:55:44")
        self.assertEqual(mac, "99:88:77:66:55:44".upper())

    def test_frame_with_no_readable_address_is_still_classified(self):
        label, mac = self._classify(type_=0, subtype=13)
        self.assertEqual(label, "ACTION")
        self.assertEqual(mac, "")

    def test_missing_or_malformed_dot11_layer_returns_no_frame(self):
        class NoDot11:
            def getlayer(self, layer):
                return None

        self.assertEqual(night_sniffer_v3.classify_frame(NoDot11()), (None, ""))
        # A control field that will not coerce must not raise: Scapy closes the
        # capture socket on any exception escaping the packet callback.
        self.assertEqual(self._classify(type_=None, subtype=8), (None, ""))
        self.assertEqual(self._classify(type_=0, subtype="junk"), (None, ""))


class NightSnifferV3ReplayClockTests(unittest.TestCase):
    """The --pcap replay path must timestamp frames from the capture, not the run.

    Without this the whole point of replay is lost: every row would carry the
    replay's wall clock, Interval_sec would measure parsing speed rather than
    the gap between frames, and SESSION_TIMEOUT would never fire because a
    night's capture would collapse into a few seconds.
    """

    def setUp(self):
        self._replay_mode = night_sniffer_v3.REPLAY_MODE
        self._frame_time = night_sniffer_v3._CURRENT_FRAME_TIME

    def tearDown(self):
        night_sniffer_v3.REPLAY_MODE = self._replay_mode
        night_sniffer_v3._CURRENT_FRAME_TIME = self._frame_time

    @staticmethod
    def _packet(ts):
        """Minimal stand-in for a scapy packet carrying a capture timestamp."""
        return types.SimpleNamespace(time=ts)

    def test_live_mode_uses_wall_clock_and_leaves_now_on_wall_clock(self):
        night_sniffer_v3.REPLAY_MODE = False
        with patch.object(night_sniffer_v3.time, "time", return_value=5000.0):
            # Even though the packet claims a much older capture time, live
            # capture must ignore it — the frame arrived now.
            self.assertEqual(night_sniffer_v3._frame_time(self._packet(10.0)), 5000.0)
            self.assertIsNone(night_sniffer_v3._CURRENT_FRAME_TIME)
            self.assertEqual(night_sniffer_v3._now(), 5000.0)

    def test_replay_mode_uses_capture_time_for_frame_and_session_clock(self):
        night_sniffer_v3.REPLAY_MODE = True
        with patch.object(night_sniffer_v3.time, "time", return_value=5000.0):
            self.assertEqual(night_sniffer_v3._frame_time(self._packet(1234.5)), 1234.5)
            self.assertEqual(night_sniffer_v3._now(), 1234.5)

    def test_replay_mode_converts_decimal_capture_times_to_float(self):
        # Scapy hands back an EDecimal for pcap timestamps. Left unconverted it
        # raises as soon as it meets a float in the session arithmetic.
        from decimal import Decimal

        night_sniffer_v3.REPLAY_MODE = True
        result = night_sniffer_v3._frame_time(self._packet(Decimal("1234.5")))
        self.assertIsInstance(result, float)
        self.assertEqual(result, 1234.5)

    def test_replay_mode_falls_back_when_a_frame_carries_no_time(self):
        night_sniffer_v3.REPLAY_MODE = True
        with patch.object(night_sniffer_v3.time, "time", return_value=5000.0):
            # Must not raise inside the packet callback: scapy closes the
            # capture socket on any exception escaping prn.
            self.assertEqual(night_sniffer_v3._frame_time(types.SimpleNamespace()), 5000.0)

    def test_track_session_runs_on_the_frame_clock_during_replay(self):
        night_sniffer_v3.active_sessions.clear()
        night_sniffer_v3._last_seen.clear()
        night_sniffer_v3.REPLAY_MODE = True
        night_sniffer_v3._CURRENT_FRAME_TIME = 9000.0
        with patch.object(night_sniffer_v3.time, "time", return_value=5000.0):
            night_sniffer_v3.track_session(
                mac="02:11:22:33:44:55",
                identity="Apple Device (US/Global)",
                power=-50,
                zone="near",
                ssids=["Office"],
                frame_type="PROBE",
                ie_fingerprint="fp2:abc",
                vendor_ies="00:17:f2",
                mac_type="Randomized",
            )
        session = night_sniffer_v3.active_sessions[1]
        self.assertEqual(session.first_ts, 9000.0)
        self.assertEqual(session.last_ts, 9000.0)


class NightSnifferV3OutputDirTests(unittest.TestCase):
    """--out-dir must move all three reports, so a replay cannot clobber a capture."""

    def setUp(self):
        self._paths = (
            night_sniffer_v3.LOG_FILE,
            night_sniffer_v3.IE_DETAILS_FILE,
            night_sniffer_v3.SUMMARY_DIR,
        )

    def tearDown(self):
        (night_sniffer_v3.LOG_FILE,
         night_sniffer_v3.IE_DETAILS_FILE,
         night_sniffer_v3.SUMMARY_DIR) = self._paths

    def test_redirects_all_three_outputs_and_keeps_basenames(self):
        import os
        import tempfile

        original_log = os.path.basename(night_sniffer_v3.LOG_FILE)
        original_ie = os.path.basename(night_sniffer_v3.IE_DETAILS_FILE)
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "made", "on", "demand")
            night_sniffer_v3.apply_output_dir(target)
            self.assertTrue(os.path.isdir(target))
            self.assertEqual(night_sniffer_v3.LOG_FILE,
                             os.path.join(target, original_log))
            self.assertEqual(night_sniffer_v3.IE_DETAILS_FILE,
                             os.path.join(target, original_ie))
            self.assertEqual(night_sniffer_v3.SUMMARY_DIR, target)


if __name__ == "__main__":
    unittest.main()
