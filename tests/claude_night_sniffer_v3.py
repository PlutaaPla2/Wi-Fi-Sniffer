"""
Characterization tests for src/night_sniffer_v3.py.

Complements tests/test_night_sniffer_v3.py (session merging + raw IE
walk) by covering the pure helper functions, frame classification,
identity/IE decoding, CSV report writing, and interface recovery.

scapy and mac_vendor_lookup are stubbed out (same approach as the
existing test file) so this runs without either dependency installed
and without touching the network. Not wired into the CI workflow yet —
run directly with:
    PYTHONPATH=src python -m unittest tests/claude_night_sniffer_v3.py
"""

import csv
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
    "Dot11", "Dot11ProbeReq", "Dot11Beacon",
    "Dot11AssoReq", "Dot11AssoResp", "Dot11ReassoReq", "Dot11ReassoResp",
    "Dot11Auth", "Dot11Deauth", "Dot11Disas", "RadioTap",
    "Dot11Elt", "Dot11EltVendorSpecific",
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

ns = importlib.import_module("night_sniffer_v3")


# ---------------------------------------------------------------------------
# Small fakes shared across test classes
# ---------------------------------------------------------------------------

class FakePacket:
    """Minimal Dot11-like packet: layer membership + arbitrary attrs."""

    def __init__(self, layers=(), **attrs):
        self._layers = set(layers)
        for key, value in attrs.items():
            setattr(self, key, value)

    def haslayer(self, layer):
        return layer in self._layers


class VendorNode:
    """One link in a fake Dot11EltVendorSpecific chain."""

    def __init__(self, oui, next_node=None):
        self.oui = oui
        self._next = next_node

    @property
    def payload(self):
        return self

    def getlayer(self, layer):
        return self._next


class IdentityPacket:
    """Fake packet for get_correlation_identity()."""

    def __init__(self, addr2=None, addr3=None, has_elt=True,
                 vendor_chain=None, ch_list=None):
        self.addr2 = addr2
        self.addr3 = addr3
        self._has_elt = has_elt
        self._vendor_chain = vendor_chain
        self._ch_list = ch_list

    def haslayer(self, layer):
        return self._has_elt

    def getlayer(self, layer, ID=None):
        if layer is ns.Dot11EltVendorSpecific:
            return self._vendor_chain
        if layer is ns.Dot11Elt and ID == 50:
            if self._ch_list is None:
                return None
            tag = types.SimpleNamespace(info=self._ch_list)
            return tag
        return None


class SsidPacket:
    """Fake packet for extract_ssid()."""

    def __init__(self, info=None, elt_info=None):
        if info is not None:
            self.info = info
        self._elt_info = elt_info

    def getlayer(self, layer, ID=None):
        if self._elt_info is None:
            return None
        return types.SimpleNamespace(info=self._elt_info)


class RawIePacket:
    """Fake packet whose Dot11Elt layer serializes to raw TLV bytes."""

    def __init__(self, raw_bytes: bytes):
        self._raw_bytes = raw_bytes

    def getlayer(self, layer):
        if layer is ns.Dot11Elt:
            return self
        return None

    def __bytes__(self):
        return self._raw_bytes


# ---------------------------------------------------------------------------
# Pure numeric / string helpers
# ---------------------------------------------------------------------------

class DistanceAndZoneTests(unittest.TestCase):
    def test_zero_rssi_is_zero_distance(self):
        self.assertEqual(ns.calculate_distance(0), 0.0)

    def test_reference_rssi_is_one_metre(self):
        self.assertEqual(ns.calculate_distance(ns.P0), 1.0)

    def test_weaker_signal_is_further_away(self):
        near = ns.calculate_distance(-40)
        far = ns.calculate_distance(-70)
        self.assertLess(near, far)

    def test_proximity_zone_buckets(self):
        self.assertEqual(ns.proximity_zone(0), "unknown")
        self.assertEqual(ns.proximity_zone(2), "immediate")
        self.assertEqual(ns.proximity_zone(7), "near")
        self.assertEqual(ns.proximity_zone(20), "mid")
        self.assertEqual(ns.proximity_zone(20.01), "far")


class MacHelperTests(unittest.TestCase):
    def test_locally_administered_bit_means_randomized(self):
        self.assertEqual(ns.check_mac_type("02:11:22:33:44:55"), "Randomized")

    def test_burned_in_mac_is_real(self):
        self.assertEqual(ns.check_mac_type("00:11:22:33:44:55"), "Real")

    def test_malformed_mac_is_unknown(self):
        self.assertEqual(ns.check_mac_type("zz:11:22:33:44:55"), "Unknown")

    def test_oui_from_mac_extracts_first_three_bytes(self):
        self.assertEqual(ns.oui_from_mac("AA:BB:CC:DD:EE:FF"), "aa:bb:cc")

    def test_lookup_oui_known_vendor(self):
        self.assertEqual(ns.lookup_oui("00:17:f2"), "Apple, Inc.")

    def test_lookup_oui_unknown_vendor_returns_placeholder(self):
        self.assertEqual(ns.lookup_oui("aa:bb:cc"), "Unknown(aa:bb:cc)")

    def test_lookup_oui_is_case_insensitive(self):
        self.assertEqual(ns.lookup_oui("00:17:F2"), "Apple, Inc.")

    def test_oui_int_to_str_round_trips_lookup_oui(self):
        self.assertEqual(ns.oui_int_to_str(0x0017F2), "00:17:f2")

    def test_safe_upper_mac_normalizes_case(self):
        self.assertEqual(ns._safe_upper_mac("aa:bb:cc:dd:ee:ff"), "AA:BB:CC:DD:EE:FF")

    def test_safe_upper_mac_handles_missing_value(self):
        self.assertEqual(ns._safe_upper_mac(None), "")
        self.assertEqual(ns._safe_upper_mac(""), "")


class VendorLookupTests(unittest.TestCase):
    def test_randomized_mac_skips_vendor_lookup(self):
        self.assertEqual(
            ns.get_vendor("02:11:22:33:44:55", "Randomized"),
            "Randomized/Unknown",
        )

    def test_real_mac_uses_vendor_lookup_library(self):
        with patch.object(ns._vendor_lookup, "lookup", return_value="Acme Corp"):
            self.assertEqual(ns.get_vendor("00:11:22:33:44:55", "Real"), "Acme Corp")

    def test_vendor_lookup_failure_is_swallowed(self):
        with patch.object(ns._vendor_lookup, "lookup", side_effect=KeyError("nope")):
            self.assertEqual(ns.get_vendor("00:11:22:33:44:55", "Real"), "Unknown")


class VendorFromIeOuisTests(unittest.TestCase):
    def test_prefers_curated_known_oui_name(self):
        self.assertEqual(ns.vendor_from_ie_ouis("00:17:f2"), "Apple, Inc.")

    def test_empty_tag221_is_unknown(self):
        self.assertEqual(ns.vendor_from_ie_ouis(""), "Unknown")

    def test_falls_back_to_full_vendor_database(self):
        with patch.object(ns._vendor_lookup, "lookup", return_value="Realtek Semiconductor"):
            self.assertEqual(ns.vendor_from_ie_ouis("52:54:00"), "Realtek Semiconductor")

    def test_full_database_lookup_gets_padded_to_a_mac(self):
        with patch.object(ns._vendor_lookup, "lookup", return_value="Realtek") as mock_lookup:
            ns.vendor_from_ie_ouis("52:54:00")
        mock_lookup.assert_called_once_with("52:54:00:00:00:00")

    def test_unresolved_oui_returns_raw_list(self):
        with patch.object(ns._vendor_lookup, "lookup", side_effect=KeyError("nope")):
            self.assertEqual(ns.vendor_from_ie_ouis("aa:bb:cc"), "Unknown(aa:bb:cc)")

    def test_first_recognized_oui_wins_over_unknown(self):
        self.assertEqual(ns.vendor_from_ie_ouis("aa:bb:cc;00:17:f2"), "Apple, Inc.")


class FrequencyHelperTests(unittest.TestCase):
    def test_2ghz_channel_and_band(self):
        self.assertEqual(ns._freq_to_channel(2412), 1)
        self.assertEqual(ns._freq_to_channel(2437), 6)
        self.assertEqual(ns._freq_to_channel(2472), 13)
        self.assertEqual(ns._freq_to_band(2412), "2.4GHz")

    def test_5ghz_channel_and_band(self):
        self.assertEqual(ns._freq_to_channel(5180), 36)
        self.assertEqual(ns._freq_to_band(5180), "5GHz")

    def test_6ghz_band_has_no_channel_mapping(self):
        # _freq_to_channel has no 6GHz branch even though _freq_to_band does.
        self.assertEqual(ns._freq_to_channel(5945), "N/A")
        self.assertEqual(ns._freq_to_band(5945), "6GHz")

    def test_out_of_range_frequency_is_not_applicable(self):
        self.assertEqual(ns._freq_to_channel(1000), "N/A")
        self.assertEqual(ns._freq_to_band(1000), "N/A")


class ColourPickerTests(unittest.TestCase):
    def test_apple_is_red(self):
        self.assertEqual(ns._pick_colour("Apple Device (US/Global)"), ns.COLOUR_RED)

    def test_samsung_is_blue(self):
        self.assertEqual(ns._pick_colour("Samsung Electronics (US/Global)"), ns.COLOUR_BLUE)

    def test_unknown_is_grey(self):
        self.assertEqual(ns._pick_colour("Unknown Device [OUI:None]"), ns.COLOUR_GREY)

    def test_other_vendor_defaults_to_yellow(self):
        self.assertEqual(ns._pick_colour("TP-Link (US/Global)"), ns.COLOUR_YELLOW)


class ParseSetTests(unittest.TestCase):
    def test_splits_on_comma_and_semicolon_and_trims(self):
        self.assertEqual(ns._parse_set("a;b,c; d ;;"), {"a", "b", "c", "d"})

    def test_empty_input_is_empty_set(self):
        self.assertEqual(ns._parse_set(""), set())


# ---------------------------------------------------------------------------
# Frame classification
# ---------------------------------------------------------------------------

class ClassifyFrameTests(unittest.TestCase):
    def test_beacon_uses_addr3(self):
        pkt = FakePacket(layers=(ns.Dot11Beacon,), addr3="aa:bb:cc:dd:ee:ff")
        self.assertEqual(ns.classify_frame(pkt), ("BEACON", "AA:BB:CC:DD:EE:FF"))

    def test_probe_request_uses_addr2(self):
        pkt = FakePacket(layers=(ns.Dot11ProbeReq,), addr2="11:22:33:44:55:66")
        self.assertEqual(ns.classify_frame(pkt), ("PROBE", "11:22:33:44:55:66".upper()))

    def test_assoc_response_takes_priority_over_assoc_request(self):
        # In real scapy, a Dot11AssoResp frame also satisfies
        # haslayer(Dot11AssoReq) because it subclasses it; classify_frame
        # checks *Resp before *Req specifically to avoid misreporting it.
        pkt = FakePacket(
            layers=(ns.Dot11AssoReq, ns.Dot11AssoResp), addr2="00:00:00:00:00:01"
        )
        pkt_type, _ = ns.classify_frame(pkt)
        self.assertEqual(pkt_type, "ASSOC_RESP")

    def test_reassoc_response_takes_priority_over_reassoc_request(self):
        pkt = FakePacket(
            layers=(ns.Dot11ReassoReq, ns.Dot11ReassoResp), addr2="00:00:00:00:00:02"
        )
        pkt_type, _ = ns.classify_frame(pkt)
        self.assertEqual(pkt_type, "REASSOC_RESP")

    def test_deauth_and_disassoc(self):
        deauth = FakePacket(layers=(ns.Dot11Deauth,), addr2="a")
        disassoc = FakePacket(layers=(ns.Dot11Disas,), addr2="b")
        self.assertEqual(ns.classify_frame(deauth)[0], "DEAUTH")
        self.assertEqual(ns.classify_frame(disassoc)[0], "DISASSOC")

    def test_unsupported_frame_is_ignored(self):
        pkt = FakePacket(layers=())
        self.assertEqual(ns.classify_frame(pkt), (None, ""))


# ---------------------------------------------------------------------------
# SSID extraction
# ---------------------------------------------------------------------------

class ExtractSsidTests(unittest.TestCase):
    def test_prefers_top_level_info_attribute(self):
        pkt = SsidPacket(info=b"HomeWifi")
        self.assertEqual(ns.extract_ssid(pkt, "(fallback)"), "HomeWifi")

    def test_falls_back_to_ssid_information_element(self):
        pkt = SsidPacket(info=b"", elt_info=b"OfficeWifi")
        self.assertEqual(ns.extract_ssid(pkt, "(fallback)"), "OfficeWifi")

    def test_falls_back_to_default_when_nothing_present(self):
        pkt = SsidPacket(info=b"", elt_info=None)
        self.assertEqual(ns.extract_ssid(pkt, "(Wildcard)"), "(Wildcard)")


# ---------------------------------------------------------------------------
# Device identity correlation
# ---------------------------------------------------------------------------

class CorrelationIdentityTests(unittest.TestCase):
    def test_apple_vendor_tag_wins_regardless_of_mac_oui(self):
        pkt = IdentityPacket(
            addr2="11:22:33:44:55:66", vendor_chain=VendorNode(0x0017F2)
        )
        self.assertEqual(ns.get_correlation_identity(pkt), "Apple Device (Unknown)")

    def test_region_is_th_eu_when_channel_12_or_13_supported(self):
        pkt = IdentityPacket(
            addr2="11:22:33:44:55:66",
            vendor_chain=VendorNode(0x0017F2),
            ch_list=[1, 2, 12],
        )
        self.assertEqual(ns.get_correlation_identity(pkt), "Apple Device (TH/EU)")

    def test_windows_vendor_tag(self):
        pkt = IdentityPacket(
            addr2="11:22:33:44:55:66", vendor_chain=VendorNode(0x0050F2)
        )
        self.assertEqual(
            ns.get_correlation_identity(pkt),
            "Windows/PC (Microsoft (Surface/WPS))",
        )

    def test_iot_vendor_from_mac_oui_alone(self):
        pkt = IdentityPacket(addr2="84:E1:BA:11:22:33", vendor_chain=None)
        self.assertEqual(
            ns.get_correlation_identity(pkt), "Smart Home/IoT (Tuya Smart (IoT))"
        )

    def test_known_vendor_without_any_information_elements(self):
        pkt = IdentityPacket(addr2="50:C7:BF:11:22:33", has_elt=False)
        self.assertEqual(ns.get_correlation_identity(pkt), "TP-Link (Unknown)")

    def test_falls_back_to_addr3_when_addr2_missing(self):
        pkt = IdentityPacket(addr2=None, addr3="50:C7:BF:11:22:33", has_elt=False)
        self.assertEqual(ns.get_correlation_identity(pkt), "TP-Link (Unknown)")


# ---------------------------------------------------------------------------
# Information-element decoding
# ---------------------------------------------------------------------------

class DecodeIeTests(unittest.TestCase):
    def test_ssid_tag(self):
        self.assertEqual(ns._decode_ie(0, b"MySSID"), "MySSID")

    def test_hidden_ssid_tag(self):
        self.assertEqual(ns._decode_ie(0, b""), "(Wildcard/Hidden)")

    def test_supported_rates_tag(self):
        self.assertEqual(ns._decode_ie(1, bytes([0x82, 0x84])), "Mbps: 1,2")

    def test_ds_parameter_set_tag(self):
        self.assertEqual(ns._decode_ie(3, bytes([6])), "Channel 6")

    def test_country_tag(self):
        self.assertEqual(ns._decode_ie(7, b"US "), "Country US")

    def test_erp_info_tag(self):
        self.assertEqual(ns._decode_ie(42, bytes([0x04])), "ERP 0x04")

    def test_vendor_specific_tag_includes_friendly_name(self):
        self.assertEqual(
            ns._decode_ie(221, b"\x00\x50\xf2\x04"),
            "OUI 00:50:f2 (Microsoft (Surface/WPS))",
        )

    def test_unrecognized_tag_decodes_to_empty_string(self):
        self.assertEqual(ns._decode_ie(99, b"\x01\x02"), "")


class DumpIeDetailsTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_file = Path(self._tmpdir.name) / "ie_details.csv"

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_rows_match_ie_sequence_and_decode(self):
        raw = b"\x00\x02\x41\x42\x03\x01\x06"
        pkt = RawIePacket(raw)
        with patch.object(ns, "IE_DETAILS_FILE", str(self.tmp_file)):
            ns.dump_ie_details(pkt, "2026-01-01 00:00:00", "PROBE", "AA:BB:CC:DD:EE:FF")
        with open(self.tmp_file, newline="") as fh:
            rows = list(csv.reader(fh))

        self.assertEqual(len(rows), 2)
        ts, pkt_type, mac, index, ie_id, ie_name, ie_len, ie_hex, ie_decoded = rows[0]
        self.assertEqual((pkt_type, mac, index, ie_id, ie_name), ("PROBE", "AA:BB:CC:DD:EE:FF", "0", "0", "SSID"))
        self.assertEqual(ie_decoded, "AB")
        self.assertEqual(rows[1][4], "3")
        self.assertEqual(rows[1][5], "DS Parameter Set")
        self.assertEqual(rows[1][8], "Channel 6")

    def test_no_information_elements_writes_nothing(self):
        pkt = RawIePacket(b"")
        with patch.object(ns, "IE_DETAILS_FILE", str(self.tmp_file)):
            ns.dump_ie_details(pkt, "2026-01-01 00:00:00", "BEACON", "AA:BB:CC:DD:EE:FF")
        self.assertFalse(self.tmp_file.exists())


# ---------------------------------------------------------------------------
# CSV setup + append helpers
# ---------------------------------------------------------------------------

class CsvSetupTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_file = Path(self._tmpdir.name) / "report.csv"

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_setup_csv_creates_header_when_missing(self):
        with patch.object(ns, "LOG_FILE", str(self.tmp_file)):
            ns.setup_csv()
            with open(self.tmp_file, newline="") as fh:
                rows = list(csv.reader(fh))
        self.assertEqual(rows, [ns.CSV_FIELDS])

    def test_setup_csv_does_not_clobber_existing_file(self):
        self.tmp_file.write_text("not,a,header\n1,2,3\n")
        with patch.object(ns, "LOG_FILE", str(self.tmp_file)):
            ns.setup_csv()
        self.assertEqual(self.tmp_file.read_text(), "not,a,header\n1,2,3\n")

    def test_setup_ie_csv_creates_header_when_missing(self):
        with patch.object(ns, "IE_DETAILS_FILE", str(self.tmp_file)):
            ns.setup_ie_csv()
            with open(self.tmp_file, newline="") as fh:
                rows = list(csv.reader(fh))
        self.assertEqual(rows, [ns.IE_CSV_FIELDS])

    def test_setup_ie_csv_truncates_previous_session(self):
        # Unlike the main log, the IE report holds only the current session so it
        # can be cross-checked against the daily summary — startup wipes stale rows.
        self.tmp_file.write_text("old,session,data\n1,2,3\n")
        with patch.object(ns, "IE_DETAILS_FILE", str(self.tmp_file)):
            ns.setup_ie_csv()
            with open(self.tmp_file, newline="") as fh:
                rows = list(csv.reader(fh))
        self.assertEqual(rows, [ns.IE_CSV_FIELDS])

    def test_append_csv_row_appends_after_header(self):
        self.tmp_file.write_text("")
        with open(self.tmp_file, "w", newline="") as fh:
            csv.writer(fh).writerow(ns.CSV_FIELDS)
        with patch.object(ns, "LOG_FILE", str(self.tmp_file)):
            ns._append_csv_row(["ts", "PROBE", "AA:BB", "Real"] + [""] * (len(ns.CSV_FIELDS) - 4))
        with open(self.tmp_file, newline="") as fh:
            rows = list(csv.reader(fh))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1][:4], ["ts", "PROBE", "AA:BB", "Real"])


# ---------------------------------------------------------------------------
# Session-window math (pure logic, no locking involved)
# ---------------------------------------------------------------------------

class SessionWindowMathTests(unittest.TestCase):
    def _session(self, first_ts, last_ts):
        return ns.Session(last_mac="00:11:22:33:44:55", first_ts=first_ts, last_ts=last_ts)

    def test_overlapping_windows_detected(self):
        session = self._session(100, 200)
        self.assertTrue(ns._sessions_overlap(session, 195, 300))

    def test_windows_further_apart_than_tolerance_do_not_overlap(self):
        session = self._session(100, 200)
        gap_start = 200 + ns.OVERLAP_TOLERANCE_SECONDS + 1
        self.assertFalse(ns._sessions_overlap(session, gap_start, gap_start + 50))

    def test_time_gap_when_right_window_is_later(self):
        session = self._session(100, 200)
        self.assertEqual(ns._time_gap_seconds(session, 250, 300), 50)

    def test_time_gap_when_right_window_is_earlier(self):
        session = self._session(100, 200)
        self.assertEqual(ns._time_gap_seconds(session, 0, 50), 50)

    def test_time_gap_is_zero_when_windows_touch_or_overlap(self):
        session = self._session(100, 200)
        self.assertEqual(ns._time_gap_seconds(session, 150, 160), 0)


# ---------------------------------------------------------------------------
# Session summary report
# ---------------------------------------------------------------------------

class GenerateSessionReportTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self._orig_sessions = dict(ns.active_sessions)
        ns.active_sessions.clear()

    def tearDown(self):
        self._tmpdir.cleanup()
        ns.active_sessions.clear()
        ns.active_sessions.update(self._orig_sessions)

    def test_report_row_reflects_session_stats(self):
        session = ns.Session(
            last_mac="02:11:22:33:44:55",
            all_macs={"02:11:22:33:44:55", "06:11:22:33:44:55"},
            fingerprint="Apple Device (US/Global)",
            frame_types={"PROBE"},
            ssids={"Office"},
            first_ts=1000.0,
            last_ts=1090.0,
        )
        session.rssi_min, session.rssi_max = -60, -40
        session.rssi_total, session.rssi_count = -150, 3
        ns.active_sessions[1] = session

        with patch.object(ns, "SUMMARY_DIR", self._tmpdir.name), \
             patch.object(ns.time, "strftime", return_value="20260101"):
            ns.generate_session_report()

        report_file = Path(self._tmpdir.name) / "daily_summary_20260101.csv"
        with open(report_file, newline="", encoding="utf-8") as fh:
            rows = list(csv.reader(fh))

        self.assertEqual(rows[0][0], "User_ID")
        row = rows[1]
        self.assertEqual(row[0], "User_1")
        self.assertEqual(row[3], "1.5m")           # stay_min
        self.assertEqual(row[4], "Apple Device")   # clean_id (split on "(")
        self.assertEqual(row[5], "2")               # MAC_Count
        self.assertEqual(row[6], "PROBE")
        self.assertEqual(row[9], "-60")             # RSSI_Min
        self.assertEqual(row[10], "-40")            # RSSI_Max
        self.assertEqual(row[11], "-50.0")          # RSSI_Avg
        self.assertEqual(row[12], "Office")         # Top_SSID

    def test_multiple_ssids_are_summarized_with_a_count_suffix(self):
        session = ns.Session(
            last_mac="00:11:22:33:44:55",
            all_macs={"00:11:22:33:44:55"},
            fingerprint="Unknown Device [OUI:None]",
            ssids={"Office"},
            first_ts=0.0,
            last_ts=60.0,
        )
        session.ssids.add("Home")
        ns.active_sessions[1] = session

        with patch.object(ns, "SUMMARY_DIR", self._tmpdir.name), \
             patch.object(ns.time, "strftime", return_value="20260101"):
            ns.generate_session_report()

        report_file = Path(self._tmpdir.name) / "daily_summary_20260101.csv"
        with open(report_file, newline="", encoding="utf-8") as fh:
            rows = list(csv.reader(fh))
        self.assertIn("(+1)", rows[1][12])

    def test_empty_sessions_still_writes_header_only(self):
        with patch.object(ns, "SUMMARY_DIR", self._tmpdir.name), \
             patch.object(ns.time, "strftime", return_value="20260101"):
            ns.generate_session_report()
        report_file = Path(self._tmpdir.name) / "daily_summary_20260101.csv"
        with open(report_file, newline="", encoding="utf-8") as fh:
            rows = list(csv.reader(fh))
        self.assertEqual(len(rows), 1)


# ---------------------------------------------------------------------------
# Interface recovery
# ---------------------------------------------------------------------------

class ResetMonitorModeTests(unittest.TestCase):
    def test_runs_down_monitor_up_sequence_in_order(self):
        with patch.object(ns.subprocess, "run") as mock_run, \
             patch.object(ns.time, "sleep") as mock_sleep:
            mock_run.return_value = types.SimpleNamespace(returncode=0, stderr="")
            ns.reset_monitor_mode("wlan1")

        self.assertEqual(
            [c.args[0] for c in mock_run.call_args_list],
            [
                ["ip", "link", "set", "wlan1", "down"],
                ["iw", "dev", "wlan1", "set", "type", "monitor"],
                ["ip", "link", "set", "wlan1", "up"],
            ],
        )
        mock_sleep.assert_called_once_with(1)

    def test_command_failure_does_not_raise(self):
        with patch.object(ns.subprocess, "run") as mock_run, \
             patch.object(ns.time, "sleep"):
            mock_run.return_value = types.SimpleNamespace(returncode=1, stderr="boom")
            ns.reset_monitor_mode("wlan1")  # should not raise despite failures


if __name__ == "__main__":
    unittest.main()
