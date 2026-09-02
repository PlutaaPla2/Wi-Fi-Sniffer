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

import contextlib
import csv
import importlib
import io
import time
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
    """Minimal Dot11-like packet: layer membership + arbitrary attrs.

    ``subtype`` opts the packet into the frame-control interface classify_frame()
    now uses — it reads the type/subtype field through getlayer(Dot11) rather
    than testing per-subtype layer classes. ``layers`` is still honoured for the
    other helpers that do use haslayer().
    """

    def __init__(self, layers=(), type=0, subtype=None, **attrs):
        self._layers = set(layers)
        self.type = type
        self.subtype = subtype
        for key, value in attrs.items():
            setattr(self, key, value)

    def haslayer(self, layer):
        return layer in self._layers

    def getlayer(self, layer):
        if layer is ns.Dot11 and self.subtype is not None:
            return self
        return None


def tlv(ie_id, data=b""):
    """One information element as it appears on the wire: [ID][len][data]."""
    return bytes([ie_id, len(data)]) + data


def vendor_tlv(oui, vendor_type=None, extra=b""):
    """A Vendor Specific element (221). ``oui`` is a 3-byte int, e.g. 0x0050F2.

    The vendor type is the octet after the OUI, which is what distinguishes a
    WMM element (00:50:F2 type 2) from a WPS one (type 4).
    """
    payload = oui.to_bytes(3, "big")
    if vendor_type is not None:
        payload += bytes([vendor_type])
    return tlv(221, payload + extra)


def mgmt_wire(subtype=4, body=b"", elements=b"",
              addr1="ff:ff:ff:ff:ff:ff",
              addr2="00:00:00:00:00:00",
              addr3="00:00:00:00:00:00"):
    """Wire bytes of a management frame: real 24-byte header, body, elements."""
    def mac(text):
        return bytes(int(part, 16) for part in text.split(":"))

    frame_control = bytes([(subtype << 4) & 0xF0, 0x00])
    return (frame_control + b"\x00\x00"
            + mac(addr1) + mac(addr2) + mac(addr3) + b"\x00\x00"
            + body + elements)


class WirePacket:
    """Fake packet exposing captured bytes, the way the element walk reads them.

    The helpers here deliberately build real TLV bytes rather than mimicking a
    Scapy layer object. The previous fixtures supplied a vendor element's
    payload without its OUI, which does not match what Scapy returns, and that
    mismatch let a defect in the WMM/WPS guard pass its own test.
    """

    def __init__(self, subtype=4, body=b"", elements=b"", addr2=None, addr3=None):
        self.addr2 = addr2
        self.addr3 = addr3
        self._raw = mgmt_wire(
            subtype, body, elements,
            addr2=addr2 or "00:00:00:00:00:00",
            addr3=addr3 or "00:00:00:00:00:00",
        )

    def getlayer(self, layer, ID=None):
        if layer is ns.Dot11:
            return types.SimpleNamespace(original=self._raw)
        return None

    def haslayer(self, layer):
        return layer is ns.Dot11





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


class SequenceDeltaTests(unittest.TestCase):
    def test_small_forward_step(self):
        self.assertEqual(ns.seq_delta(105, 100), 5)

    def test_wraparound(self):
        self.assertEqual(ns.seq_delta(3, 4095), 4)

    def test_equal_inputs(self):
        self.assertEqual(ns.seq_delta(1234, 1234), 0)


class AuthTierTests(unittest.TestCase):
    def test_sae_algorithm(self):
        self.assertEqual(ns.auth_tier(3, set()), "WPA3-SAE")

    def test_ft_algorithm(self):
        self.assertEqual(ns.auth_tier(2, set()), "FT")

    def test_open_auth_with_ft_tags_is_ft(self):
        self.assertEqual(ns.auth_tier(0, {54, 55}), "FT")

    def test_open_auth_without_ft_tags_is_open(self):
        self.assertEqual(ns.auth_tier(0, set()), "Open")

    def test_unknown_algorithm_is_labelled(self):
        self.assertEqual(ns.auth_tier(1, set()), "algo:1")


class FrameDirectionTests(unittest.TestCase):
    def test_equal_addr2_addr3_is_from_ap(self):
        pkt = FakePacket(addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff")
        self.assertEqual(ns.frame_direction(pkt), "from-AP")

    def test_different_addr2_addr3_is_from_client(self):
        pkt = FakePacket(addr2="11:22:33:44:55:66", addr3="aa:bb:cc:dd:ee:ff")
        self.assertEqual(ns.frame_direction(pkt), "from-client")

    def test_missing_address_is_unknown(self):
        self.assertEqual(ns.frame_direction(FakePacket(addr2="aa:bb:cc:dd:ee:ff")), "unknown")
        self.assertEqual(ns.frame_direction(FakePacket()), "unknown")


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

    def test_microsoft_protocol_oui_is_not_a_device_vendor(self):
        with patch.object(ns._vendor_lookup, "lookup") as mock_lookup:
            self.assertEqual(ns.vendor_from_ie_ouis("00:50:F2"), "Unknown")
        mock_lookup.assert_not_called()


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
    """Frames are classified from the frame-control subtype field.

    These tests previously described a ladder of haslayer() checks whose
    ordering was meant to stop Scapy's layer subclassing from misreporting the
    response frames. That ordering did not survive contact with a capture
    carrying an FCS, so classification now reads the subtype directly. The
    intent of each case is unchanged; only the mechanism it exercises is.
    """

    def test_beacon_uses_addr3(self):
        pkt = FakePacket(subtype=8, addr3="aa:bb:cc:dd:ee:ff")
        self.assertEqual(ns.classify_frame(pkt), ("BEACON", "AA:BB:CC:DD:EE:FF"))

    def test_beacon_prefers_bssid_over_transmitter(self):
        # These are the same address on a normal AP but differ on a repeater.
        # The column has always meant the BSSID for beacons and must keep to it,
        # because wifi_full_recon_report.csv accumulates across runs.
        pkt = FakePacket(subtype=8, addr2="11:22:33:44:55:66",
                         addr3="aa:bb:cc:dd:ee:ff")
        self.assertEqual(ns.classify_frame(pkt)[1], "AA:BB:CC:DD:EE:FF")

    def test_probe_request_uses_addr2(self):
        pkt = FakePacket(subtype=4, addr2="11:22:33:44:55:66")
        self.assertEqual(ns.classify_frame(pkt), ("PROBE", "11:22:33:44:55:66".upper()))

    def test_transmitter_address_wins_over_bssid(self):
        pkt = FakePacket(subtype=4, addr2="11:22:33:44:55:66",
                         addr3="aa:bb:cc:dd:ee:ff")
        self.assertEqual(ns.classify_frame(pkt)[1], "11:22:33:44:55:66".upper())

    def test_association_response_is_labelled_as_a_response(self):
        pkt = FakePacket(subtype=1, addr2="00:00:00:00:00:01")
        self.assertEqual(ns.classify_frame(pkt)[0], "ASSOC_RESP")

    def test_reassociation_response_is_not_confused_with_association_response(self):
        # The bug this replaces: Dot11ReassoResp subclasses Dot11AssoResp, and
        # with Dot11FCS in the chain haslayer() matched the parent class first,
        # so every Reassociation Response was recorded as ASSOC_RESP.
        pkt = FakePacket(subtype=3, addr2="00:00:00:00:00:02")
        self.assertEqual(ns.classify_frame(pkt)[0], "REASSOC_RESP")

    def test_deauth_and_disassoc(self):
        deauth = FakePacket(subtype=12, addr2="a")
        disassoc = FakePacket(subtype=10, addr2="b")
        self.assertEqual(ns.classify_frame(deauth)[0], "DEAUTH")
        self.assertEqual(ns.classify_frame(disassoc)[0], "DISASSOC")

    def test_previously_unsupported_subtypes_are_now_captured(self):
        # Probe Response and Action were silently dropped before; both are
        # ordinarily more common than every subtype below them in this file.
        for subtype, label in ((5, "PROBE_RESP"), (13, "ACTION"), (9, "ATIM")):
            with self.subTest(subtype=subtype):
                pkt = FakePacket(subtype=subtype, addr2="00:00:00:00:00:03")
                self.assertEqual(ns.classify_frame(pkt)[0], label)

    def test_non_management_frame_is_ignored(self):
        # Control (1) and data (2) frames stay out of scope, matching the
        # `type mgt` filter the reference dumpcap capture uses.
        self.assertEqual(
            ns.classify_frame(FakePacket(type=2, subtype=0, addr2="a")), (None, "")
        )
        # A packet with no Dot11 layer at all.
        self.assertEqual(ns.classify_frame(FakePacket(layers=())), (None, ""))


# ---------------------------------------------------------------------------
# SSID extraction
# ---------------------------------------------------------------------------

class ExtractSsidTests(unittest.TestCase):
    def test_reads_only_the_tag_zero_element(self):
        # Elements present, but none of them is an SSID.
        pkt = WirePacket(elements=tlv(1, b"\x82\x84") + vendor_tlv(0x0017F2, 0x0A))
        self.assertEqual(ns.extract_ssid(pkt, "(fallback)"), "(fallback)")

    def test_reads_the_ssid_information_element(self):
        pkt = WirePacket(elements=tlv(0, b"OfficeWifi") + tlv(1, b"\x82"))
        self.assertEqual(ns.extract_ssid(pkt, "(fallback)"), "OfficeWifi")

    def test_falls_back_to_default_when_nothing_present(self):
        self.assertEqual(ns.extract_ssid(WirePacket(), "(Wildcard)"), "(Wildcard)")

    def test_zero_length_ssid_uses_the_fallback(self):
        # A wildcard probe or a hidden network: the element is there but empty.
        pkt = WirePacket(elements=tlv(0, b"") + tlv(1, b"\x82"))
        self.assertEqual(ns.extract_ssid(pkt, "(Hidden SSID)"), "(Hidden SSID)")

    def test_reads_an_ssid_past_the_fixed_body_of_a_beacon(self):
        # Beacons carry 12 bytes of fixed fields before the first element; the
        # walk has to skip them rather than treat them as element bytes.
        pkt = WirePacket(subtype=8, body=bytes(12), elements=tlv(0, b"OfficeWifi"))
        self.assertEqual(ns.extract_ssid(pkt, "(fallback)"), "OfficeWifi")


# ---------------------------------------------------------------------------
# Device identity correlation
# ---------------------------------------------------------------------------

class CorrelationIdentityTests(unittest.TestCase):
    def test_apple_vendor_tag_wins_regardless_of_mac_oui(self):
        pkt = WirePacket(addr2="11:22:33:44:55:66",
                         elements=vendor_tlv(0x0017F2, 0x0A))
        self.assertEqual(ns.get_correlation_identity(pkt), "Apple Device (Unknown)")

    def test_region_is_th_eu_when_channel_12_or_13_supported(self):
        pkt = WirePacket(addr2="11:22:33:44:55:66",
                         elements=vendor_tlv(0x0017F2, 0x0A) + tlv(50, bytes([1, 2, 12])))
        self.assertEqual(ns.get_correlation_identity(pkt), "Apple Device (TH/EU)")

    def test_wmm_vendor_tag_does_not_imply_windows_or_microsoft(self):
        # 00:50:F2 type 2 is WMM, a protocol marker carried by devices from many
        # manufacturers. It must not be read as a Microsoft device.
        pkt = WirePacket(addr2="11:22:33:44:55:66",
                         elements=vendor_tlv(0x0050F2, 0x02, b"\x01\x02"))
        identity = ns.get_correlation_identity(pkt)
        self.assertNotIn("Windows", identity)
        self.assertNotIn("Microsoft", identity)

    def test_wps_vendor_tag_does_not_imply_microsoft(self):
        pkt = WirePacket(addr2="11:22:33:44:55:66",
                         elements=vendor_tlv(0x0050F2, 0x04, b"\x10\x4a"))
        self.assertNotIn("Microsoft", ns.get_correlation_identity(pkt))

    def test_vendor_element_after_an_unknown_element_is_still_seen(self):
        # Scapy's element chain stopped at an element it could not dissect, and
        # vendor elements sit late in a frame. The raw walk reaches them.
        pkt = WirePacket(addr2="11:22:33:44:55:66",
                         elements=tlv(201, bytes(12)) + vendor_tlv(0x0017F2, 0x0A))
        self.assertEqual(ns.get_correlation_identity(pkt), "Apple Device (Unknown)")

    def test_iot_vendor_from_mac_oui_alone(self):
        pkt = WirePacket(addr2="1C:90:FF:11:22:33")
        self.assertEqual(
            ns.get_correlation_identity(pkt), "Smart Home/IoT (Tuya Smart (IoT))"
        )

    def test_known_vendor_without_any_information_elements(self):
        pkt = WirePacket(addr2="50:C7:BF:11:22:33")
        self.assertEqual(ns.get_correlation_identity(pkt), "TP-Link (Unknown)")

    def test_falls_back_to_addr3_when_addr2_missing(self):
        pkt = WirePacket(addr2=None, addr3="50:C7:BF:11:22:33")
        self.assertEqual(ns.get_correlation_identity(pkt), "TP-Link (Unknown)")


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

    def test_init_log_file_creates_header_when_missing(self):
        # setup_csv() was replaced by init_log_file(), which names the file from
        # the rotation bucket rather than a fixed LOG_FILE - so the directory is
        # what gets patched, and the resulting path is read back off the module.
        with patch.object(ns, "LOG_DIR", self._tmpdir.name), \
             patch.object(ns, "LOG_FILE", ""), \
             patch.object(ns, "_log_bucket_ts", None):
            ns.init_log_file()
            with open(ns.LOG_FILE, newline="") as fh:
                rows = list(csv.reader(fh))
        self.assertEqual(rows, [ns.CSV_FIELDS])
        # Frame_Hex holds a fixed position so appending it did not move any
        # column above it. Later columns are appended after it rather than
        # inserted, so its index is the invariant, not its being last;
        # everything else is addressed by name.
        self.assertEqual(ns.CSV_FIELDS.index("Frame_Hex"), 25)
        self.assertEqual(ns.CSV_FIELDS[-1], "Timestamp_ISO")
        for column in ("Seq_Num", "Direction", "Reason_Code"):
            self.assertIn(column, ns.CSV_FIELDS)

    def test_init_log_file_does_not_clobber_the_current_interval(self):
        # A restart mid-interval must append to the file already covering that
        # interval, not truncate it and not add a second header row.
        with patch.object(ns, "LOG_DIR", self._tmpdir.name), \
             patch.object(ns, "LOG_FILE", ""), \
             patch.object(ns, "_log_bucket_ts", None):
            existing = ns.build_log_path(ns._log_bucket(time.time()))
            Path(existing).write_text("not,a,header\n1,2,3\n")
            ns.init_log_file()
            self.assertEqual(ns.LOG_FILE, existing)
        self.assertEqual(Path(existing).read_text(), "not,a,header\n1,2,3\n")

    def test_append_csv_row_appends_after_header(self):
        # LOG_DIR is patched rather than LOG_FILE: the live path now rolls the
        # file inside _append_csv_row(), reassigning LOG_FILE, so patching the
        # filename would be silently defeated on the very first row.
        with patch.object(ns, "LOG_DIR", self._tmpdir.name), \
             patch.object(ns, "LOG_FILE", ""), \
             patch.object(ns, "_log_bucket_ts", None):
            ns.init_log_file()
            ns._append_csv_row(["ts", "PROBE", "AA:BB", "Real"] + [""] * (len(ns.CSV_FIELDS) - 4))
            path = ns.LOG_FILE
            ns.close_output_files()
        with open(path, newline="") as fh:
            rows = list(csv.reader(fh))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], ns.CSV_FIELDS)
        self.assertEqual(rows[1][:4], ["ts", "PROBE", "AA:BB", "Real"])


# ---------------------------------------------------------------------------
# Log rotation and count-based pruning
# ---------------------------------------------------------------------------

class LogRotationTests(unittest.TestCase):
    """Interval bucketing and filename assembly. Pure arithmetic and strings."""

    def test_bucket_snaps_to_the_interval_start(self):
        with patch.object(ns, "LOG_ROTATE_SECONDS", 900):
            # A timestamp mid-interval belongs to the interval's start, not to
            # its own second.
            self.assertEqual(ns._log_bucket(1_000_000_450.0), 999_999_900.0)
            for now, expected in ((900.0, 900.0), (901.0, 900.0),
                                  (1799.9, 900.0), (1800.0, 1800.0)):
                self.assertEqual(ns._log_bucket(now), expected)

    def test_every_instant_in_an_interval_maps_to_one_filename(self):
        # This is what makes a restart mid-interval append instead of starting a
        # second file for the same window.
        with patch.object(ns, "LOG_ROTATE_SECONDS", 900), \
             patch.object(ns, "LOG_DIR", "/tmp/x"):
            names = {ns.build_log_path(ns._log_bucket(900.0 + off))
                     for off in (0, 1, 450, 899.999)}
        self.assertEqual(len(names), 1)

    def test_filenames_sort_chronologically_as_plain_strings(self):
        # The pruner sorts lexicographically and never parses a filename, so
        # date-first naming is load-bearing, not cosmetic.
        with patch.object(ns, "LOG_ROTATE_SECONDS", 900), \
             patch.object(ns, "LOG_DIR", "/tmp/x"), \
             patch.object(ns, "LOG_PREFIX", "wifi_full_recon_report"):
            buckets = [ns._log_bucket(t) for t in
                       (1_700_000_000.0, 1_700_090_000.0, 1_700_900_000.0)]
            paths = [ns.build_log_path(b) for b in buckets]
        self.assertEqual(paths, sorted(paths))
        for path in paths:
            self.assertTrue(path.endswith("-wifi_full_recon_report.csv"))


class LogPruningTests(unittest.TestCase):
    """The only code in the project that deletes captured data."""

    def setUp(self):
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.dir = self._tmpdir.name

    def tearDown(self):
        ns.close_output_files()
        self._tmpdir.cleanup()

    def _seed(self, count):
        """Create ``count`` rotated logs with ascending, boundary-aligned names."""
        paths = []
        for i in range(count):
            path = Path(self.dir) / f"2026010{i}-000000-wifi_full_recon_report.csv"
            path.write_text("header\n")
            paths.append(str(path))
        return paths

    def _prune(self, active, *, enabled=True, keep=2):
        with patch.object(ns, "LOG_DIR", self.dir), \
             patch.object(ns, "LOG_PREFIX", "wifi_full_recon_report"), \
             patch.object(ns, "LOG_KEEP_FILES", keep), \
             patch.object(ns, "LOG_PRUNE_ENABLED", enabled), \
             patch.object(ns, "LOG_FILE", active):
            ns._prune_old_logs()
        return sorted(str(p) for p in Path(self.dir).glob("*.csv"))

    def test_keeps_the_newest_n_and_deletes_the_rest(self):
        paths = self._seed(5)
        self.assertEqual(self._prune(paths[-1]), paths[-2:])

    def test_no_op_until_the_count_is_exceeded(self):
        # With keep=2 the third file's creation is the first deletion.
        paths = self._seed(2)
        self.assertEqual(self._prune(paths[-1]), paths)

    def test_disabled_switch_deletes_nothing(self):
        paths = self._seed(6)
        self.assertEqual(self._prune(paths[-1], enabled=False), paths)

    def test_keep_zero_deletes_nothing(self):
        # Guarded separately from the switch so a misconfigured 0 cannot be read
        # as "keep none of them".
        paths = self._seed(6)
        self.assertEqual(self._prune(paths[-1], keep=0), paths)

    def test_never_deletes_the_active_file(self):
        # The active file sorts last so it should never be a candidate; this
        # asserts the explicit guard holds even when it is not, because the cost
        # of being wrong is deleting the file currently being written.
        paths = self._seed(5)
        survivors = self._prune(paths[0], keep=1)
        self.assertIn(paths[0], survivors)
        self.assertIn(paths[-1], survivors)

    def test_ignores_files_it_did_not_name(self):
        # ie_details_report.csv and the daily summary live in the same directory
        # and are explicitly out of scope.
        paths = self._seed(5)
        bystanders = []
        for name in ("ie_details_report.csv", "daily_summary_2026-01-01.csv"):
            other = Path(self.dir) / name
            other.write_text("x")
            bystanders.append(str(other))
        survivors = self._prune(paths[-1])
        for path in bystanders:
            self.assertIn(path, survivors)

    def test_a_rolled_file_is_bounded_at_the_moment_it_is_created(self):
        # End to end through _open_new_log(), which is the only caller: crossing
        # four boundaries must leave exactly LOG_KEEP_FILES files behind.
        with patch.object(ns, "LOG_DIR", self.dir), \
             patch.object(ns, "LOG_ROTATE_SECONDS", 60), \
             patch.object(ns, "LOG_KEEP_FILES", 2), \
             patch.object(ns, "LOG_PRUNE_ENABLED", True), \
             patch.object(ns, "LOG_FILE", ""), \
             patch.object(ns, "_log_bucket_ts", None):
            for tick in range(5):
                with ns._writer_lock:
                    ns._open_new_log(ns._log_bucket(1_700_000_000.0 + tick * 60))
                    active = ns.LOG_FILE
            ns.close_output_files()
            remaining = sorted(str(p) for p in Path(self.dir).glob("*.csv"))
        self.assertEqual(len(remaining), 2)
        self.assertEqual(remaining[-1], active)


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


# ---------------------------------------------------------------------------
# Channel control
# ---------------------------------------------------------------------------

class SetChannelTests(unittest.TestCase):
    def test_issues_iw_set_channel_and_reports_success(self):
        with patch.object(ns.subprocess, "run") as mock_run:
            mock_run.return_value = types.SimpleNamespace(returncode=0, stderr="")
            self.assertTrue(ns.set_channel("wlan1", 36))

        self.assertEqual(
            mock_run.call_args.args[0],
            ["iw", "dev", "wlan1", "set", "channel", "36"],
        )

    def test_driver_refusal_reports_failure(self):
        # What a DFS/no-IR rejection looks like coming back from iw.
        with patch.object(ns.subprocess, "run") as mock_run, \
             patch.object(ns.log, "warning"):
            mock_run.return_value = types.SimpleNamespace(
                returncode=-22, stderr="command failed: Invalid argument (-22)"
            )
            self.assertFalse(ns.set_channel("wlan1", 120))

    def test_quiet_suppresses_the_per_failure_warning(self):
        with patch.object(ns.subprocess, "run") as mock_run, \
             patch.object(ns.log, "warning") as mock_warning:
            mock_run.return_value = types.SimpleNamespace(returncode=1, stderr="nope")
            self.assertFalse(ns.set_channel("wlan1", 120, quiet=True))

        mock_warning.assert_not_called()


class ChannelBandLabelTests(unittest.TestCase):
    def test_labels_channels_from_the_configured_lists(self):
        self.assertEqual(ns._channel_band_label(6), "2.4GHz")
        self.assertEqual(ns._channel_band_label(36), "5GHz")
        self.assertEqual(ns._channel_band_label(165), "5GHz")

    def test_channel_outside_the_configured_lists_is_unknown(self):
        self.assertEqual(ns._channel_band_label(14), "unknown")  # Japan-only
        self.assertEqual(ns._channel_band_label(999), "unknown")


class BuildHopChannelsTests(unittest.TestCase):
    def test_each_band_maps_to_its_configured_list(self):
        self.assertEqual(ns.build_hop_channels("2.4"), ns.CHANNELS_2GHZ)
        self.assertEqual(ns.build_hop_channels("5"), ns.CHANNELS_5GHZ)

    def test_both_is_one_concatenated_sweep_not_an_interleave(self):
        self.assertEqual(
            ns.build_hop_channels("both"),
            ns.CHANNELS_2GHZ + ns.CHANNELS_5GHZ,
        )

    def test_returns_a_copy_so_callers_cannot_mutate_the_config(self):
        channels = ns.build_hop_channels("2.4")
        channels.append(99)
        self.assertNotIn(99, ns.CHANNELS_2GHZ)

    def test_24ghz_range_is_1_to_13(self):
        # Channel 14 is Japan-only and deliberately excluded.
        self.assertEqual(ns.CHANNELS_2GHZ, list(range(1, 14)))

    def test_unknown_band_raises(self):
        with self.assertRaises(ValueError):
            ns.build_hop_channels("6")


class ProbeChannelsTests(unittest.TestCase):
    def test_drops_the_channels_the_driver_refuses(self):
        refused = {120, 124, 128}
        with patch.object(
            ns, "set_channel", side_effect=lambda i, c, quiet=False: c not in refused
        ), patch.object(ns.time, "sleep"), patch.object(ns.log, "warning"):
            usable = ns.probe_channels("wlan1", [36, 120, 124, 128, 149])

        self.assertEqual(usable, [36, 149])

    def test_probes_quietly_so_refusals_do_not_spam_warnings(self):
        with patch.object(ns, "set_channel", return_value=True) as mock_set, \
             patch.object(ns.time, "sleep"):
            ns.probe_channels("wlan1", [36])

        self.assertTrue(mock_set.call_args.kwargs.get("quiet"))

    def test_nothing_tunable_falls_back_to_the_unverified_list(self):
        # Almost always means the interface is not in monitor mode; returning
        # an empty rotation would leave the hopper with nothing to do.
        requested = [36, 40, 44]
        with patch.object(ns, "set_channel", return_value=False), \
             patch.object(ns.time, "sleep"), \
             patch.object(ns.log, "error") as mock_error, \
             patch.object(ns.log, "warning"):
            usable = ns.probe_channels("wlan1", requested)

        self.assertEqual(usable, requested)
        self.assertTrue(mock_error.called)


class ChannelHopperTests(unittest.TestCase):
    def test_walks_the_supplied_list_in_order_dwelling_on_each(self):
        class StopLoop(Exception):
            """Breaks the hopper's infinite while-loop from inside sleep()."""

        visited: list[int] = []
        sleeps: list[float] = []

        def fake_sleep(seconds):
            sleeps.append(seconds)
            if len(sleeps) == 3:
                raise StopLoop

        with patch.object(
            ns, "set_channel", side_effect=lambda i, c: visited.append(c)
        ), patch.object(ns.time, "sleep", fake_sleep), patch.object(ns.log, "info"):
            with self.assertRaises(StopLoop):
                ns.channel_hopper("wlan1", [36, 40, 44, 48])

        self.assertEqual(visited, [36, 40, 44])
        self.assertEqual(sleeps, [ns.CHANNEL_HOP_INTERVAL] * 3)


# ---------------------------------------------------------------------------
# Startup prompts
# ---------------------------------------------------------------------------

class StdinInteractiveTests(unittest.TestCase):
    def test_terminal_stdin_is_interactive(self):
        with patch.object(ns.sys, "stdin", types.SimpleNamespace(isatty=lambda: True)):
            self.assertTrue(ns._stdin_is_interactive())

    def test_piped_stdin_is_not_interactive(self):
        with patch.object(ns.sys, "stdin", types.SimpleNamespace(isatty=lambda: False)):
            self.assertFalse(ns._stdin_is_interactive())

    def test_detached_stdin_is_not_interactive(self):
        with patch.object(ns.sys, "stdin", None):
            self.assertFalse(ns._stdin_is_interactive())

    def test_closed_stdin_is_not_interactive(self):
        def closed():
            raise ValueError("I/O operation on closed file")

        with patch.object(ns.sys, "stdin", types.SimpleNamespace(isatty=closed)):
            self.assertFalse(ns._stdin_is_interactive())


class PromptChoiceTests(unittest.TestCase):
    OPTIONS = [("camp", "Camp on one channel"), ("hop", "Hop across a band")]

    def test_bare_enter_takes_the_default(self):
        with patch("builtins.input", return_value=""), patch("builtins.print"):
            self.assertEqual(ns.prompt_choice("t", self.OPTIONS, "hop"), "hop")

    def test_accepts_the_menu_number(self):
        with patch("builtins.input", return_value="1"), patch("builtins.print"):
            self.assertEqual(ns.prompt_choice("t", self.OPTIONS, "hop"), "camp")

    def test_accepts_the_key_itself_case_insensitively(self):
        with patch("builtins.input", return_value="CAMP"), patch("builtins.print"):
            self.assertEqual(ns.prompt_choice("t", self.OPTIONS, "hop"), "camp")

    def test_reasks_until_the_answer_is_valid(self):
        with patch("builtins.input", side_effect=["nope", "2"]), patch("builtins.print"):
            self.assertEqual(ns.prompt_choice("t", self.OPTIONS, "camp"), "hop")

    def test_closed_stdin_mid_prompt_falls_back_to_the_default(self):
        with patch("builtins.input", side_effect=EOFError), patch("builtins.print"):
            self.assertEqual(ns.prompt_choice("t", self.OPTIONS, "hop"), "hop")

    def test_ctrl_c_at_the_prompt_exits_cleanly(self):
        with patch("builtins.input", side_effect=KeyboardInterrupt), \
             patch("builtins.print"):
            with self.assertRaises(SystemExit):
                ns.prompt_choice("t", self.OPTIONS, "hop")


class PromptCampChannelTests(unittest.TestCase):
    def test_parses_a_channel_number(self):
        with patch("builtins.input", return_value="149"), patch("builtins.print"):
            self.assertEqual(ns.prompt_camp_channel(), 149)

    def test_bare_enter_takes_the_configured_default(self):
        with patch("builtins.input", return_value=""), patch("builtins.print"):
            self.assertEqual(ns.prompt_camp_channel(), ns.DEFAULT_CAMP_CHANNEL)

    def test_reasks_on_non_numeric_and_non_positive_input(self):
        with patch("builtins.input", side_effect=["abc", "0", "-4", "36"]), \
             patch("builtins.print"):
            self.assertEqual(ns.prompt_camp_channel(), 36)

    def test_channel_outside_the_configured_lists_is_still_accepted(self):
        # The driver is the real authority; the prompt only notes it.
        with patch("builtins.input", return_value="14"), patch("builtins.print"):
            self.assertEqual(ns.prompt_camp_channel(), 14)


class PromptDefaultsTests(unittest.TestCase):
    def test_mode_and_band_prompts_default_to_the_module_constants(self):
        with patch("builtins.input", return_value=""), patch("builtins.print"):
            self.assertEqual(ns.prompt_capture_mode(), ns.DEFAULT_CAPTURE_MODE)
            self.assertEqual(ns.prompt_band(), ns.DEFAULT_BAND)
            self.assertEqual(ns.prompt_interface(), ns.INTERFACE)

    def test_configured_defaults_are_valid_choices(self):
        self.assertIn(ns.DEFAULT_CAPTURE_MODE, ns.CAPTURE_MODES)
        self.assertIn(ns.DEFAULT_BAND, ns.BANDS)


# ---------------------------------------------------------------------------
# Terminal output filtering (--frames / --hide)
# ---------------------------------------------------------------------------

class GatedPacket(WirePacket):
    """WirePacket that also answers the frame-control and SC interfaces.

    _process_frame() reads the sequence-control field through ``pkt[Dot11]``
    and the type/subtype through ``getlayer(Dot11)``, so a packet driven all
    the way through handle_packet() has to satisfy both.
    """

    def __init__(self, subtype, addr2):
        super().__init__(subtype=subtype, addr2=addr2)
        self.type    = 0
        self.subtype = subtype
        self.addr1   = "ff:ff:ff:ff:ff:ff"
        self.SC      = 0

    def __getitem__(self, layer):
        return self

    def getlayer(self, layer, ID=None):
        return self if layer is ns.Dot11 else None

    @property
    def original(self):
        return self._raw


class ResolveHiddenTypesTests(unittest.TestCase):
    """--hide resolves to the set of suppressed labels."""

    def test_default_hides_nothing(self):
        self.assertEqual(ns.resolve_hidden_types(None), frozenset())
        self.assertEqual(ns.resolve_hidden_types(""), frozenset())

    def test_beacon_replaces_the_old_no_beacon_mode(self):
        # --frames no-beacon was the only filter before --hide existed; this is
        # the same behaviour spelled with the flag that replaced it.
        self.assertEqual(ns.resolve_hidden_types("BEACON"),
                         frozenset({"BEACON"}))

    def test_action_group_covers_both_action_subtypes(self):
        # The reason the group exists: there is no ACTION_REQ, and hiding only
        # ACTION leaves ACTION_NOACK on screen.
        self.assertEqual(ns.resolve_hidden_types("action"),
                         frozenset({"ACTION", "ACTION_NOACK"}))

    def test_groups_and_labels_accumulate(self):
        self.assertEqual(ns.resolve_hidden_types("BEACON,action"),
                         frozenset({"BEACON", "ACTION", "ACTION_NOACK"}))

    def test_names_are_case_insensitive_and_whitespace_tolerant(self):
        self.assertEqual(ns.resolve_hidden_types(" beacon , ACTION ,,"),
                         frozenset({"BEACON", "ACTION", "ACTION_NOACK"}))
        self.assertEqual(ns.resolve_hidden_types("Beacon"),
                         ns.resolve_hidden_types("BEACON"))

    def test_explicit_labels_work_alongside_groups(self):
        self.assertEqual(ns.resolve_hidden_types("PROBE_RESP,beacon"),
                         frozenset({"PROBE_RESP", "BEACON"}))

    def test_unknown_name_raises_rather_than_being_ignored(self):
        # A typo that only warned would scroll past and leave the operator
        # watching traffic they believed was hidden.
        with self.assertRaises(ValueError) as caught:
            ns.resolve_hidden_types("ACTION_REQ")
        self.assertIn("ACTION_REQ", str(caught.exception))

    def test_client_and_ap_groups_partition_every_label(self):
        # Both are derived, not written out, so a subtype added to
        # MGMT_SUBTYPE_LABELS lands in exactly one of them with no second edit.
        client = ns.FRAME_TYPE_GROUPS["client"]
        ap     = ns.FRAME_TYPE_GROUPS["ap"]
        labels = frozenset(ns.MGMT_SUBTYPE_LABELS.values())
        self.assertEqual(client, frozenset(ns.CLIENT_FRAME_TYPES))
        self.assertEqual(client | ap, labels)
        self.assertEqual(client & ap, frozenset())

    def test_hiding_every_group_is_expressible(self):
        # The quiet mode main() warns about: CSV only, empty terminal.
        self.assertEqual(ns.resolve_hidden_types("client,ap"),
                         frozenset(ns.MGMT_SUBTYPE_LABELS.values()))


class TerminalHideGateTests(unittest.TestCase):
    """The filter suppresses printing and nothing else."""

    def _run(self, hidden, subtypes):
        """Drive handle_packet() and return (csv_rows, printed_lines)."""
        rows: list = []
        buffer = io.StringIO()
        with patch.object(ns, "_append_csv_row", rows.append), \
             patch.object(ns, "TERMINAL_HIDE_TYPES", frozenset(hidden)), \
             contextlib.redirect_stdout(buffer):
            for index, subtype in enumerate(subtypes):
                ns.handle_packet(GatedPacket(subtype, f"aa:bb:cc:dd:ee:{index:02x}"))
        printed = [line for line in buffer.getvalue().splitlines() if line.strip()]
        return rows, printed

    def test_hidden_frames_still_reach_the_csv(self):
        # The whole safety property of this feature: --hide is a display
        # filter. Capture, fingerprinting and logging must not notice it.
        rows, printed = self._run({"BEACON"}, [8, 4, 13])   # BEACON, PROBE, ACTION
        self.assertEqual(len(rows), 3)
        self.assertEqual(len(printed), 2)
        self.assertNotIn("BEACON", "".join(printed))
        self.assertIn("PROBE", "".join(printed))
        self.assertIn("ACTION", "".join(printed))

    def test_empty_filter_prints_everything(self):
        rows, printed = self._run(set(), [8, 4, 13])
        self.assertEqual(len(rows), 3)
        self.assertEqual(len(printed), 3)

    def test_hiding_every_type_still_logs_every_row(self):
        rows, printed = self._run(ns.MGMT_SUBTYPE_LABELS.values(), [8, 4, 13])
        self.assertEqual(len(rows), 3)
        self.assertEqual(printed, [])

    def test_action_group_silences_both_action_subtypes(self):
        hidden = ns.resolve_hidden_types("action")
        rows, printed = self._run(hidden, [13, 14, 4])   # ACTION, NOACK, PROBE
        self.assertEqual(len(rows), 3)
        self.assertEqual(len(printed), 1)
        self.assertIn("PROBE", printed[0])


class DescribeHiddenTypesTests(unittest.TestCase):
    """The startup line reports the resolved set, not the raw flag."""

    def test_empty_filter_says_so(self):
        with patch.object(ns, "TERMINAL_HIDE_TYPES", frozenset()):
            self.assertEqual(ns._describe_hidden_types(),
                             "showing all 16 frame types")

    def test_hidden_types_are_listed_sorted(self):
        # Sorted so two runs with the same filter produce identical lines.
        with patch.object(ns, "TERMINAL_HIDE_TYPES",
                          frozenset({"BEACON", "ACTION", "ACTION_NOACK"})):
            self.assertEqual(ns._describe_hidden_types(),
                             "hiding ACTION, ACTION_NOACK, BEACON (3 of 16)")


if __name__ == "__main__":
    unittest.main()
