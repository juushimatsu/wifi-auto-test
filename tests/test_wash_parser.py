import pytest

from wifi_auto_test.core.models import WiFiNetwork
from wifi_auto_test.scanner.wash_parser import WashParser


@pytest.fixture
def parser():
    return WashParser()


class TestWashParser:
    def test_parse_valid_wpa2(self, parser):
        line = "14:9D:09:3C:9E:30  -72  11  270   WPA2  testnet"
        result = parser.parse(line)
        assert result is not None
        assert result.bssid == "14:9D:09:3C:9E:30"
        assert result.ssid == "testnet"
        assert result.channel == 11
        assert result.signal_dbm == -72
        assert result.security == "WPA2"

    def test_parse_valid_wep(self, parser):
        line = "00:11:22:33:44:55  -50   6  54    WEP   oldnet"
        result = parser.parse(line)
        assert result is not None
        assert result.security == "WEP"
        assert result.ssid == "oldnet"

    def test_parse_open_network(self, parser):
        line = "AA:BB:CC:DD:EE:FF  -80   1  54    OPEN  FreeWiFi"
        result = parser.parse(line)
        assert result is not None
        assert result.security == "OPEN"
        assert result.ssid == "FreeWiFi"

    def test_parse_ssid_with_spaces(self, parser):
        line = "AA:BB:CC:DD:EE:FF  -60   1  150   WPA2  My Home Network"
        result = parser.parse(line)
        assert result is not None
        assert result.ssid == "My Home Network"

    def test_parse_empty_ssid(self, parser):
        line = "AA:BB:CC:DD:EE:FF  -60   1  150   WPA2  "
        result = parser.parse(line)
        assert result is not None
        assert result.ssid == ""

    def test_parse_hidden_ssid(self, parser):
        line = "AA:BB:CC:DD:EE:FF  -60   1  150   WPA2  <length:  0>"
        result = parser.parse(line)
        assert result is not None
        assert result.ssid == "<length:  0>"

    def test_parse_weak_signal(self, parser):
        line = "AA:BB:CC:DD:EE:FF  -95  13  54    WPA2  faraway"
        result = parser.parse(line)
        assert result.signal_dbm == -95

    def test_parse_strong_signal(self, parser):
        line = "AA:BB:CC:DD:EE:FF  -20   6  300   WPA3  nearby"
        result = parser.parse(line)
        assert result.signal_dbm == -20

    def test_parse_invalid_line_returns_none(self, parser):
        assert parser.parse("random text") is None
        assert parser.parse("") is None
        assert parser.parse("BSSID  RSSI  CH  RATE  ENC  ESSID") is None
        assert parser.parse("not:a:valid:bssid -50 6 54 WPA2 test") is None

    def test_parse_lowercase_bssid(self, parser):
        line = "aa:bb:cc:dd:ee:ff  -50   6  54    WPA2  lower"
        result = parser.parse(line)
        assert result is not None
        assert result.bssid == "aa:bb:cc:dd:ee:ff"

    def test_parse_leading_trailing_whitespace(self, parser):
        line = "  14:9D:09:3C:9E:30  -72  11  270   WPA2  testnet  "
        result = parser.parse(line)
        assert result is not None
        assert result.ssid == "testnet"
