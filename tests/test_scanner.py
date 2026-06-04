import subprocess
from unittest.mock import MagicMock, patch

import pytest

from wifi_auto_test.core.models import WiFiNetwork
from wifi_auto_test.scanner.wash_scanner import IwScanner


@pytest.fixture
def iw_scanner(mock_process_runner, mock_parser):
    return IwScanner("wlan0", mock_parser, mock_process_runner, scan_interval=5)


class TestFindInterfaces:
    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    def test_find_interfaces_via_iwconfig(self, mock_run, iw_scanner):
        mock_run.return_value.stdout = (
            "lo        no wireless extensions.\n\n"
            "eth0      no wireless extensions.\n\n"
            "wlan0     IEEE 802.11  ESSID:off/any\n"
            "          Mode:Managed  Frequency:2.452 GHz\n\n"
            "wlan1mon  IEEE 802.11  Mode:Monitor  Frequency:2.412 GHz\n"
        )
        mock_run.return_value.returncode = 0

        result = sorted(iw_scanner._find_interfaces())
        assert result == ["wlan0", "wlan1mon"]

    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    @patch("wifi_auto_test.scanner.wash_scanner.os.listdir")
    @patch("wifi_auto_test.scanner.wash_scanner.os.path.exists")
    def test_find_interfaces_fallback_sysfs(self, mock_exists, mock_listdir, mock_run, iw_scanner):
        # iwconfig fails -> fallback to sysfs
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="lo        no wireless extensions.\n"),
        ]
        mock_listdir.return_value = ["eth0", "wlan0", "wlan1mon", "lo"]
        def exists_side(path):
            if "wireless" in path and "wlan0" in path:
                return True
            if "type" in path:
                return True
            return False
        mock_exists.side_effect = exists_side

        result = iw_scanner._find_interfaces()
        assert "wlan0" in result

    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    @patch("wifi_auto_test.scanner.wash_scanner.os.listdir")
    @patch("wifi_auto_test.scanner.wash_scanner.os.path.exists")
    def test_find_interfaces_all_fail(self, mock_exists, mock_listdir, mock_run, iw_scanner):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""
        mock_listdir.side_effect = OSError

        result = iw_scanner._find_interfaces()
        assert result == []


class TestGetInterfaceMode:
    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    def test_get_mode_monitor_via_iwconfig(self, mock_run, iw_scanner):
        mock_run.return_value.stdout = (
            "wlan1mon  IEEE 802.11  Mode:Monitor  Tx-Power=20 dBm\n"
        )
        mock_run.return_value.returncode = 0

        assert iw_scanner._get_interface_mode("wlan1mon") == "monitor"

    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    def test_get_mode_managed_via_iwconfig(self, mock_run, iw_scanner):
        mock_run.return_value.stdout = (
            "wlan0     IEEE 802.11  ESSID:off/any  Mode:Managed  Frequency:2.452 GHz\n"
        )
        mock_run.return_value.returncode = 0

        assert iw_scanner._get_interface_mode("wlan0") == "managed"

    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    def test_get_mode_iwconfig_fails_falls_back_to_iw_dev(self, mock_run, iw_scanner):
        fail = MagicMock(returncode=1)
        ok = MagicMock(
            returncode=0,
            stdout=(
                "Interface wlan1mon\n\tifindex 4\n\twdev 0x1\n"
                "\taddr 00:11:22:33:44:55\n\ttype monitor\n\twiphy 0\n"
            ),
        )
        mock_run.side_effect = [fail, ok]

        assert iw_scanner._get_interface_mode("wlan1mon") == "monitor"

    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    def test_get_mode_both_fail_falls_back_to_sysfs(self, mock_run, iw_scanner):
        mock_run.return_value.returncode = 1
        mock_file = MagicMock()
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_file.read.return_value = "803"
        with patch("builtins.open", return_value=mock_file):
            assert iw_scanner._get_interface_mode("wlan1mon") == "monitor"


class TestFindMonitorInterface:
    @patch.object(IwScanner, "_find_interfaces")
    @patch.object(IwScanner, "_get_interface_mode")
    def test_finds_monitor(self, mock_mode, mock_find, iw_scanner):
        mock_find.return_value = ["wlan0", "wlan1mon"]
        mock_mode.side_effect = ["managed", "monitor"]

        result = iw_scanner._find_monitor_interface()
        assert result == "wlan1mon"

    @patch.object(IwScanner, "_find_interfaces")
    @patch.object(IwScanner, "_get_interface_mode")
    def test_no_monitor_found(self, mock_mode, mock_find, iw_scanner):
        mock_find.return_value = ["wlan0"]
        mock_mode.return_value = "managed"

        result = iw_scanner._find_monitor_interface()
        assert result is None


class TestEnsureMonitor:
    @patch.object(IwScanner, "_get_interface_mode")
    @patch.object(IwScanner, "_bring_up")
    def test_already_monitor(self, mock_up, mock_mode, iw_scanner):
        mock_mode.return_value = "monitor"

        result = iw_scanner._ensure_monitor()
        assert result == "wlan0"
        mock_up.assert_called_once_with("wlan0")

    @patch.object(IwScanner, "_get_interface_mode")
    @patch.object(IwScanner, "_find_monitor_interface")
    @patch.object(IwScanner, "_bring_up")
    def test_finds_existing_monitor(self, mock_up, mock_find, mock_mode, iw_scanner):
        mock_mode.side_effect = ["managed", "monitor"]
        mock_find.return_value = "wlan1mon"

        result = iw_scanner._ensure_monitor()
        assert result == "wlan1mon"
        mock_up.assert_called_once_with("wlan1mon")

    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    @patch.object(IwScanner, "_get_interface_mode")
    @patch.object(IwScanner, "_find_monitor_interface")
    def test_airmon_fallback(self, mock_find, mock_mode, mock_subprocess, iw_scanner):
        mock_mode.side_effect = ["managed", "unknown", "monitor"]
        mock_find.side_effect = [None, "wlan0mon"]

        result = iw_scanner._ensure_monitor()
        assert result == "wlan0mon"
        mock_subprocess.assert_any_call(
            ["sudo", "airmon-ng", "start", "wlan0"],
            capture_output=True,
        )

    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    @patch.object(IwScanner, "_get_interface_mode")
    @patch.object(IwScanner, "_find_monitor_interface")
    def test_iw_fallback(self, mock_find, mock_mode, mock_subprocess, iw_scanner):
        mock_mode.side_effect = ["managed", "monitor"]
        mock_find.side_effect = [None, None]

        result = iw_scanner._ensure_monitor()
        assert result == "wlan0"


class TestParseIwScan:
    def test_parse_single_network(self, iw_scanner):
        raw = (
            "BSS 00:11:22:33:44:55\n"
            "\tSSID: MyNet\n"
            "\tsignal: -55.50 dBm\n"
            "\tDS Parameter set: channel 6\n"
            "\tRSN:\t* Version: 1\n"
        )
        nets = iw_scanner._parse_iw_scan(raw)
        assert len(nets) == 1
        assert nets[0].bssid == "00:11:22:33:44:55"
        assert nets[0].ssid == "MyNet"
        assert nets[0].channel == 6
        assert nets[0].signal_dbm == -55
        assert nets[0].security == "WPA2"

    def test_parse_multiple_networks(self, iw_scanner):
        raw = (
            "BSS 00:11:22:33:44:01\n\tSSID: Net1\n\tsignal: -40.00 dBm\n"
            "\tDS Parameter set: channel 1\n\tRSN:\n"
            "BSS 00:11:22:33:44:02\n\tSSID: Net2\n\tsignal: -70.00 dBm\n"
            "\tDS Parameter set: channel 11\n\tPrivacy:\n"
        )
        nets = iw_scanner._parse_iw_scan(raw)
        assert len(nets) == 2
        assert nets[0].ssid == "Net1"
        assert nets[0].security == "WPA2"
        assert nets[1].ssid == "Net2"
        assert nets[1].security == "WEP"

    def test_parse_no_networks(self, iw_scanner):
        assert iw_scanner._parse_iw_scan("") == []

    def test_parse_missing_channel_defaults_zero(self, iw_scanner):
        raw = "BSS 00:11:22:33:44:55\n\tSSID: NoCh\n\tsignal: -60 dBm\n"
        nets = iw_scanner._parse_iw_scan(raw)
        assert nets[0].channel == 0
        assert nets[0].security == "UNKNOWN"


class TestScan:
    @patch.object(IwScanner, "_ensure_monitor")
    @patch.object(IwScanner, "_bring_up")
    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    def test_scan_success(self, mock_run, mock_up, mock_ensure, iw_scanner):
        mock_ensure.return_value = "wlan1mon"
        mock_run.return_value.stdout = (
            "BSS 00:11:22:33:44:55\n\tSSID: FoundNet\n"
            "\tsignal: -50.00 dBm\n\tDS Parameter set: channel 6\n\tRSN:\n"
        )
        mock_run.return_value.returncode = 0

        result = iw_scanner.scan()
        assert len(result) == 1
        assert result[0].ssid == "FoundNet"
        mock_up.assert_called_once_with("wlan1mon")

    @patch.object(IwScanner, "_ensure_monitor")
    def test_scan_no_monitor_interface(self, mock_ensure, iw_scanner):
        mock_ensure.return_value = None
        result = iw_scanner.scan()
        assert result == []

    @patch.object(IwScanner, "_ensure_monitor")
    @patch.object(IwScanner, "_bring_up")
    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    def test_scan_network_is_down_retry(self, mock_run, mock_up, mock_ensure, iw_scanner):
        mock_ensure.return_value = "wlan1mon"
        # first call fails with Network is down
        fail = MagicMock()
        fail.returncode = 1
        fail.stderr = "command failed: Network is down (-100)"
        # second call succeeds
        success = MagicMock()
        success.returncode = 0
        success.stdout = (
            "BSS 00:11:22:33:44:55\n\tSSID: RetryNet\n"
            "\tsignal: -50.00 dBm\n\tDS Parameter set: channel 1\n\tRSN:\n"
        )
        mock_run.side_effect = [fail, success]

        result = iw_scanner.scan()
        assert len(result) == 1
        assert result[0].ssid == "RetryNet"
        assert mock_up.call_count == 2  # once before scan, once after failure

    @patch.object(IwScanner, "_ensure_monitor")
    @patch.object(IwScanner, "_bring_up")
    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    def test_scan_complete_failure(self, mock_run, mock_up, mock_ensure, iw_scanner, capsys):
        mock_ensure.return_value = "wlan1mon"
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "some fatal error"

        result = iw_scanner.scan()
        assert result == []
        captured = capsys.readouterr()
        assert "iw scan failed" in captured.out

    @patch.object(IwScanner, "_ensure_monitor")
    @patch.object(IwScanner, "_bring_up")
    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    def test_scan_iwlist_fallback_on_eopnotsupp_stderr(self, mock_run, mock_up, mock_ensure, iw_scanner):
        mock_ensure.return_value = "wlan1mon"
        fail = MagicMock()
        fail.returncode = 1
        fail.stderr = "command failed: Operation not supported (-95)"
        fail.stdout = ""
        # second call: iwlist scan succeeds
        success = MagicMock()
        success.returncode = 0
        success.stdout = (
            "Cell 01 - Address: 00:11:22:33:44:55\n"
            "\tESSID:\"FallbackNet\"\n"
            "\tFrequency:2.437 GHz (Channel 6)\n"
            "\tQuality=70/70  Signal level=-30 dBm\n"
            "\tEncryption key:on\n"
            "\tWPA2\n"
        )
        mock_run.side_effect = [fail, success]

        result = iw_scanner.scan()
        assert len(result) == 1
        assert result[0].ssid == "FallbackNet"
        assert result[0].bssid == "00:11:22:33:44:55"
        assert result[0].channel == 6
        assert result[0].signal_dbm == -30
        assert result[0].security == "WPA2"
        mock_run.assert_any_call(
            ["sudo", "iwlist", "wlan1mon", "scan"],
            capture_output=True, text=True, timeout=5,
        )

    @patch.object(IwScanner, "_ensure_monitor")
    @patch.object(IwScanner, "_bring_up")
    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    def test_scan_iwlist_fallback_on_eopnotsupp_stdout(self, mock_run, mock_up, mock_ensure, iw_scanner):
        mock_ensure.return_value = "wlan1mon"
        fail = MagicMock()
        fail.returncode = 1
        fail.stderr = ""
        fail.stdout = "wlan1mon  Interface doesn't support scanning : Operation not supported"
        # second call: iwlist scan succeeds
        success = MagicMock()
        success.returncode = 0
        success.stdout = (
            "Cell 01 - Address: 00:11:22:33:44:55\n"
            "\tESSID:\"FallbackNetStdout\"\n"
            "\tFrequency:2.437 GHz (Channel 6)\n"
            "\tQuality=70/70  Signal level=-30 dBm\n"
            "\tEncryption key:on\n"
            "\tWPA2\n"
        )
        mock_run.side_effect = [fail, success]

        result = iw_scanner.scan()
        assert len(result) == 1
        assert result[0].ssid == "FallbackNetStdout"

    @patch.object(IwScanner, "_ensure_monitor")
    @patch.object(IwScanner, "_bring_up")
    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    def test_scan_iwlist_fallback_on_lowercase_eopnotsupp(self, mock_run, mock_up, mock_ensure, iw_scanner):
        mock_ensure.return_value = "wlan1mon"
        fail = MagicMock()
        fail.returncode = 1
        fail.stderr = "command failed: operation not supported"
        fail.stdout = ""
        success = MagicMock()
        success.returncode = 0
        success.stdout = (
            "Cell 01 - Address: AA:BB:CC:DD:EE:FF\n"
            "\tESSID:\"OpenNet\"\n"
            "\tFrequency:2.412 GHz (Channel 1)\n"
            "\tQuality=50/70  Signal level=-50 dBm\n"
            "\tEncryption key:off\n"
        )
        mock_run.side_effect = [fail, success]

        result = iw_scanner.scan()
        assert len(result) == 1
        assert result[0].ssid == "OpenNet"
        assert result[0].security == "OPEN"

    @patch.object(IwScanner, "_ensure_monitor")
    @patch.object(IwScanner, "_bring_up")
    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    def test_scan_iwlist_fallback_fails_returns_empty(self, mock_run, mock_up, mock_ensure, iw_scanner):
        mock_ensure.return_value = "wlan1mon"
        fail1 = MagicMock()
        fail1.returncode = 1
        fail1.stderr = "command failed: Operation not supported (-95)"
        fail1.stdout = ""
        fail2 = MagicMock()
        fail2.returncode = 1
        fail2.stdout = ""
        fail2.stderr = "interface has no scan results"
        mock_run.side_effect = [fail1, fail2]

        result = iw_scanner.scan()
        assert result == []


class TestParseIwlistScan:
    def test_parse_single_network_wpa2(self, iw_scanner):
        raw = (
            "Cell 01 - Address: 00:11:22:33:44:55\n"
            "\tESSID:\"TestNet\"\n"
            "\tFrequency:2.437 GHz (Channel 6)\n"
            "\tQuality=70/70  Signal level=-40 dBm\n"
            "\tEncryption key:on\n"
            "\tIE: IEEE 802.11i/WPA2 Version 1\n"
        )
        nets = iw_scanner._parse_iwlist_scan(raw)
        assert len(nets) == 1
        assert nets[0].ssid == "TestNet"
        assert nets[0].bssid == "00:11:22:33:44:55"
        assert nets[0].channel == 6
        assert nets[0].signal_dbm == -40
        assert nets[0].security == "WPA2"

    def test_parse_multiple_networks(self, iw_scanner):
        raw = (
            "Cell 01 - Address: 00:11:22:33:44:01\n"
            "\tESSID:\"Net1\"\n"
            "\tFrequency:2.412 GHz (Channel 1)\n"
            "\tQuality=60/70  Signal level=-50 dBm\n"
            "\tEncryption key:on\n"
            "\tWPA Version 1\n"
            "Cell 02 - Address: 00:11:22:33:44:02\n"
            "\tESSID:\"Net2\"\n"
            "\tFrequency:2.452 GHz (Channel 11)\n"
            "\tQuality=70/70  Signal level=-30 dBm\n"
            "\tEncryption key:on\n"
            "\tIE: IEEE 802.11i/WPA2 Version 1\n"
        )
        nets = iw_scanner._parse_iwlist_scan(raw)
        assert len(nets) == 2
        assert nets[0].ssid == "Net1"
        assert nets[0].security == "WPA"
        assert nets[1].ssid == "Net2"
        assert nets[1].security == "WPA2"

    def test_parse_open_network(self, iw_scanner):
        raw = (
            "Cell 01 - Address: AA:BB:CC:DD:EE:FF\n"
            "\tESSID:\"FreeWiFi\"\n"
            "\tFrequency:2.437 GHz (Channel 6)\n"
            "\tQuality=70/70  Signal level=-35 dBm\n"
            "\tEncryption key:off\n"
        )
        nets = iw_scanner._parse_iwlist_scan(raw)
        assert len(nets) == 1
        assert nets[0].ssid == "FreeWiFi"
        assert nets[0].security == "OPEN"

    def test_parse_quality_only_no_dbm_defaults_minus_100(self, iw_scanner):
        raw = (
            "Cell 01 - Address: 00:11:22:33:44:55\n"
            "\tESSID:\"QualityOnly\"\n"
            "\tFrequency:2.412 GHz (Channel 1)\n"
            "\tQuality=35/70\n"
            "\tEncryption key:on\n"
        )
        nets = iw_scanner._parse_iwlist_scan(raw)
        assert len(nets) == 1
        assert nets[0].ssid == "QualityOnly"
        assert nets[0].signal_dbm == -100  # no Signal level=... dBm found


class TestParseAirodumpCsv:
    def test_parse_single_network_wpa2(self, iw_scanner, tmp_path):
        csv_content = (
            "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
            "00:11:22:33:44:55, 2024-01-01 00:00:00, 2024-01-01 00:00:10, 6, 54, WPA2, CCMP, PSK, -45, 100, 0, 0.0.0.0, 7, TestNet, \n"
        )
        csv_file = tmp_path / "test-01.csv"
        csv_file.write_text(csv_content, encoding="utf-8")
        nets = iw_scanner._parse_airodump_csv(str(csv_file))
        assert len(nets) == 1
        assert nets[0].bssid == "00:11:22:33:44:55"
        assert nets[0].ssid == "TestNet"
        assert nets[0].channel == 6
        assert nets[0].signal_dbm == -45
        assert nets[0].security == "WPA2"

    def test_parse_multiple_networks(self, iw_scanner, tmp_path):
        csv_content = (
            "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
            "00:11:22:33:44:01, 2024-01-01 00:00:00, 2024-01-01 00:00:10, 1, 54, WPA2, CCMP, PSK, -50, 100, 0, 0.0.0.0, 4, Net1, \n"
            "00:11:22:33:44:02, 2024-01-01 00:00:00, 2024-01-01 00:00:10, 11, 54, WPA, TKIP, PSK, -70, 80, 0, 0.0.0.0, 4, Net2, \n"
            "00:11:22:33:44:03, 2024-01-01 00:00:00, 2024-01-01 00:00:10, 6, 54, OPN, , , -35, 200, 0, 0.0.0.0, 6, FreeWiFi, \n"
        )
        csv_file = tmp_path / "test-01.csv"
        csv_file.write_text(csv_content, encoding="utf-8")
        nets = iw_scanner._parse_airodump_csv(str(csv_file))
        assert len(nets) == 3
        assert nets[0].ssid == "Net1"
        assert nets[0].security == "WPA2"
        assert nets[1].ssid == "Net2"
        assert nets[1].security == "WPA"
        assert nets[2].ssid == "FreeWiFi"
        assert nets[2].security == "OPEN"

    def test_parse_skips_header_and_blank(self, iw_scanner, tmp_path):
        csv_content = (
            "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
            "\n"
            "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n"
            "AA:BB:CC:DD:EE:FF, 2024-01-01 00:00:00, 2024-01-01 00:00:10, -40, 5, 00:11:22:33:44:55, \n"
        )
        csv_file = tmp_path / "test-01.csv"
        csv_file.write_text(csv_content, encoding="utf-8")
        nets = iw_scanner._parse_airodump_csv(str(csv_file))
        assert len(nets) == 0

    def test_parse_missing_file_returns_empty(self, iw_scanner):
        nets = iw_scanner._parse_airodump_csv("/nonexistent/path.csv")
        assert nets == []


class TestWashScannerAlias:
    def test_wash_scanner_is_iw_scanner(self):
        from wifi_auto_test.scanner.wash_scanner import WashScanner
        assert WashScanner is IwScanner
