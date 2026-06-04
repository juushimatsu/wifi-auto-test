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
    def test_find_interfaces_via_iw_dev(self, mock_run, iw_scanner):
        mock_run.return_value.stdout = (
            "phy#0\n\tInterface wlan0\n\t\tifindex 3\n"
            "\tInterface wlan1mon\n\t\tifindex 4\n"
        )
        mock_run.return_value.returncode = 0

        result = iw_scanner._find_interfaces()
        assert result == ["wlan0", "wlan1mon"]

    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    def test_find_interfaces_iw_dev_fails(self, mock_run, iw_scanner):
        mock_run.return_value.stdout = ""
        mock_run.return_value.returncode = 1

        result = iw_scanner._find_interfaces()
        assert result == []


class TestGetInterfaceMode:
    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    def test_get_mode_monitor(self, mock_run, iw_scanner):
        mock_run.return_value.stdout = (
            "Interface wlan1mon\n\tifindex 4\n\twdev 0x1\n\taddr 00:11:22:33:44:55\n"
            "\ttype monitor\n\twiphy 0\n"
        )
        mock_run.return_value.returncode = 0

        assert iw_scanner._get_interface_mode("wlan1mon") == "monitor"

    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    def test_get_mode_managed(self, mock_run, iw_scanner):
        mock_run.return_value.stdout = (
            "Interface wlan0\n\tifindex 3\n\twdev 0x1\n\taddr 00:11:22:33:44:55\n"
            "\ttype managed\n\twiphy 0\n"
        )
        mock_run.return_value.returncode = 0

        assert iw_scanner._get_interface_mode("wlan0") == "managed"

    @patch("wifi_auto_test.scanner.wash_scanner.subprocess.run")
    def test_get_mode_iw_falls_back_to_sysfs(self, mock_run, iw_scanner):
        mock_run.return_value.returncode = 1
        with patch("builtins.open", return_value=MagicMock(read=MagicMock(return_value="803"))):
            with patch("wifi_auto_test.scanner.wash_scanner.os.path.exists", return_value=True):
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
        mock_mode.side_effect = ["managed", "unknown", "unknown", "monitor"]
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
        assert nets[0].encryption == "WPA2"

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
        assert nets[0].encryption == "WPA2"
        assert nets[1].ssid == "Net2"
        assert nets[1].encryption == "WEP"

    def test_parse_no_networks(self, iw_scanner):
        assert iw_scanner._parse_iw_scan("") == []

    def test_parse_missing_channel_defaults_zero(self, iw_scanner):
        raw = "BSS 00:11:22:33:44:55\n\tSSID: NoCh\n\tsignal: -60 dBm\n"
        nets = iw_scanner._parse_iw_scan(raw)
        assert nets[0].channel == 0
        assert nets[0].encryption == "UNKNOWN"


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


class TestWashScannerAlias:
    def test_wash_scanner_is_iw_scanner(self):
        from wifi_auto_test.scanner.wash_scanner import WashScanner
        assert WashScanner is IwScanner
