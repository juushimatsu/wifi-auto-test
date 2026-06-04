from unittest.mock import MagicMock, patch, call

import pytest

from wifi_auto_test.ap_manager.linux_ap import LinuxAPManager


@pytest.fixture
def ap_manager():
    return LinuxAPManager(logger=lambda x: None)


class TestSetupAP:
    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_setup_ap_success(self, mock_run, ap_manager):
        # disconnect ok, delete ok (or fail silently), add ok, up ok
        mock_run.side_effect = [
            MagicMock(returncode=0),                          # disconnect
            MagicMock(returncode=0, stderr=""),               # delete
            MagicMock(returncode=0, stderr="", stdout=""),     # add
            MagicMock(returncode=0, stderr=""),               # up
        ]

        result = ap_manager.setup_ap("wlan0", "TestAP", "password123", "192.168.50.1/24", "192.168.50.10,192.168.50.100")
        assert result is True
        assert ap_manager._interface == "wlan0"

        # Verify disconnect called first
        mock_run.assert_any_call(
            ["sudo", "nmcli", "device", "disconnect", "wlan0"],
            capture_output=True,
        )
        # Verify up with explicit ifname
        mock_run.assert_any_call(
            ["sudo", "nmcli", "connection", "up", ap_manager._con_name, "ifname", "wlan0"],
            capture_output=True, text=True,
        )

    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_setup_ap_add_fails(self, mock_run, ap_manager):
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=1, stderr="not found"),
            MagicMock(returncode=1, stderr="Error: invalid setting"),
        ]

        result = ap_manager.setup_ap("wlan0", "TestAP", "pass", "10.0.0.1/24", "10.0.0.10,10.0.0.100")
        assert result is False

    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_setup_ap_up_fails(self, mock_run, ap_manager):
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stderr=""),
            MagicMock(returncode=0, stderr="", stdout=""),
            MagicMock(returncode=1, stderr="Error: Connection activation failed"),
        ]

        result = ap_manager.setup_ap("wlan0", "TestAP", "pass", "10.0.0.1/24", "10.0.0.10,10.0.0.100")
        assert result is False

    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_setup_ap_ssid_with_spaces(self, mock_run, ap_manager):
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stderr=""),
            MagicMock(returncode=0, stderr="", stdout=""),
            MagicMock(returncode=0, stderr=""),
        ]

        result = ap_manager.setup_ap("wlan0", "My Test AP", "pass123", "10.0.0.1/24", "10.0.0.10,10.0.0.100")
        assert result is True
        # con-name should have dashes instead of spaces, truncated to 20 chars
        assert ap_manager._con_name == "wifi-auto-test-My-Test-AP"


class TestStopAP:
    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_stop_ap_success(self, mock_run, ap_manager):
        ap_manager._con_name = "wifi-auto-test-TestAP"
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0),
        ]

        result = ap_manager.stop_ap()
        assert result is True
        assert ap_manager._con_name == ""
        mock_run.assert_has_calls([
            call(["sudo", "nmcli", "connection", "down", "wifi-auto-test-TestAP"], capture_output=True),
            call(["sudo", "nmcli", "connection", "delete", "wifi-auto-test-TestAP"], capture_output=True),
        ])

    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_stop_ap_no_con_name(self, mock_run, ap_manager):
        ap_manager._con_name = ""
        result = ap_manager.stop_ap()
        assert result is True
        mock_run.assert_not_called()


class TestIsClientConnected:
    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_is_connected_true(self, mock_run, ap_manager):
        ap_manager._con_name = "wifi-auto-test-TestAP"
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = (
            "NAME              UUID                                  TYPE      DEVICE\n"
            "wifi-auto-test-TestAP  abc-def-123  wifi  wlan0\n"
        )

        assert ap_manager.is_client_connected() is True

    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_is_connected_false(self, mock_run, ap_manager):
        ap_manager._con_name = "wifi-auto-test-TestAP"
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "NAME  UUID  TYPE  DEVICE\n"

        assert ap_manager.is_client_connected() is False

    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_is_connected_no_con_name(self, mock_run, ap_manager):
        ap_manager._con_name = ""
        assert ap_manager.is_client_connected() is False
        mock_run.assert_not_called()

    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_is_connected_nmcli_fails(self, mock_run, ap_manager):
        ap_manager._con_name = "wifi-auto-test-TestAP"
        mock_run.return_value.returncode = 1

        assert ap_manager.is_client_connected() is False
