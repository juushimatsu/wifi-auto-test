from unittest.mock import MagicMock, patch, call

import pytest

from wifi_auto_test.ap_manager.linux_ap import LinuxAPManager


@pytest.fixture
def ap_manager():
    return LinuxAPManager(logger=lambda x: None)


class TestSupportsAP:
    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_supports_ap_true(self, mock_run, ap_manager):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "\t	* AP/VLAN"

        assert ap_manager._supports_ap_via_nm("wlan0") is True

    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_supports_ap_false(self, mock_run, ap_manager):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "\t	* managed"

        assert ap_manager._supports_ap_via_nm("wlan0") is False

    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_supports_ap_iw_fails(self, mock_run, ap_manager):
        mock_run.return_value.returncode = 1

        assert ap_manager._supports_ap_via_nm("wlan0") is False


class TestSetupAPNmcli:
    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_setup_ap_success(self, mock_run, ap_manager):
        # disconnect ok, delete ok (or fail silently), add ok, up ok
        mock_run.side_effect = [
            MagicMock(returncode=0),                          # disconnect
            MagicMock(returncode=0, stderr=""),               # delete
            MagicMock(returncode=0, stderr="", stdout=""),     # add
            MagicMock(returncode=0, stderr=""),               # up
        ]

        result = ap_manager._setup_ap_nmcli("wlan0", "TestAP", "password123")
        assert result is True

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

        result = ap_manager._setup_ap_nmcli("wlan0", "TestAP", "pass")
        assert result is False

    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_setup_ap_up_fails(self, mock_run, ap_manager):
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stderr=""),
            MagicMock(returncode=0, stderr="", stdout=""),
            MagicMock(returncode=1, stderr="Error: Connection activation failed"),
        ]

        result = ap_manager._setup_ap_nmcli("wlan0", "TestAP", "pass")
        assert result is False

    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_setup_ap_ssid_with_spaces(self, mock_run, ap_manager):
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stderr=""),
            MagicMock(returncode=0, stderr="", stdout=""),
            MagicMock(returncode=0, stderr=""),
        ]

        result = ap_manager._setup_ap_nmcli("wlan0", "My Test AP", "pass123")
        assert result is True
        # con-name should have dashes instead of spaces, truncated to 20 chars
        assert ap_manager._con_name == "wifi-auto-test-My-Test-AP"


class TestSetupAPHostapd:
    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.Popen")
    @patch("wifi_auto_test.ap_manager.linux_ap.open")
    def test_setup_ap_hostapd_success(self, mock_open, mock_popen, mock_run, ap_manager):
        mock_run.side_effect = [
            MagicMock(returncode=0),  # nmcli disconnect
            MagicMock(returncode=0),  # nmcli set managed no
            MagicMock(returncode=0),  # pkill hostapd
            MagicMock(returncode=0),  # pkill dnsmasq
            MagicMock(returncode=0),  # ip addr flush
            MagicMock(returncode=0),  # ip addr add
            MagicMock(returncode=0),  # ip link set up
            MagicMock(returncode=0),  # dnsmasq
            MagicMock(returncode=0),  # iptables
        ]
        proc = MagicMock()
        proc.poll.return_value = None  # still running
        mock_popen.return_value = proc

        result = ap_manager._setup_ap_hostapd(
            "wlan0", "TestAP", "pass123",
            "192.168.50.1/24", "192.168.50.10,192.168.50.100"
        )
        assert result is True
        mock_popen.assert_called_once()

    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.Popen")
    @patch("wifi_auto_test.ap_manager.linux_ap.open")
    def test_setup_ap_hostapd_fails(self, mock_open, mock_popen, mock_run, ap_manager):
        # Enough mocks for hostapd setup + airbase-ng fallback path, then default (returncode=0)
        mock_run.side_effect = [
            MagicMock(returncode=0),  # nmcli disconnect (hostapd)
            MagicMock(returncode=0),  # nmcli set managed no
            MagicMock(returncode=0),  # pkill hostapd
            MagicMock(returncode=0),  # pkill dnsmasq
            MagicMock(returncode=0),  # ip addr flush
            MagicMock(returncode=0),  # ip addr add
            MagicMock(returncode=0),  # ip link set up
            # airbase-ng fallback:
            MagicMock(returncode=0),  # nmcli disconnect
            MagicMock(returncode=0),  # nmcli set managed no
            MagicMock(returncode=0),  # pkill airbase-ng
            MagicMock(returncode=0),  # pkill dnsmasq at0
            MagicMock(returncode=0),  # ip link down
            MagicMock(returncode=0),  # iwconfig mode monitor
            MagicMock(returncode=0),  # iw dev set type monitor
            MagicMock(returncode=0),  # ip link up
            MagicMock(returncode=0),  # ip addr flush at0
            MagicMock(returncode=0),  # ip addr add at0
            MagicMock(returncode=0),  # ip link up at0
            MagicMock(returncode=0),  # dnsmasq at0
            MagicMock(returncode=0),  # iptables
        ]
        proc = MagicMock()
        proc.poll.return_value = 1  # exited immediately -> failure
        mock_popen.return_value = proc  # nl80211, wext, airbase-ng all fail

        result = ap_manager._setup_ap_hostapd(
            "wlan0", "TestAP", "pass123",
            "192.168.50.1/24", "192.168.50.10,192.168.50.100"
        )
        assert result is False

    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.Popen")
    @patch("wifi_auto_test.ap_manager.linux_ap.open")
    def test_setup_ap_hostapd_wext_fallback(self, mock_open, mock_popen, mock_run, ap_manager):
        mock_run.side_effect = [
            MagicMock(returncode=0),  # nmcli disconnect
            MagicMock(returncode=0),  # nmcli set managed no
            MagicMock(returncode=0),  # pkill hostapd
            MagicMock(returncode=0),  # pkill dnsmasq
            MagicMock(returncode=0),  # ip addr flush
            MagicMock(returncode=0),  # ip addr add
            MagicMock(returncode=0),  # ip link set up
            MagicMock(returncode=0),  # dnsmasq
            MagicMock(returncode=0),  # iptables
        ]
        proc_fail = MagicMock()
        proc_fail.poll.return_value = 1  # nl80211 fails
        proc_ok = MagicMock()
        proc_ok.poll.return_value = None  # wext succeeds
        mock_popen.side_effect = [proc_fail, proc_ok]

        result = ap_manager._setup_ap_hostapd(
            "wlan0", "TestAP", "pass123",
            "192.168.50.1/24", "192.168.50.10,192.168.50.100"
        )
        assert result is True
        assert mock_popen.call_count == 2

    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.Popen")
    @patch("wifi_auto_test.ap_manager.linux_ap.open")
    def test_setup_ap_airbase_ng_fallback(self, mock_open, mock_popen, mock_run, ap_manager):
        """hostapd fails both nl80211 and wext -> airbase-ng fallback works."""
        mock_run.side_effect = [
            MagicMock(returncode=0),  # nmcli disconnect (hostapd setup)
            MagicMock(returncode=0),  # nmcli set managed no
            MagicMock(returncode=0),  # pkill hostapd
            MagicMock(returncode=0),  # pkill dnsmasq
            MagicMock(returncode=0),  # ip addr flush
            MagicMock(returncode=0),  # ip addr add
            MagicMock(returncode=0),  # ip link set up
            # airbase-ng calls start here:
            MagicMock(returncode=0),  # nmcli disconnect
            MagicMock(returncode=0),  # nmcli set managed no
            MagicMock(returncode=0),  # pkill airbase-ng
            MagicMock(returncode=0),  # pkill dnsmasq at0
            MagicMock(returncode=0),  # ip link down
            MagicMock(returncode=0),  # iwconfig mode monitor
            MagicMock(returncode=0),  # iw dev set type monitor
            MagicMock(returncode=0),  # ip link up
            MagicMock(returncode=0),  # ip addr flush at0
            MagicMock(returncode=0),  # ip addr add at0
            MagicMock(returncode=0),  # ip link up at0
            MagicMock(returncode=0),  # dnsmasq
            MagicMock(returncode=0),  # iptables
        ]
        proc_fail1 = MagicMock()
        proc_fail1.poll.return_value = 1  # nl80211 fails
        proc_fail2 = MagicMock()
        proc_fail2.poll.return_value = 1  # wext fails
        proc_ok = MagicMock()
        proc_ok.poll.return_value = None  # airbase-ng succeeds
        mock_popen.side_effect = [proc_fail1, proc_fail2, proc_ok]

        result = ap_manager._setup_ap_hostapd(
            "wlan0", "TestAP", "pass123",
            "192.168.50.1/24", "192.168.50.10,192.168.50.100"
        )
        assert result is True
        assert mock_popen.call_count == 3
        # airbase-ng called with right args
        mock_popen.assert_called_with(
            ["sudo", "airbase-ng", "-e", "TestAP", "-c", "6", "wlan0"],
            stdout=mock_open.return_value,
            stderr=subprocess.STDOUT,
        )


class TestSetupAP:
    @patch.object(LinuxAPManager, "_setup_ap_nmcli")
    @patch.object(LinuxAPManager, "_setup_ap_hostapd")
    @patch.object(LinuxAPManager, "_supports_ap_via_nm")
    def test_uses_nmcli_when_supported(self, mock_supports, mock_hostapd, mock_nmcli, ap_manager):
        mock_supports.return_value = True
        mock_nmcli.return_value = True

        result = ap_manager.setup_ap("wlan0", "TestAP", "pass123", "10.0.0.1/24", "10.0.0.10,10.0.0.100")
        assert result is True
        mock_nmcli.assert_called_once()
        mock_hostapd.assert_not_called()

    @patch.object(LinuxAPManager, "_setup_ap_nmcli")
    @patch.object(LinuxAPManager, "_setup_ap_hostapd")
    @patch.object(LinuxAPManager, "_supports_ap_via_nm")
    def test_uses_hostapd_fallback(self, mock_supports, mock_hostapd, mock_nmcli, ap_manager):
        mock_supports.return_value = False
        mock_hostapd.return_value = True

        result = ap_manager.setup_ap("wlan0", "TestAP", "pass123", "10.0.0.1/24", "10.0.0.10,10.0.0.100")
        assert result is True
        mock_nmcli.assert_not_called()
        mock_hostapd.assert_called_once()


class TestStopAP:
    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_stop_ap_nmcli(self, mock_run, ap_manager):
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
    def test_stop_ap_hostapd(self, mock_run, ap_manager):
        ap_manager._con_name = ""
        ap_manager._hostapd_pid = 1234
        ap_manager._interface = "wlan0"
        mock_run.return_value = MagicMock(returncode=0)

        result = ap_manager.stop_ap()
        assert result is True
        assert ap_manager._hostapd_pid is None
        mock_run.assert_has_calls([
            call(["sudo", "pkill", "-f", "hostapd.*wlan0"], capture_output=True),
            call(["sudo", "pkill", "-f", "dnsmasq.*wlan0"], capture_output=True),
        ], any_order=True)

    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_stop_ap_no_con_name_no_pid(self, mock_run, ap_manager):
        ap_manager._con_name = ""
        ap_manager._hostapd_pid = None
        result = ap_manager.stop_ap()
        assert result is True
        mock_run.assert_not_called()


class TestIsClientConnected:
    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_is_connected_true(self, mock_run, ap_manager):
        ap_manager._interface = "wlan0"
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "Station AA:BB:CC:DD:EE:FF (on wlan0)"

        assert ap_manager.is_client_connected() is True

    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_is_connected_false(self, mock_run, ap_manager):
        ap_manager._interface = "wlan0"
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""

        assert ap_manager.is_client_connected() is False

    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_is_connected_no_interface(self, mock_run, ap_manager):
        ap_manager._interface = None
        assert ap_manager.is_client_connected() is False
        mock_run.assert_not_called()

    @patch("wifi_auto_test.ap_manager.linux_ap.subprocess.run")
    def test_is_connected_iw_fails(self, mock_run, ap_manager):
        ap_manager._interface = "wlan0"
        mock_run.return_value.returncode = 1

        assert ap_manager.is_client_connected() is False
