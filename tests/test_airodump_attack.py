import subprocess
from unittest.mock import MagicMock, patch, call
import pytest

from wifi_auto_test.attack.airodump_attack import AirodumpAttack
from wifi_auto_test.attack.hybrid_attack import HybridAttack
from wifi_auto_test.core.models import WiFiNetwork, TestStatus


@pytest.fixture
def airodump_attack():
    runner = MagicMock()
    return AirodumpAttack(
        interface="wlan0mon",
        output_dir="/tmp/caps",
        timeout=60,
        process_runner=runner,
    )


class TestAirodumpAttack:
    @patch.object(AirodumpAttack, "_has_handshake")
    @patch("wifi_auto_test.attack.airodump_attack.os.path.exists")
    @patch("wifi_auto_test.attack.airodump_attack.subprocess.Popen")
    @patch("wifi_auto_test.attack.airodump_attack.subprocess.run")
    @patch("wifi_auto_test.attack.airodump_attack.time.sleep")
    @patch("wifi_auto_test.attack.airodump_attack.glob.glob")
    @patch("wifi_auto_test.attack.airodump_attack.os.path.getsize")
    def test_run_success_when_handshake_in_pcap(
        self, mock_getsize, mock_glob, mock_sleep, mock_run, mock_popen, mock_exists, mock_has_handshake, airodump_attack
    ):
        # Mock airodump-ng Popen
        mock_proc = MagicMock()
        mock_proc.stderr = MagicMock()
        mock_proc.stderr.readline = MagicMock(return_value="")
        mock_proc.terminate = MagicMock()
        mock_proc.wait = MagicMock(return_value=0)
        mock_popen.return_value = mock_proc

        mock_has_handshake.return_value = True
        mock_exists.return_value = True
        mock_glob.return_value = ["/tmp/caps/test.cap"]
        mock_getsize.return_value = 1024

        network = WiFiNetwork(
            bssid="00:11:22:33:44:55",
            ssid="TestNet",
            channel=6,
            signal_dbm=-50,
            security="WPA2",
        )
        result = airodump_attack.run(network)
        assert result.status == TestStatus.SUCCESS
        assert result.captured_frames == "WPA_HANDSHAKE"
        assert result.pcap_file is not None
        mock_has_handshake.assert_called_once()

    @patch("wifi_auto_test.attack.airodump_attack.subprocess.Popen")
    @patch("wifi_auto_test.attack.airodump_attack.subprocess.run")
    @patch("wifi_auto_test.attack.airodump_attack.time.sleep")
    @patch("wifi_auto_test.attack.airodump_attack.glob.glob")
    def test_run_failure_when_no_handshake(
        self, mock_glob, mock_sleep, mock_run, mock_popen, airodump_attack
    ):
        mock_proc = MagicMock()
        mock_proc.stderr = MagicMock()
        mock_proc.stderr.readline = MagicMock(return_value="")
        mock_proc.terminate = MagicMock()
        mock_proc.wait = MagicMock(return_value=0)
        mock_popen.return_value = mock_proc

        mock_run.return_value = MagicMock(stdout="WPA (0 handshake)", stderr="", returncode=0)
        mock_glob.return_value = []

        network = WiFiNetwork(
            bssid="00:11:22:33:44:55",
            ssid="TestNet",
            channel=6,
            signal_dbm=-50,
            security="WPA2",
        )
        result = airodump_attack.run(network)
        assert result.status == TestStatus.TIMEOUT
        assert result.pcap_file is None
        assert result.captured_frames is None

    @patch("wifi_auto_test.attack.airodump_attack.subprocess.Popen")
    @patch("wifi_auto_test.attack.airodump_attack.subprocess.run")
    @patch("wifi_auto_test.attack.airodump_attack.time.sleep")
    @patch("wifi_auto_test.attack.airodump_attack.glob.glob")
    def test_run_uses_channel_1_when_network_channel_invalid(
        self, mock_glob, mock_sleep, mock_run, mock_popen, airodump_attack
    ):
        mock_proc = MagicMock()
        mock_proc.stderr = MagicMock()
        mock_proc.stderr.readline = MagicMock(return_value="")
        mock_proc.terminate = MagicMock()
        mock_proc.wait = MagicMock(return_value=0)
        mock_popen.return_value = mock_proc

        mock_run.return_value = MagicMock(stdout="WPA (0 handshake)", stderr="", returncode=0)
        mock_glob.return_value = []

        network = WiFiNetwork(
            bssid="00:11:22:33:44:55",
            ssid="BadCh",
            channel=-1,
            signal_dbm=-50,
            security="WPA2",
        )
        airodump_attack.run(network)
        # Verify airodump-ng called with channel 1
        airodump_call = mock_popen.call_args[0][0]
        assert "-c" in airodump_call
        assert airodump_call[airodump_call.index("-c") + 1] == "1"


class TestHybridAttack:
    @patch("wifi_auto_test.attack.hybrid_attack.shutil.which")
    def test_uses_hcxdump_when_available(self, mock_which):
        mock_which.return_value = "/usr/bin/hcxdumptool"
        hcxdump = MagicMock()
        airodump = MagicMock()
        hybrid = HybridAttack(hcxdump=hcxdump, airodump=airodump)

        net = WiFiNetwork(bssid="AA:BB:CC:DD:EE:FF", ssid="N", channel=1, signal_dbm=-50, security="WPA2")
        hybrid.run(net)
        hcxdump.run.assert_called_once_with(net)
        airodump.run.assert_not_called()

    @patch("wifi_auto_test.attack.hybrid_attack.shutil.which")
    def test_falls_back_to_airodump(self, mock_which):
        mock_which.return_value = None
        hcxdump = MagicMock()
        airodump = MagicMock()
        hybrid = HybridAttack(hcxdump=hcxdump, airodump=airodump)

        net = WiFiNetwork(bssid="AA:BB:CC:DD:EE:FF", ssid="N", channel=1, signal_dbm=-50, security="WPA2")
        hybrid.run(net)
        airodump.run.assert_called_once_with(net)
        hcxdump.run.assert_not_called()
