from unittest.mock import MagicMock, patch
import pytest

from wifi_auto_test.attack.airodump_attack import AirodumpAttack
from wifi_auto_test.attack.hybrid_attack import HybridAttack
from wifi_auto_test.core.models import WiFiNetwork, TestStatus


@pytest.fixture
def airodump_attack():
    runner = MagicMock()
    runner.run.return_value = 0
    return AirodumpAttack(
        interface="wlan0mon",
        output_dir="/tmp/caps",
        timeout=60,
        process_runner=runner,
    )


class TestAirodumpAttack:
    def test_run_success_when_handshake_in_stdout(self, airodump_attack, tmp_path):
        airodump_attack._output_dir = str(tmp_path)
        airodump_attack._runner.run.return_value = 0

        # Simulate stdout callback triggering handshake detection
        def capture_stdout_call(*, on_stdout, **kwargs):
            on_stdout("WPA handshake: 00:11:22:33:44:55")
            return 0

        airodump_attack._runner.run.side_effect = capture_stdout_call

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

    def test_run_failure_when_no_handshake(self, airodump_attack):
        airodump_attack._runner.run.return_value = 0
        network = WiFiNetwork(
            bssid="00:11:22:33:44:55",
            ssid="TestNet",
            channel=6,
            signal_dbm=-50,
            security="WPA2",
        )
        result = airodump_attack.run(network)
        assert result.status == TestStatus.FAILURE

    def test_run_uses_channel_1_when_network_channel_invalid(self, airodump_attack):
        called_with = None

        def capture_cmd(*, command, **kwargs):
            nonlocal called_with
            called_with = command
            return 0

        airodump_attack._runner.run.side_effect = capture_cmd
        network = WiFiNetwork(
            bssid="00:11:22:33:44:55",
            ssid="BadCh",
            channel=-1,
            signal_dbm=-50,
            security="WPA2",
        )
        airodump_attack.run(network)
        assert "-c" in called_with
        assert called_with[called_with.index("-c") + 1] == "1"


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
