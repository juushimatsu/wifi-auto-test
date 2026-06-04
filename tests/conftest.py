import pytest
from unittest.mock import MagicMock

from wifi_auto_test.core.models import WiFiNetwork, TestResult, TestStatus, SessionState


@pytest.fixture
def sample_network():
    return WiFiNetwork(
        bssid="AA:BB:CC:DD:EE:FF",
        ssid="TestNet",
        channel=6,
        signal_dbm=-55,
        security="WPA2",
    )


@pytest.fixture
def sample_networks():
    return [
        WiFiNetwork(
            bssid="AA:BB:CC:DD:EE:01",
            ssid="Net1",
            channel=1,
            signal_dbm=-40,
            security="WPA2",
        ),
        WiFiNetwork(
            bssid="AA:BB:CC:DD:EE:02",
            ssid="Net2",
            channel=6,
            signal_dbm=-70,
            security="WPA2",
        ),
        WiFiNetwork(
            bssid="AA:BB:CC:DD:EE:03",
            ssid="Net3",
            channel=11,
            signal_dbm=-55,
            security="WPA2",
        ),
    ]


@pytest.fixture
def mock_process_runner():
    runner = MagicMock()
    runner.run.return_value = ""
    return runner


@pytest.fixture
def mock_parser():
    parser = MagicMock()
    parser.parse.side_effect = lambda line: None
    return parser
