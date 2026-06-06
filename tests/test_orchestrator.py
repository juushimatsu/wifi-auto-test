import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from wifi_auto_test.core.models import TestResult, TestStatus, WiFiNetwork
from wifi_auto_test.core.orchestrator import Orchestrator


@pytest.fixture
def orchestrator():
    scanner = MagicMock()
    attack = MagicMock()
    repo = MagicMock()
    config = MagicMock()
    repo.get_successful_bssids.return_value = []
    orchestrator = Orchestrator(scanner, attack, repo, config, logger=lambda x: None)
    return orchestrator


class TestStartStopRestart:
    def test_start_creates_thread(self, orchestrator):
        orchestrator.start()
        assert orchestrator._thread is not None
        assert orchestrator._thread.is_alive()
        assert orchestrator.state.running is True
        orchestrator._stop_event.set()
        orchestrator._thread.join(timeout=2)

    def test_start_already_running(self, orchestrator):
        orchestrator.start()
        thread = orchestrator._thread
        orchestrator.start()  # should not create new thread
        assert orchestrator._thread is thread
        orchestrator._stop_event.set()
        orchestrator._thread.join(timeout=2)

    def test_stop_sets_paused(self, orchestrator):
        orchestrator.start()
        orchestrator.stop()
        assert orchestrator.state.paused is True
        orchestrator._stop_event.set()
        orchestrator._thread.join(timeout=2)

    def test_restart_when_running(self, orchestrator):
        orchestrator.start()
        orchestrator.stop()
        orchestrator.restart()
        assert orchestrator.state.paused is False
        assert orchestrator._thread.is_alive()
        orchestrator._stop_event.set()
        orchestrator._thread.join(timeout=2)

    def test_restart_when_stopped(self, orchestrator):
        orchestrator.restart()
        assert orchestrator.state.paused is False
        assert orchestrator._thread is not None
        orchestrator._stop_event.set()
        orchestrator._thread.join(timeout=2)


class TestPrioritize:
    def test_prioritize_sets_bssid(self, orchestrator):
        orchestrator.prioritize("AA:BB:CC:DD:EE:FF")
        assert orchestrator._priority_bssid == "AA:BB:CC:DD:EE:FF"


class TestRunCycle:
    def test_cycle_no_networks(self, orchestrator):
        orchestrator._scanner.scan.return_value = []
        orchestrator._run_cycle()
        assert orchestrator.state.total_scanned == 0

    def test_cycle_scans_and_attacks(self, orchestrator, sample_networks):
        orchestrator._scanner.scan.return_value = sample_networks
        orchestrator._attack.run.return_value = TestResult(
            network=sample_networks[0],
            status=TestStatus.SUCCESS,
            pcap_file="/tmp/test.pcap",
        )

        orchestrator._run_cycle()
        assert orchestrator.state.total_scanned == 3
        assert orchestrator.state.total_success == 3  # all mocked to return SUCCESS
        orchestrator._attack.run.assert_called()
        orchestrator._repo.add_test_run.assert_called()

    def test_cycle_filters_successful(self, orchestrator, sample_networks):
        orchestrator._repo.get_successful_bssids.return_value = ["AA:BB:CC:DD:EE:01"]
        orchestrator._scanner.scan.return_value = sample_networks
        orchestrator._attack.run.return_value = TestResult(
            network=sample_networks[1],
            status=TestStatus.SUCCESS,
        )

        orchestrator._run_cycle()
        # Net1 is filtered out, only Net2 and Net3 attacked
        assert orchestrator._attack.run.call_count == 2

    def test_cycle_filters_hidden_and_own_ap(self, orchestrator):
        orchestrator._config.get.return_value = "wifitest"
        networks = [
            WiFiNetwork(bssid="AA:BB:CC:DD:EE:01", ssid="", channel=1, signal_dbm=-30, security="WPA2"),
            WiFiNetwork(bssid="AA:BB:CC:DD:EE:02", ssid="wifitest", channel=6, signal_dbm=-40, security="WPA2"),
            WiFiNetwork(bssid="AA:BB:CC:DD:EE:03", ssid="Target", channel=9, signal_dbm=-50, security="WPA2"),
        ]
        orchestrator._scanner.scan.return_value = networks
        orchestrator._attack.run.return_value = TestResult(network=networks[2], status=TestStatus.SUCCESS)

        orchestrator._run_cycle()

        orchestrator._attack.run.assert_called_once_with(networks[2])

    def test_cycle_sorts_by_signal(self, orchestrator, sample_networks):
        orchestrator._scanner.scan.return_value = sample_networks
        orchestrator._attack.run.return_value = TestResult(
            network=sample_networks[0],
            status=TestStatus.SUCCESS,
        )

        orchestrator._run_cycle()
        # Networks sorted by signal_dbm descending: Net1(-40), Net3(-55), Net2(-70)
        call_args = [call[0][0] for call in orchestrator._attack.run.call_args_list]
        assert call_args[0].ssid == "Net1"  # strongest
        assert call_args[1].ssid == "Net3"
        assert call_args[2].ssid == "Net2"  # weakest

    def test_cycle_prioritizes_bssid(self, orchestrator, sample_networks):
        orchestrator._priority_bssid = "AA:BB:CC:DD:EE:02"  # Net2, weakest signal
        orchestrator._scanner.scan.return_value = sample_networks
        orchestrator._attack.run.return_value = TestResult(
            network=sample_networks[0],
            status=TestStatus.SUCCESS,
        )

        orchestrator._run_cycle()
        call_args = [call[0][0] for call in orchestrator._attack.run.call_args_list]
        # Net2 should be first despite weakest signal
        assert call_args[0].ssid == "Net2"
        assert orchestrator._priority_bssid is None  # cleared after use

    def test_cycle_paused_stops(self, orchestrator, sample_networks):
        orchestrator._scanner.scan.return_value = sample_networks
        orchestrator.state.paused = True

        orchestrator._run_cycle()
        # Should still scan but stop before attacking
        orchestrator._attack.run.assert_not_called()

    def test_cycle_attack_failure(self, orchestrator, sample_networks):
        orchestrator._scanner.scan.return_value = sample_networks[:1]
        orchestrator._attack.run.return_value = TestResult(
            network=sample_networks[0],
            status=TestStatus.FAILURE,
        )

        orchestrator._run_cycle()
        assert orchestrator.state.total_failure == 1
        assert orchestrator.state.total_success == 0
        orchestrator._repo.upsert_network.assert_called_with(
            sample_networks[0], TestStatus.PENDING_RETRY
        )

    def test_cycle_attack_timeout(self, orchestrator, sample_networks):
        orchestrator._scanner.scan.return_value = sample_networks[:1]
        orchestrator._attack.run.return_value = TestResult(
            network=sample_networks[0],
            status=TestStatus.TIMEOUT,
        )

        orchestrator._run_cycle()
        assert orchestrator.state.total_failure == 1


class TestLoop:
    def test_loop_runs_cycles(self, orchestrator):
        orchestrator._scanner.scan.side_effect = [
            [],
            [],
        ]
        orchestrator.start()
        time.sleep(0.3)
        orchestrator._stop_event.set()
        orchestrator._thread.join(timeout=2)
        assert orchestrator._scanner.scan.call_count >= 1

    def test_loop_handles_exceptions(self, orchestrator):
        orchestrator._scanner.scan.side_effect = Exception("scan crash")
        orchestrator.start()
        time.sleep(0.3)
        orchestrator._stop_event.set()
        orchestrator._thread.join(timeout=10)
        assert orchestrator.state.running is False


class TestStateProperty:
    def test_state_returns_session_state(self, orchestrator):
        state = orchestrator.state
        assert state.running is False
        assert state.paused is False
        assert state.total_scanned == 0
