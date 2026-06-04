import pytest

from wifi_auto_test.core.models import TestStatus, WiFiNetwork, TestResult, SessionState


class TestWiFiNetwork:
    def test_defaults(self):
        net = WiFiNetwork(bssid="00:11:22:33:44:55", ssid="Test", channel=6, signal_dbm=-50)
        assert net.security == ""

    def test_equality_by_bssid(self):
        a = WiFiNetwork("AA:BB:CC:DD:EE:FF", "NetA", 1, -50)
        b = WiFiNetwork("AA:BB:CC:DD:EE:FF", "NetB", 6, -70, "WPA3")
        c = WiFiNetwork("11:22:33:44:55:66", "NetA", 1, -50)
        assert a == b
        assert a != c
        assert hash(a) == hash(b)

    def test_hash_in_set(self):
        a = WiFiNetwork("AA:BB:CC:DD:EE:FF", "A", 1, -50)
        b = WiFiNetwork("AA:BB:CC:DD:EE:FF", "B", 2, -60)
        s = {a, b}
        assert len(s) == 1


class TestTestResult:
    def test_timestamp_auto(self):
        net = WiFiNetwork("AA:BB:CC:DD:EE:FF", "A", 1, -50)
        r = TestResult(network=net, status=TestStatus.SUCCESS)
        assert r.pcap_file is None
        assert r.timestamp > 0
        assert r.captured_frames is None
        assert r.log_excerpt == ""


class TestSessionState:
    def test_defaults(self):
        s = SessionState()
        assert s.running is False
        assert s.paused is False
        assert s.current_network is None
        assert s.queue == []
        assert s.total_scanned == 0
        assert s.total_success == 0
        assert s.total_failure == 0

    def test_queue_is_isolated(self):
        s1 = SessionState()
        s2 = SessionState()
        s1.queue.append("x")
        assert s2.queue == []
