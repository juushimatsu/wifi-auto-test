import json
import sqlite3
from typing import List

from wifi_auto_test.core.models import WiFiNetwork, TestResult, TestStatus
from .interfaces import IStateRepository


class SqliteStateRepository(IStateRepository):
    def __init__(self, db_path: str = "wifi_auto_test.db"):
        self._db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS networks (
                    bssid TEXT PRIMARY KEY,
                    ssid TEXT,
                    last_channel INTEGER,
                    last_signal_dbm INTEGER,
                    last_seen REAL,
                    overall_status TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS test_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bssid TEXT,
                    timestamp REAL,
                    status TEXT,
                    pcap_file TEXT,
                    log_excerpt TEXT,
                    FOREIGN KEY (bssid) REFERENCES networks(bssid)
                )
                """
            )
            conn.commit()

    def upsert_network(self, network: WiFiNetwork, status: TestStatus) -> None:
        import time
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                INSERT INTO networks (bssid, ssid, last_channel, last_signal_dbm, last_seen, overall_status)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(bssid) DO UPDATE SET
                    ssid=excluded.ssid,
                    last_channel=excluded.last_channel,
                    last_signal_dbm=excluded.last_signal_dbm,
                    last_seen=excluded.last_seen,
                    overall_status=excluded.overall_status
                """,
                (
                    network.bssid,
                    network.ssid,
                    network.channel,
                    network.signal_dbm,
                    time.time(),
                    status.value,
                ),
            )
            conn.commit()

    def get_pending_networks(self) -> List[WiFiNetwork]:
        with sqlite3.connect(self._db_path) as conn:
            cursor = conn.execute(
                "SELECT bssid, ssid, last_channel, last_signal_dbm FROM networks WHERE overall_status != ?",
                (TestStatus.SUCCESS.value,),
            )
            rows = cursor.fetchall()
        return [
            WiFiNetwork(
                bssid=r[0],
                ssid=r[1] or "",
                channel=r[2] or 0,
                signal_dbm=r[3] or -100,
            )
            for r in rows
        ]

    def get_successful_bssids(self) -> List[str]:
        with sqlite3.connect(self._db_path) as conn:
            cursor = conn.execute(
                "SELECT bssid FROM networks WHERE overall_status = ?",
                (TestStatus.SUCCESS.value,),
            )
            return [r[0] for r in cursor.fetchall()]

    def get_network_history(self, bssid: str) -> List[TestResult]:
        with sqlite3.connect(self._db_path) as conn:
            cursor = conn.execute(
                "SELECT timestamp, status, pcap_file, log_excerpt FROM test_runs WHERE bssid = ? ORDER BY timestamp DESC",
                (bssid,),
            )
            rows = cursor.fetchall()
        return [
            TestResult(
                network=WiFiNetwork(bssid=bssid, ssid="", channel=0, signal_dbm=0),
                status=TestStatus(r[1]),
                pcap_file=r[2],
                timestamp=r[0],
                log_excerpt=r[3] or "",
            )
            for r in rows
        ]

    def add_test_run(self, result: TestResult) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                INSERT INTO test_runs (bssid, timestamp, status, pcap_file, log_excerpt)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    result.network.bssid,
                    result.timestamp,
                    result.status.value,
                    result.pcap_file,
                    result.log_excerpt,
                ),
            )
            conn.commit()
