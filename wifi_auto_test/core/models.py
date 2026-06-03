from dataclasses import dataclass, field
from typing import Optional, List
from enum import Enum
import time


class TestStatus(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    PENDING_RETRY = "pending_retry"
    EXCLUDED = "excluded"
    IN_PROGRESS = "in_progress"


@dataclass
class WiFiNetwork:
    bssid: str
    ssid: str
    channel: int
    signal_dbm: int
    security: str = ""

    def __hash__(self) -> int:
        return hash(self.bssid)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, WiFiNetwork):
            return NotImplemented
        return self.bssid == other.bssid


@dataclass
class TestResult:
    network: WiFiNetwork
    status: TestStatus
    pcap_file: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    captured_frames: Optional[str] = None
    log_excerpt: str = ""


@dataclass
class SessionState:
    running: bool = False
    paused: bool = False
    current_network: Optional[WiFiNetwork] = None
    queue: List[WiFiNetwork] = field(default_factory=list)
    total_scanned: int = 0
    total_success: int = 0
    total_failure: int = 0
