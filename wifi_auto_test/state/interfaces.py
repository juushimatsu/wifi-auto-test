from abc import ABC, abstractmethod
from typing import List, Optional

from wifi_auto_test.core.models import WiFiNetwork, TestResult, TestStatus


class IStateRepository(ABC):
    @abstractmethod
    def upsert_network(self, network: WiFiNetwork, status: TestStatus) -> None:
        pass

    @abstractmethod
    def get_pending_networks(self) -> List[WiFiNetwork]:
        pass

    @abstractmethod
    def get_successful_bssids(self) -> List[str]:
        pass

    @abstractmethod
    def get_network_history(self, bssid: str) -> List[TestResult]:
        pass

    @abstractmethod
    def add_test_run(self, result: TestResult) -> None:
        pass
