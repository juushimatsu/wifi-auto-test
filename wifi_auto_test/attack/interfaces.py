from abc import ABC, abstractmethod

from wifi_auto_test.core.models import WiFiNetwork, TestResult


class IAttackEngine(ABC):
    @abstractmethod
    def run(self, network: WiFiNetwork) -> TestResult:
        pass
