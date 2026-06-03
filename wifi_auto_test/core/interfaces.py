from abc import ABC, abstractmethod
from typing import List

from .models import WiFiNetwork, TestResult


class IScanner(ABC):
    @abstractmethod
    def scan(self) -> List[WiFiNetwork]:
        """Вернуть список найденных WiFi-сетей."""
        pass


class IAttackEngine(ABC):
    @abstractmethod
    def run(self, network: WiFiNetwork) -> TestResult:
        """Запустить атаку на сеть, вернуть результат."""
        pass
