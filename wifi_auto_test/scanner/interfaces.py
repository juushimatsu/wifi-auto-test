from abc import ABC, abstractmethod
from typing import List

from wifi_auto_test.core.models import WiFiNetwork


class IScanner(ABC):
    @abstractmethod
    def scan(self) -> List[WiFiNetwork]:
        pass


class INetworkParser(ABC):
    @abstractmethod
    def parse(self, line: str) -> WiFiNetwork | None:
        pass
