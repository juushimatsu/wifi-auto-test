from abc import ABC, abstractmethod


class IAPManager(ABC):
    @abstractmethod
    def setup_ap(self, interface: str, ssid: str, password: str, ip_cidr: str, dhcp_range: str) -> bool:
        pass

    @abstractmethod
    def stop_ap(self) -> bool:
        pass

    @abstractmethod
    def is_client_connected(self) -> bool:
        pass
