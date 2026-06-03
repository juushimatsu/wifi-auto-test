import re
from typing import Optional

from wifi_auto_test.core.models import WiFiNetwork
from .interfaces import INetworkParser


class WashParser(INetworkParser):
    # Пример строки wash:
    # 14:9D:09:3C:9E:30  -72  11  270   WPA2  testnet
    # BSSID               RSSI CH  RATE  ENC   ESSID
    _PATTERN = re.compile(
        r"^(?P<bssid>[0-9A-Fa-f:]{17})\s+"
        r"(?P<rssi>-?\d+)\s+"
        r"(?P<channel>\d+)\s+"
        r"(?P<rate>\d+)\s+"
        r"(?P<enc>\S+)\s+"
        r"(?P<essid>.*)$"
    )

    def parse(self, line: str) -> WiFiNetwork | None:
        line = line.strip()
        match = self._PATTERN.match(line)
        if not match:
            return None
        return WiFiNetwork(
            bssid=match.group("bssid").strip(),
            ssid=match.group("essid").strip(),
            channel=int(match.group("channel")),
            signal_dbm=int(match.group("rssi")),
            security=match.group("enc").strip(),
        )
