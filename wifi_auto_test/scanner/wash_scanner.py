import os
import re
import subprocess
import threading
import time
from typing import List, Optional

from wifi_auto_test.core.models import WiFiNetwork
from wifi_auto_test.utils.process_runner import ProcessRunner
from .interfaces import IScanner, INetworkParser


class IwScanner(IScanner):
    """Сканер через iw dev scan — без зависимости от wash."""

    def __init__(
        self,
        interface: str,
        parser: INetworkParser,
        process_runner: ProcessRunner,
        scan_interval: int = 15,
    ):
        self._interface = interface
        self._parser = parser
        self._runner = process_runner
        self._scan_interval = scan_interval
        self._buffer: List[WiFiNetwork] = []
        self._buffer_lock = threading.Lock()

    def _find_interfaces(self) -> List[str]:
        result = []
        # Primary: /sys/class/net/*/wireless (works on most systems including Orange Pi)
        try:
            for entry in os.listdir("/sys/class/net"):
                if os.path.exists(f"/sys/class/net/{entry}/wireless"):
                    result.append(entry)
        except OSError:
            pass
        # Fallback: iw dev
        if not result:
            try:
                out = subprocess.run(
                    ["iw", "dev"], capture_output=True, text=True
                ).stdout
                for line in out.split("\n"):
                    if line.strip().startswith("Interface "):
                        result.append(line.strip().split(" ")[1])
            except Exception:
                pass
        return result

    def _get_interface_mode(self, iface: str) -> str:
        # Primary: iwconfig (works on Orange Pi)
        result = subprocess.run(
            ["sudo", "iwconfig", iface],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "Mode:" in line:
                    return line.split("Mode:")[1].split()[0].lower()
        # Fallback: iw dev <iface> info
        result2 = subprocess.run(
            ["sudo", "iw", "dev", iface, "info"],
            capture_output=True, text=True,
        )
        if result2.returncode == 0:
            for line in result2.stdout.split("\n"):
                if "type" in line.lower():
                    return line.strip().rsplit(" ", 1)[-1].lower()
        # sysfs fallback
        try:
            with open(f"/sys/class/net/{iface}/type", "r") as f:
                t = f.read().strip()
                if t == "803":
                    return "monitor"
        except OSError:
            pass
        return "unknown"

    def _find_monitor_interface(self) -> Optional[str]:
        for iface in self._find_interfaces():
            if self._get_interface_mode(iface) == "monitor":
                return iface
        return None

    def _bring_up(self, iface: str) -> None:
        subprocess.run(
            ["sudo", "ip", "link", "set", iface, "up"],
            capture_output=True,
        )
        time.sleep(0.3)

    def _ensure_monitor(self) -> Optional[str]:
        # 1. Исходный интерфейс уже monitor?
        if self._get_interface_mode(self._interface) == "monitor":
            self._bring_up(self._interface)
            return self._interface

        # 2. Найти любой monitor
        mon = self._find_monitor_interface()
        if mon:
            self._bring_up(mon)
            return mon

        # 3. Перевести через airmon-ng
        subprocess.run(
            ["sudo", "airmon-ng", "start", self._interface],
            capture_output=True,
        )
        time.sleep(1)

        mon = self._find_monitor_interface()
        if mon:
            return mon

        # 4. Fallback: iw set type monitor
        subprocess.run(["sudo", "ip", "link", "set", self._interface, "down"], capture_output=True)
        subprocess.run(["sudo", "iw", "dev", self._interface, "set", "type", "monitor"], capture_output=True)
        subprocess.run(["sudo", "ip", "link", "set", self._interface, "up"], capture_output=True)
        time.sleep(0.5)

        if self._get_interface_mode(self._interface) == "monitor":
            return self._interface

        return None

    def _parse_iw_scan(self, raw: str) -> List[WiFiNetwork]:
        """Парсинг вывода `iw dev <iface> scan`."""
        networks = []
        current = {}
        for line in raw.split("\n"):
            line = line.strip()
            if line.startswith("BSS "):
                if current and "bssid" in current:
                    networks.append(WiFiNetwork(
                        bssid=current.get("bssid", ""),
                        ssid=current.get("ssid", ""),
                        channel=int(current.get("channel", 0)),
                        signal_dbm=int(current.get("signal", -100)),
                        security=current.get("security", "UNKNOWN"),
                    ))
                current = {"bssid": line.split()[1].replace("(", "").replace(")", "")}
            elif "SSID:" in line and line.startswith("SSID:"):
                current["ssid"] = line.split(":", 1)[1].strip()
            elif "signal:" in line:
                m = re.search(r"(-?\d+\.?\d*) dBm", line)
                if m:
                    current["signal"] = int(float(m.group(1)))
            elif "DS Parameter set: channel" in line:
                m = re.search(r"channel (\d+)", line)
                if m:
                    current["channel"] = int(m.group(1))
            elif "RSN:" in line or "WPA:" in line:
                current["security"] = "WPA2"
            elif "Privacy" in line and "security" not in current:
                current["security"] = "WEP"
        if current and "bssid" in current:
            networks.append(WiFiNetwork(
                bssid=current.get("bssid", ""),
                ssid=current.get("ssid", ""),
                channel=int(current.get("channel", 0)),
                signal_dbm=int(current.get("signal", -100)),
                security=current.get("security", "UNKNOWN"),
            ))
        return networks

    def scan(self) -> List[WiFiNetwork]:
        iface = self._ensure_monitor()
        if not iface:
            print(f"[!] Нет интерфейса в monitor mode")
            return []

        self._bring_up(iface)

        # Запускаем iw scan
        result = subprocess.run(
            ["sudo", "iw", "dev", iface, "scan"],
            capture_output=True, text=True,
            timeout=self._scan_interval,
        )
        if result.returncode != 0:
            err = result.stderr.strip()
            if "network is down" in err.lower() or "-100" in err:
                self._bring_up(iface)
                result = subprocess.run(
                    ["sudo", "iw", "dev", iface, "scan"],
                    capture_output=True, text=True,
                    timeout=self._scan_interval,
                )
        if result.returncode != 0:
            print(f"[!] iw scan failed: {result.stderr[:200]}")
            return []

        networks = self._parse_iw_scan(result.stdout)
        print(f"[DEBUG] Найдено сетей через iw: {len(networks)}")
        return networks


# Alias для обратной совместимости
WashScanner = IwScanner
