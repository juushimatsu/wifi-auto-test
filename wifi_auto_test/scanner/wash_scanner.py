import subprocess
import threading
import time
from typing import Callable, List, Optional

from wifi_auto_test.core.models import WiFiNetwork
from wifi_auto_test.utils.process_runner import ProcessRunner
from .interfaces import IScanner, INetworkParser


class WashScanner(IScanner):
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
        self._mon_interface = f"{interface}mon"
        self._mon_created = False

    def _nm_release(self) -> None:
        # Отключить интерфейс от NetworkManager
        subprocess.run(
            ["sudo", "nmcli", "device", "disconnect", self._interface],
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "nmcli", "device", "set", self._interface, "managed", "no"],
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "systemctl", "stop", "NetworkManager"],
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "killall", "-q", "wpa_supplicant"],
            capture_output=True,
        )
        time.sleep(1)

    def _ensure_monitor_mode(self) -> bool:
        self._nm_release()

        # Check if interface already in monitor mode
        result = subprocess.run(
            ["sudo", "iw", "dev", self._interface, "info"],
            capture_output=True, text=True,
        )
        if "type monitor" in result.stdout:
            return True

        # Try airmon-ng
        subprocess.run(
            ["sudo", "airmon-ng", "start", self._interface],
            capture_output=True,
        )
        time.sleep(1)
        result = subprocess.run(
            ["sudo", "iw", "dev", self._mon_interface, "info"],
            capture_output=True, text=True,
        )
        if result.returncode == 0 and "type monitor" in result.stdout:
            self._mon_created = True
            return True

        # Fallback: direct iw set type monitor
        subprocess.run(
            ["sudo", "ip", "link", "set", self._interface, "down"],
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "iw", "dev", self._interface, "set", "type", "monitor"],
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "ip", "link", "set", self._interface, "up"],
            capture_output=True,
        )
        result = subprocess.run(
            ["sudo", "iw", "dev", self._interface, "info"],
            capture_output=True, text=True,
        )
        if result.returncode == 0 and "type monitor" in result.stdout:
            return True
        return False

    def _cleanup_monitor_mode(self) -> None:
        if self._mon_created:
            subprocess.run(
                ["sudo", "airmon-ng", "stop", self._mon_interface],
                capture_output=True,
            )
            self._mon_created = False

    def scan(self) -> List[WiFiNetwork]:
        if not self._ensure_monitor_mode():
            print(f"[!] Не удалось перевести {self._interface} в monitor mode")
            return []

        self._buffer.clear()

        def _on_stdout(line: str) -> None:
            network = self._parser.parse(line)
            if network:
                with self._buffer_lock:
                    for i, existing in enumerate(self._buffer):
                        if existing.bssid == network.bssid:
                            if network.signal_dbm > existing.signal_dbm:
                                self._buffer[i] = network
                            return
                    self._buffer.append(network)

        def _on_stderr(line: str) -> None:
            pass

        iface = self._mon_interface if self._mon_created else self._interface
        command = ["sudo", "wash", "-i", iface, "-f"]
        rc = self._runner.run(
            command=command,
            timeout=self._scan_interval,
            on_stdout=_on_stdout,
            on_stderr=_on_stderr,
        )
        with self._buffer_lock:
            return list(self._buffer)
