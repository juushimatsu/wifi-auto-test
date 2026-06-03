import os
import shutil
import subprocess
import threading
import time
from typing import Callable, List, Optional

from wifi_auto_test.core.models import WiFiNetwork
from wifi_auto_test.utils.process_runner import ProcessRunner
from .interfaces import IScanner, INetworkParser


def _which(name: str) -> str:
    """Найти бинарник, используя полный PATH."""
    path_env = os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")
    for p in path_env.split(os.pathsep) + ["/usr/sbin", "/sbin", "/usr/local/sbin"]:
        full = os.path.join(p, name)
        if os.path.isfile(full) and os.access(full, os.X_OK):
            return full
    return shutil.which(name) or name


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

    def _find_interfaces(self) -> List[str]:
        """Найти все WiFi интерфейсы через sysfs."""
        result = []
        try:
            for entry in os.listdir("/sys/class/net"):
                if os.path.exists(f"/sys/class/net/{entry}/wireless"):
                    result.append(entry)
        except OSError:
            pass
        return result

    def _get_interface_mode(self, iface: str) -> str:
        """Определить режим интерфейса через iw или iwconfig."""
        # Try iw first
        iw = _which("iw")
        result = subprocess.run(
            ["sudo", iw, "dev", iface, "info"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "type" in line:
                    return line.strip().split("type")[-1].strip()
        # Fallback to iwconfig
        iwconfig = _which("iwconfig")
        result = subprocess.run(
            ["sudo", iwconfig, iface],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "Mode:" in line:
                    mode = line.split("Mode:")[1].split()[0]
                    return mode.lower()
        # Try sysfs
        try:
            with open(f"/sys/class/net/{iface}/type", "r") as f:
                t = f.read().strip()
                if t == "803":
                    return "monitor"
                if t == "1":
                    return "managed"
        except OSError:
            pass
        return "unknown"

    def _find_monitor_interface(self) -> Optional[str]:
        """Найти интерфейс в monitor mode."""
        for iface in self._find_interfaces():
            mode = self._get_interface_mode(iface)
            if mode == "monitor":
                return iface
        return None

    def _try_wash(self, iface: str) -> bool:
        """Проверить что wash работает на интерфейсе."""
        wash = _which("wash")
        proc = subprocess.Popen(
            ["sudo", wash, "-i", iface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(2)
        ret = proc.poll()
        if ret is not None:
            stdout, stderr = proc.communicate()
            err_text = stderr.decode('utf-8', errors='replace').strip()
            print(f"[DEBUG] wash -i {iface} вышел сразу (code={ret}), stderr: {err_text[:200]}")
            return False
        proc.terminate()
        proc.wait(timeout=2)
        print(f"[DEBUG] wash -i {iface} работает!")
        return True

    def _ensure_monitor_mode(self) -> Optional[str]:
        """Вернуть имя интерфейса для wash."""
        # 0. Пробуем исходный интерфейс напрямую
        print(f"[DEBUG] Проверка wash на {self._interface}")
        if self._try_wash(self._interface):
            return self._interface

        # 1. Проверить исходный интерфейс
        mode = self._get_interface_mode(self._interface)
        if mode == "monitor":
            return self._interface

        # 2. Искать любой monitor-интерфейс
        existing_mon = self._find_monitor_interface()
        if existing_mon:
            print(f"[DEBUG] Найден monitor-интерфейс: {existing_mon}")
            return existing_mon

        # 3. Попытка через airmon-ng
        airmon = _which("airmon-ng")
        print(f"[DEBUG] Попытка airmon-ng start {self._interface}")
        subprocess.run(
            ["sudo", airmon, "start", self._interface],
            capture_output=True,
        )
        time.sleep(1)

        existing_mon = self._find_monitor_interface()
        if existing_mon:
            return existing_mon

        # 4. Fallback: iw set type monitor
        iw = _which("iw")
        print(f"[DEBUG] Попытка iw set type monitor {self._interface}")
        subprocess.run(
            ["sudo", "ip", "link", "set", self._interface, "down"],
            capture_output=True,
        )
        subprocess.run(
            ["sudo", iw, "dev", self._interface, "set", "type", "monitor"],
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "ip", "link", "set", self._interface, "up"],
            capture_output=True,
        )
        time.sleep(0.5)

        mode = self._get_interface_mode(self._interface)
        if mode == "monitor":
            return self._interface

        print(f"[!] Не удалось подготовить {self._interface} (текущий режим: {mode})")
        return None

    def scan(self) -> List[WiFiNetwork]:
        iface = self._ensure_monitor_mode()
        if not iface:
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

        wash = _which("wash")
        command = ["sudo", wash, "-i", iface, "-f"]
        print(f"[DEBUG] Запуск wash на {iface}")
        rc = self._runner.run(
            command=command,
            timeout=self._scan_interval,
            on_stdout=_on_stdout,
            on_stderr=_on_stderr,
        )
        with self._buffer_lock:
            return list(self._buffer)
