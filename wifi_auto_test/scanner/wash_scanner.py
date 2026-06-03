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

    def scan(self) -> List[WiFiNetwork]:
        self._buffer.clear()

        def _on_stdout(line: str) -> None:
            network = self._parser.parse(line)
            if network:
                with self._buffer_lock:
                    # Дедупликация по BSSID
                    for i, existing in enumerate(self._buffer):
                        if existing.bssid == network.bssid:
                            # Обновить более сильным сигналом
                            if network.signal_dbm > existing.signal_dbm:
                                self._buffer[i] = network
                            return
                    self._buffer.append(network)

        def _on_stderr(line: str) -> None:
            pass

        command = ["sudo", "wash", "-i", self._interface, "-f"]
        rc = self._runner.run(
            command=command,
            timeout=self._scan_interval,
            on_stdout=_on_stdout,
            on_stderr=_on_stderr,
        )
        with self._buffer_lock:
            return list(self._buffer)
