import os
import threading
from datetime import datetime
from typing import Optional

from .interfaces import ILogger


class FileWebSocketLogger(ILogger):
    def __init__(
        self,
        log_dir: str = "./logs",
        ws_manager=None,
    ):
        self._log_dir = log_dir
        self._ws_manager = ws_manager
        self._lock = threading.Lock()
        os.makedirs(self._log_dir, exist_ok=True)
        self._filepath = os.path.join(
            self._log_dir, f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )

    def set_ws_manager(self, ws_manager) -> None:
        self._ws_manager = ws_manager

    def _write(self, level: str, msg: str) -> None:
        line = f"[{datetime.now().isoformat()}] [{level}] {msg}"
        print(line)
        with self._lock:
            with open(self._filepath, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        if self._ws_manager:
            try:
                self._ws_manager.sync_broadcast(line)
            except Exception:
                pass

    def debug(self, msg: str) -> None:
        self._write("DEBUG", msg)

    def info(self, msg: str) -> None:
        self._write("INFO", msg)

    def warning(self, msg: str) -> None:
        self._write("WARNING", msg)

    def error(self, msg: str) -> None:
        self._write("ERROR", msg)
