import subprocess
import threading
import time
from typing import List, Callable, Optional


class ProcessRunner:
    def __init__(self):
        self._proc: Optional[subprocess.Popen] = None
        self._terminated = False

    def run(
        self,
        command: List[str],
        timeout: int,
        on_stdout: Optional[Callable[[str], None]] = None,
        on_stderr: Optional[Callable[[str], None]] = None,
        cwd: Optional[str] = None,
    ) -> int:
        self._terminated = False
        self._proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
        )

        def _read_stream(pipe, callback):
            if pipe is None or callback is None:
                return
            for line in iter(pipe.readline, ""):
                if not line:
                    break
                callback(line.rstrip("\n"))

        threads: List[threading.Thread] = []
        if self._proc.stdout and on_stdout:
            t = threading.Thread(
                target=_read_stream, args=(self._proc.stdout, on_stdout), daemon=True
            )
            t.start()
            threads.append(t)
        if self._proc.stderr and on_stderr:
            t = threading.Thread(
                target=_read_stream, args=(self._proc.stderr, on_stderr), daemon=True
            )
            t.start()
            threads.append(t)

        try:
            return self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.terminate()
            return -1
        finally:
            for t in threads:
                t.join(timeout=2)

    def terminate(self) -> None:
        if self._proc is None:
            return
        self._terminated = True
        self._proc.terminate()
        try:
            self._proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait(timeout=1)
        finally:
            self._proc = None

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None
