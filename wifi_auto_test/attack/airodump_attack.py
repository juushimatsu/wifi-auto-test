import glob
import os
import re
import time
from datetime import datetime
from typing import Callable, Optional

from wifi_auto_test.config.interfaces import IConfigStore
from wifi_auto_test.core.models import WiFiNetwork, TestResult, TestStatus
from wifi_auto_test.utils.process_runner import ProcessRunner
from .interfaces import IAttackEngine


class AirodumpAttack(IAttackEngine):
    """Fallback attack via airodump-ng when hcxdumptool is unavailable."""

    def __init__(
        self,
        interface: str,
        output_dir: str,
        timeout: int,
        process_runner: ProcessRunner,
        logger: Optional[Callable[[str], None]] = None,
    ):
        self._interface = interface
        self._output_dir = output_dir
        self._timeout = timeout
        self._runner = process_runner
        self._log: Callable[[str], None] = logger or (lambda x: None)
        os.makedirs(self._output_dir, exist_ok=True)

    def run(self, network: WiFiNetwork) -> TestResult:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_ssid = re.sub(r"[^\w\-]", "_", network.ssid or "hidden")
        prefix = f"{self._output_dir}/{timestamp}_{safe_ssid}_{network.bssid.replace(':', '')}"

        # Prevent channel -1 (invalid)
        channel = network.channel if network.channel > 0 else 1

        command = [
            "sudo", "airodump-ng",
            "-c", str(channel),
            "--bssid", network.bssid,
            "-w", prefix,
            "--output-format", "pcap",
            self._interface,
        ]

        status = TestStatus.TIMEOUT
        log_lines: list[str] = []
        handshake_found = False
        pcap_file = None

        def _on_stdout(line: str) -> None:
            nonlocal status, handshake_found
            log_lines.append(line)
            # airodump-ng prints "WPA handshake: <BSSID>" when it captures one
            if "WPA handshake:" in line and network.bssid.lower() in line.lower():
                status = TestStatus.SUCCESS
                handshake_found = True
                self._log(f"[+] WPA handshake captured for {network.ssid}: {line.strip()}")

        def _on_stderr(line: str) -> None:
            log_lines.append(line)
            self._log(f"[!] stderr {network.ssid}: {line.strip()}")

        self._log(f"[*] Запуск airodump-ng на {network.ssid} (ch {channel}, {network.bssid})")
        rc = self._runner.run(
            command=command,
            timeout=self._timeout,
            on_stdout=_on_stdout,
            on_stderr=_on_stderr,
        )

        if rc == -1 and status != TestStatus.SUCCESS:
            status = TestStatus.TIMEOUT
        elif status != TestStatus.SUCCESS:
            status = TestStatus.FAILURE

        # Find the generated pcap file
        pcap_files = glob.glob(prefix + "-*.cap")
        if pcap_files:
            pcap_file = pcap_files[0]
            if os.path.getsize(pcap_file) == 0:
                pcap_file = None

        return TestResult(
            network=network,
            status=status,
            pcap_file=pcap_file,
            captured_frames="WPA_HANDSHAKE" if handshake_found else None,
            log_excerpt="\n".join(log_lines[-50:]),
        )
