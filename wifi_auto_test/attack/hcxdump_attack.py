import os
import re
import time
from datetime import datetime
from typing import Callable, Optional

from wifi_auto_test.config.interfaces import IConfigStore
from wifi_auto_test.core.models import WiFiNetwork, TestResult, TestStatus
from wifi_auto_test.utils.process_runner import ProcessRunner
from .interfaces import IAttackEngine
from .output_parser import HcxdumpOutputParser, HcxdumpStatus


class HcxdumpAttack(IAttackEngine):
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
        self._parser = HcxdumpOutputParser()
        self._log: Callable[[str], None] = logger or (lambda x: None)
        os.makedirs(self._output_dir, exist_ok=True)

    def _sanitize(self, s: str) -> str:
        return re.sub(r"[^\w\-]", "_", s)

    def run(self, network: WiFiNetwork) -> TestResult:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_ssid = self._sanitize(network.ssid or "hidden")
        filename = f"{timestamp}_{safe_ssid}_{network.bssid.replace(':', '')}.pcapng"
        filepath = os.path.join(self._output_dir, filename)

        command = [
            "sudo",
            "hcxdumptool",
            "-i",
            self._interface,
            "-c",
            f"{network.channel}a",
            "-w",
            filepath,
            "--rds=4",
        ]

        status = TestStatus.TIMEOUT
        log_lines: list[str] = []
        pcap_created = False

        def _on_stdout(line: str) -> None:
            nonlocal status
            log_lines.append(line)
            parsed = self._parser.parse(line)
            if parsed in (
                HcxdumpStatus.PMKID_FOUND,
                HcxdumpStatus.M1M2_FOUND,
                HcxdumpStatus.M1M4_FOUND,
            ):
                status = TestStatus.SUCCESS
                self._log(f"[+] Успех для {network.ssid}: {line.strip()}")
            elif parsed == HcxdumpStatus.ACTIVITY:
                self._log(f"[*] Активность для {network.ssid}: {line.strip()}")

        def _on_stderr(line: str) -> None:
            log_lines.append(line)
            self._log(f"[!] stderr {network.ssid}: {line.strip()}")

        self._log(f"[*] Запуск hcxdumptool на {network.ssid} (ch {network.channel})")
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

        if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
            pcap_created = True
        else:
            filepath = None

        if status == TestStatus.SUCCESS and not pcap_created:
            # Если pcapng не создан, хотя успех зафиксирован — редкий edge-case
            pass

        return TestResult(
            network=network,
            status=status,
            pcap_file=filepath if pcap_created else None,
            captured_frames="HCXDUMP_HANDSHAKE" if status == TestStatus.SUCCESS else None,
            log_excerpt="\n".join(log_lines[-50:]),
        )
