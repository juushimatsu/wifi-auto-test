import os
import re
import subprocess
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
        self._help_text_cache: str | None = None
        self._version_cache: tuple[int, int, int] | None = None
        self._output_option_cache: str | None = None
        os.makedirs(self._output_dir, exist_ok=True)

    def _sanitize(self, s: str) -> str:
        return re.sub(r"[^\w\-]", "_", s)

    def _get_help_text(self) -> str:
        if self._help_text_cache is not None:
            return self._help_text_cache
        try:
            result = subprocess.run(
                ["hcxdumptool", "-h"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            self._help_text_cache = f"{result.stdout}\n{result.stderr}"
        except Exception:
            self._help_text_cache = ""
        return self._help_text_cache

    def _get_version(self) -> tuple[int, int, int] | None:
        if self._version_cache is not None:
            return self._version_cache

        texts = [self._get_help_text()]
        for option in ("--version", "-v"):
            try:
                result = subprocess.run(
                    ["hcxdumptool", option],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                texts.append(f"{result.stdout}\n{result.stderr}")
            except Exception:
                pass

        for text in texts:
            match = re.search(r"hcxdumptool\s+(\d+)\.(\d+)(?:\.(\d+))?", text, re.IGNORECASE)
            if match:
                self._version_cache = (
                    int(match.group(1)),
                    int(match.group(2)),
                    int(match.group(3) or 0),
                )
                return self._version_cache
        return None

    def _get_output_option(self) -> str:
        if self._output_option_cache:
            return self._output_option_cache
        self._output_option_cache = "-w" if "-w <" in self._get_help_text() else "-o"
        return self._output_option_cache

    def _supports_option(self, option: str) -> bool:
        return option in self._get_help_text()

    def _build_command(self, network: WiFiNetwork, filepath: str) -> list[str]:
        channel = network.channel if network.channel > 0 else 1
        version = self._get_version()
        is_legacy_v6 = version is not None and version[0] < 7
        supports_rds = self._supports_option("--rds") and not is_legacy_v6
        # hcxdumptool 7.x accepts the channel suffix used by the current working
        # test command. Version 6.x, including 6.2.6 on Orange Pi, requires a
        # plain numeric channel and works with --enable_status=1.
        channel_arg = f"{channel}a" if supports_rds else str(channel)
        command = [
            "sudo",
            "hcxdumptool",
            "-i",
            self._interface,
            "-c",
            channel_arg,
            self._get_output_option(),
            filepath,
        ]
        if supports_rds:
            command.append("--rds=4")
        elif self._supports_option("--enable_status"):
            command.append("--enable_status=1")
        return command

    def run(self, network: WiFiNetwork) -> TestResult:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_ssid = self._sanitize(network.ssid or "hidden")
        filename = f"{timestamp}_{safe_ssid}_{network.bssid.replace(':', '')}.pcapng"
        filepath = os.path.join(self._output_dir, filename)

        command = self._build_command(network, filepath)

        status = TestStatus.TIMEOUT
        log_lines: list[str] = []
        pcap_created = False

        def _handle_output(line: str, source: str) -> None:
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
                self._runner.terminate()
            elif parsed == HcxdumpStatus.ACTIVITY:
                self._log(f"[*] Активность для {network.ssid}: {line.strip()}")
            elif source == "stderr":
                self._log(f"[!] stderr {network.ssid}: {line.strip()}")

        def _on_stdout(line: str) -> None:
            _handle_output(line, "stdout")

        def _on_stderr(line: str) -> None:
            _handle_output(line, "stderr")

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

        if status != TestStatus.SUCCESS:
            if pcap_created:
                try:
                    os.remove(filepath)
                except OSError:
                    pass
            pcap_created = False
            filepath = None
        elif not pcap_created:
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

    def terminate(self) -> None:
        self._runner.terminate()
