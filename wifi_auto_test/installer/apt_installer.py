import shutil
import subprocess
from typing import Dict

from .interfaces import IDependencyInstaller


class AptInstaller(IDependencyInstaller):
    _PACKAGES = [
        "aircrack-ng",
        "hcxtools",
        "hostapd",
        "dnsmasq",
        "iptables",
        "python3-pip",
        "wireless-tools",
        "iw",
        "rfkill",
        "build-essential",
        "git",
        "libcurl4-openssl-dev",
        "libssl-dev",
        "pkg-config",
        "zlib1g-dev",
    ]

    _BINARIES = ["wash", "hcxdumptool", "hostapd", "dnsmasq", "iptables", "airmon-ng", "iw", "iwconfig", "rfkill"]

    def _hcxdumptool_supports_manual_mode(self) -> bool:
        """Return True when hcxdumptool supports the known-good manual command."""
        if not shutil.which("hcxdumptool"):
            return False
        result = subprocess.run(
            ["hcxdumptool", "-h"],
            capture_output=True,
            text=True,
        )
        help_text = f"{result.stdout}\n{result.stderr}"
        return "-w <" in help_text and "--rds" in help_text

    def _build_hcxtools(self) -> bool:
        """Fallback: build hcxdumptool from source if apt package lacks compatible one."""
        print("[*] hcxdumptool missing or too old, building from source...")
        cmds = [
            ["sudo", "rm", "-rf", "/tmp/hcxdumptool-build"],
            ["sudo", "git", "clone", "https://github.com/ZerBea/hcxdumptool.git", "/tmp/hcxdumptool-build"],
            ["sudo", "bash", "-c", "cd /tmp/hcxdumptool-build && make"],
            ["sudo", "bash", "-c", "cd /tmp/hcxdumptool-build && make install"],
        ]
        for cmd in cmds:
            print(f"[*] {' '.join(cmd[:8])}...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"[!] failed: {result.stderr[-300:] if result.stderr else result.stdout[-300:]}")
                return False
        print("[+] hcxdumptool built from source")
        return True

    def install_all(self) -> bool:
        print("[*] apt-get update...")
        result = subprocess.run(
            ["sudo", "apt-get", "update"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"[!] apt-get update failed (code={result.returncode}):")
            print(result.stdout[-500:] if result.stdout else "")
            print(result.stderr[-500:] if result.stderr else "")
        else:
            print("[+] apt-get update OK")

        print(f"[*] apt-get install {' '.join(self._PACKAGES)}...")
        result = subprocess.run(
            ["sudo", "apt-get", "install", "-y"] + self._PACKAGES,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"[!] apt-get install failed (code={result.returncode}):")
            print(result.stdout[-500:] if result.stdout else "")
            print(result.stderr[-500:] if result.stderr else "")
            return False
        else:
            print("[+] apt-get install OK")

        # Verify critical binaries
        missing = [b for b in self._BINARIES if not shutil.which(b)]
        if "hcxdumptool" in missing:
            print("[*] trying apt-get install hcxdumptool...")
            subprocess.run(
                ["sudo", "apt-get", "install", "-y", "hcxdumptool"],
                capture_output=True,
                text=True,
            )
        if not self._hcxdumptool_supports_manual_mode() and not self._build_hcxtools():
            print("[!] WARNING: compatible hcxdumptool still not available. Handshake attacks can fail.")

        return True

    def check_binaries(self) -> Dict[str, bool]:
        return {b: shutil.which(b) is not None for b in self._BINARIES}
