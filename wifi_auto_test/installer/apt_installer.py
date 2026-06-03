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
    ]

    _BINARIES = ["wash", "hcxdumptool", "hostapd", "dnsmasq", "iptables", "airmon-ng", "iw", "iwconfig", "rfkill"]

    def install_all(self) -> bool:
        try:
            print("[*] apt-get update...")
            result = subprocess.run(
                ["sudo", "apt-get", "update"],
                check=True,
                capture_output=True,
                text=True,
            )
            print("[*] apt-get install...")
            result = subprocess.run(
                ["sudo", "apt-get", "install", "-y"] + self._PACKAGES,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                print(f"[!] apt-get install failed (code={result.returncode}):")
                print(result.stderr[:500])
                return False
            return True
        except subprocess.CalledProcessError as e:
            print(f"[!] apt-get failed: {e.stderr[:500]}")
            return False

    def check_binaries(self) -> Dict[str, bool]:
        return {b: shutil.which(b) is not None for b in self._BINARIES}
