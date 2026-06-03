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

        return True

    def check_binaries(self) -> Dict[str, bool]:
        return {b: shutil.which(b) is not None for b in self._BINARIES}
