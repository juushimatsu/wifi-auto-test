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
    ]

    _BINARIES = ["wash", "hcxdumptool", "hostapd", "dnsmasq", "iptables", "airmon-ng"]

    def install_all(self) -> bool:
        try:
            subprocess.run(
                ["sudo", "apt-get", "update"],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["sudo", "apt-get", "install", "-y"] + self._PACKAGES,
                check=True,
                capture_output=True,
                text=True,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def check_binaries(self) -> Dict[str, bool]:
        return {b: shutil.which(b) is not None for b in self._BINARIES}
