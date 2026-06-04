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

    def _build_hcxtools(self) -> bool:
        """Fallback: build hcxtools from source if apt package lacks hcxdumptool."""
        print("[*] hcxdumptool not found after apt install, building from source...")
        cmds = [
            ["sudo", "rm", "-rf", "/tmp/hcxtools-build"],
            ["sudo", "git", "clone", "https://github.com/zerbea/hcxtools.git", "/tmp/hcxtools-build"],
            ["sudo", "bash", "-c", "cd /tmp/hcxtools-build && make"],
            ["sudo", "bash", "-c", "cd /tmp/hcxtools-build && make install"],
        ]
        for cmd in cmds:
            print(f"[*] {' '.join(cmd[:8])}...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"[!] failed: {result.stderr[-300:] if result.stderr else result.stdout[-300:]}")
                return False
        print("[+] hcxtools built from source")
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
            if not self._build_hcxtools():
                print("[!] WARNING: hcxdumptool still not available. PMKID attacks will fail.")

        return True

    def check_binaries(self) -> Dict[str, bool]:
        return {b: shutil.which(b) is not None for b in self._BINARIES}
