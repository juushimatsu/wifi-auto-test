import os
import subprocess
import time

from .interfaces import IAPManager


class LinuxAPManager(IAPManager):
    """AP через NetworkManager — не трогает другие интерфейсы."""

    def __init__(self, logger=None):
        self._log = logger or (lambda x: None)
        self._interface: str | None = None
        self._con_name: str = ""

    def setup_ap(
        self,
        interface: str,
        ssid: str,
        password: str,
        ip_cidr: str,
        dhcp_range: str,
    ) -> bool:
        self._interface = interface
        self._con_name = f"wifi-auto-test-{ssid.replace(' ', '-')[:20]}"
        self._log(f"[*] Настройка AP через nmcli на {interface}: {ssid}")

        # Удалить старое соединение
        subprocess.run(
            ["sudo", "nmcli", "connection", "delete", self._con_name],
            capture_output=True,
        )

        # Создать AP-соединение
        result = subprocess.run(
            [
                "sudo", "nmcli", "connection", "add",
                "type", "wifi",
                "ifname", interface,
                "con-name", self._con_name,
                "autoconnect", "no",
                "ssid", ssid,
                "802-11-wireless.mode", "ap",
                "802-11-wireless.band", "bg",
                "802-11-wireless-security.key-mgmt", "wpa-psk",
                "802-11-wireless-security.psk", password,
                "ipv4.method", "shared",
            ],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            self._log(f"[!] nmcli add failed: {result.stderr.strip()[:300]}")
            return False

        # Активировать
        result = subprocess.run(
            ["sudo", "nmcli", "connection", "up", self._con_name],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            self._log(f"[!] nmcli up failed: {result.stderr.strip()[:300]}")
            return False

        self._log(f"[+] AP {ssid} запущена через nmcli на {interface}")
        return True

    def stop_ap(self) -> bool:
        self._log("[*] Остановка AP")
        if self._con_name:
            subprocess.run(
                ["sudo", "nmcli", "connection", "down", self._con_name],
                capture_output=True,
            )
            subprocess.run(
                ["sudo", "nmcli", "connection", "delete", self._con_name],
                capture_output=True,
            )
            self._con_name = ""
        self._log("[+] AP остановлена")
        return True

    def is_client_connected(self) -> bool:
        if not self._con_name:
            return False
        result = subprocess.run(
            ["sudo", "nmcli", "connection", "show", "--active"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            return self._con_name in result.stdout
        return False
