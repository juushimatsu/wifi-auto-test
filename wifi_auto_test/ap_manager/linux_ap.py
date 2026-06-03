import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .interfaces import IAPManager


class LinuxAPManager(IAPManager):
    def __init__(self, logger=None):
        self._log = logger or (lambda x: None)
        self._hostapd_conf: str = ""
        self._dnsmasq_conf: str = ""
        self._proc_hostapd: subprocess.Popen | None = None
        self._proc_dnsmasq: subprocess.Popen | None = None

    def setup_ap(
        self,
        interface: str,
        ssid: str,
        password: str,
        ip_cidr: str,
        dhcp_range: str,
    ) -> bool:
        self._log(f"[*] Настройка AP на {interface}: {ssid}")

        # Остановить NetworkManager и wpa_supplicant на интерфейсе
        subprocess.run(
            ["sudo", "systemctl", "stop", "wpa_supplicant"],
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "nmcli", "device", "set", interface, "managed", "no"],
            capture_output=True,
        )

        # Назначить IP
        ip_addr = ip_cidr.split("/")[0]
        prefix = ip_cidr.split("/")[1]
        subprocess.run(
            ["sudo", "ip", "addr", "flush", "dev", interface],
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "ip", "addr", "add", ip_cidr, "dev", interface],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "ip", "link", "set", interface, "up"],
            check=True,
            capture_output=True,
        )

        # hostapd конфиг
        hostapd_cfg = tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False)
        hostapd_cfg.write(
            f"interface={interface}\n"
            f"ssid={ssid}\n"
            f"hw_mode=g\n"
            f"channel=7\n"
            f"wpa=2\n"
            f"wpa_passphrase={password}\n"
            f"wpa_key_mgmt=WPA-PSK\n"
            f"rsn_pairwise=CCMP\n"
            f"auth_algs=1\n"
            f"ignore_broadcast_ssid=0\n"
        )
        hostapd_cfg.close()
        self._hostapd_conf = hostapd_cfg.name

        # dnsmasq конфиг
        dnsmasq_cfg = tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False)
        range_parts = dhcp_range.split(",")
        start_ip = range_parts[0]
        end_ip = range_parts[1] if len(range_parts) > 1 else range_parts[0]
        netmask = range_parts[2] if len(range_parts) > 2 else "255.255.255.0"
        lease = range_parts[3] if len(range_parts) > 3 else "12h"
        dnsmasq_cfg.write(
            f"interface={interface}\n"
            f"dhcp-range={start_ip},{end_ip},{netmask},{lease}\n"
            f"dhcp-option=3,{ip_addr}\n"
            f"dhcp-option=6,{ip_addr}\n"
            f"server=8.8.8.8\n"
            f"listen-address={ip_addr}\n"
            f"bind-interfaces\n"
        )
        dnsmasq_cfg.close()
        self._dnsmasq_conf = dnsmasq_cfg.name

        # Запуск hostapd
        self._proc_hostapd = subprocess.Popen(
            ["sudo", "hostapd", self._hostapd_conf],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Запуск dnsmasq
        self._proc_dnsmasq = subprocess.Popen(
            ["sudo", "dnsmasq", "-C", self._dnsmasq_conf],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self._log(f"[+] AP {ssid} запущена на {interface} ({ip_addr})")
        return True

    def stop_ap(self) -> bool:
        self._log("[*] Остановка AP")
        if self._proc_hostapd:
            self._proc_hostapd.terminate()
            try:
                self._proc_hostapd.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc_hostapd.kill()
            self._proc_hostapd = None

        if self._proc_dnsmasq:
            self._proc_dnsmasq.terminate()
            try:
                self._proc_dnsmasq.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc_dnsmasq.kill()
            self._proc_dnsmasq = None

        # Очистка dnsmasq артефактов
        subprocess.run(["sudo", "killall", "-q", "dnsmasq"], capture_output=True)

        for f in [self._hostapd_conf, self._dnsmasq_conf]:
            if f and os.path.exists(f):
                os.unlink(f)

        subprocess.run(
            ["sudo", "nmcli", "device", "set", "wlan1", "managed", "yes"],
            capture_output=True,
        )
        self._log("[+] AP остановлена")
        return True

    def is_client_connected(self) -> bool:
        # Простая проверка: смотрим dhcp leases dnsmasq
        lease_file = "/var/lib/misc/dnsmasq.leases"
        if not os.path.exists(lease_file):
            return False
        try:
            with open(lease_file, "r") as f:
                return bool(f.read().strip())
        except OSError:
            return False
