import os
import subprocess
import time

from .interfaces import IAPManager


class LinuxAPManager(IAPManager):
    """AP через NetworkManager (nmcli) или fallback на hostapd."""

    def __init__(self, logger=None):
        self._log = logger or (lambda x: None)
        self._interface: str | None = None
        self._con_name: str = ""
        self._hostapd_pid: int | None = None

    def _supports_ap_via_nm(self, interface: str) -> bool:
        """Проверяем, может ли устройство работать в AP mode через nmcli."""
        result = subprocess.run(
            ["sudo", "iw", interface, "info"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            return False
        return "AP/VLAN" in result.stdout

    def _setup_ap_nmcli(
        self,
        interface: str,
        ssid: str,
        password: str,
    ) -> bool:
        self._con_name = f"wifi-auto-test-{ssid.replace(' ', '-')[:20]}"

        # Отключить интерфейс от текущего клиентского соединения NM
        subprocess.run(
            ["sudo", "nmcli", "device", "disconnect", interface],
            capture_output=True,
        )
        time.sleep(0.5)

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

        # Активировать, явно указав устройство
        result = subprocess.run(
            ["sudo", "nmcli", "connection", "up", self._con_name, "ifname", interface],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            self._log(f"[!] nmcli up failed: {result.stderr.strip()[:300]}")
            return False

        self._log(f"[+] AP {ssid} запущена через nmcli на {interface}")
        return True

    def _setup_ap_hostapd(
        self,
        interface: str,
        ssid: str,
        password: str,
        ip_cidr: str,
        dhcp_range: str,
    ) -> bool:
        self._log(f"[*] Настройка AP через hostapd на {interface}: {ssid}")
        # Отключить от NM
        subprocess.run(
            ["sudo", "nmcli", "device", "disconnect", interface],
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "nmcli", "device", "set", interface, "managed", "no"],
            capture_output=True,
        )

        # Kill lingering hostapd/dnsmasq
        subprocess.run(["sudo", "pkill", "-f", f"hostapd.*{interface}"], capture_output=True)
        subprocess.run(["sudo", "pkill", "-f", f"dnsmasq.*{interface}"], capture_output=True)
        time.sleep(0.3)

        # Настроить IP
        ip, prefix = ip_cidr.rsplit("/", 1)
        subprocess.run(["sudo", "ip", "addr", "flush", "dev", interface], capture_output=True)
        subprocess.run(
            ["sudo", "ip", "addr", "add", ip_cidr, "dev", interface],
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "ip", "link", "set", "dev", interface, "up"],
            capture_output=True,
        )

        # Сохранить hostapd.conf
        conf_path = "/tmp/hostapd-wifi-auto-test.conf"
        with open(conf_path, "w") as f:
            f.write(
                f"interface={interface}\n"
                f"driver=nl80211\n"
                f"ssid={ssid}\n"
                f"hw_mode=g\n"
                f"channel=6\n"
                f"wpa=2\n"
                f"wpa_passphrase={password}\n"
                f"wpa_key_mgmt=WPA-PSK\n"
                f"rsn_pairwise=CCMP\n"
                f"auth_algs=1\n"
                f"ignore_broadcast_ssid=0\n"
            )

        # Запустить hostapd
        log_path = "/tmp/hostapd-wifi-auto-test.log"
        with open(log_path, "w") as logf:
            proc = subprocess.Popen(
                ["sudo", "hostapd", "-B", conf_path],
                stdout=logf,
                stderr=subprocess.STDOUT,
            )
        time.sleep(1)
        if proc.poll() is not None:
            with open(log_path, "r") as f:
                err = f.read().strip()
            self._log(f"[!] hostapd failed to start: {err[:500]}")
            return False
        self._hostapd_pid = proc.pid

        # dnsmasq
        dhcp_start, dhcp_end = dhcp_range.split(",", 1)
        subprocess.run(
            ["sudo", "dnsmasq",
             "--interface={interface}".format(interface=interface),
             "--bind-interfaces",
             "--dhcp-range={range}".format(range=dhcp_range),
             "--conf-file=/dev/null",
             ],
            capture_output=True,
        )

        # NAT (если есть uplink)
        subprocess.run(
            ["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING",
             "-o", "end0", "-j", "MASQUERADE"],
            capture_output=True,
        )

        self._log(f"[+] AP {ssid} запущена через hostapd на {interface}")
        return True

    def setup_ap(
        self,
        interface: str,
        ssid: str,
        password: str,
        ip_cidr: str,
        dhcp_range: str,
    ) -> bool:
        self._interface = interface

        if self._supports_ap_via_nm(interface):
            return self._setup_ap_nmcli(interface, ssid, password)
        else:
            self._log(f"[!] Устройство не поддерживает AP через nmcli, используем hostapd")
            return self._setup_ap_hostapd(interface, ssid, password, ip_cidr, dhcp_range)

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
        if self._hostapd_pid:
            subprocess.run(
                ["sudo", "pkill", "-f", f"hostapd.*{self._interface}"],
                capture_output=True,
            )
            subprocess.run(
                ["sudo", "pkill", "-f", f"dnsmasq.*{self._interface}"],
                capture_output=True,
            )
            self._hostapd_pid = None
        self._log("[+] AP остановлена")
        return True

    def is_client_connected(self) -> bool:
        if not self._interface:
            return False
        # Проверяем station count через hostapd_cli или iw
        result = subprocess.run(
            ["sudo", "iw", "dev", self._interface, "station", "dump"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            return len(result.stdout.strip().splitlines()) > 0
        return False
