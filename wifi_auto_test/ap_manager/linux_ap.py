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

        def _try_hostapd(driver: str) -> tuple[bool, int | None]:
            self._log(f"[*] Пробуем hostapd с driver={driver}...")
            conf_path = "/tmp/hostapd-wifi-auto-test.conf"
            with open(conf_path, "w") as f:
                f.write(
                    f"interface={interface}\n"
                    f"driver={driver}\n"
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

            log_path = f"/tmp/hostapd-wifi-auto-test-{driver}.log"
            with open(log_path, "w") as logf:
                proc = subprocess.Popen(
                    ["sudo", "hostapd", "-B", conf_path],
                    stdout=logf,
                    stderr=subprocess.STDOUT,
                )
            time.sleep(1.5)
            if proc.poll() is not None:
                with open(log_path, "r") as f:
                    err = f.read().strip()
                self._log(f"[!] hostapd driver={driver} failed: {err[:500]}")
                return False, None
            return True, proc.pid

        for drv in ("nl80211", "wext"):
            ok, pid = _try_hostapd(drv)
            if ok and pid:
                self._hostapd_pid = pid
                break
        else:
            # Fallback: airbase-ng для адаптеров без nl80211/wext (например Realtek USB)
            if self._setup_ap_airbase_ng(interface, ssid, ip_cidr, dhcp_range):
                return True
            self._log("[!] hostapd не запустился ни с одним драйвером, airbase-ng тоже не сработал")
            return False

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

        # 1. Try nmcli first (works on many adapters via wpa_supplicant/wext)
        if self._setup_ap_nmcli(interface, ssid, password):
            return True

        # 2. Fallback: hostapd
        self._log(f"[!] nmcli failed, trying hostapd")
        if self._setup_ap_hostapd(interface, ssid, password, ip_cidr, dhcp_range):
            return True

        # 3. Last resort: wpa_supplicant directly
        self._log(f"[!] hostapd failed, trying wpa_supplicant")
        if self._setup_ap_wpa_supplicant(interface, ssid, password, ip_cidr, dhcp_range):
            return True

        self._log(f"[!] All AP methods failed for {interface}")
        return False

    def _setup_ap_wpa_supplicant(
        self,
        interface: str,
        ssid: str,
        password: str,
        ip_cidr: str,
        dhcp_range: str,
    ) -> bool:
        """Last-resort AP setup via wpa_supplicant (works with r8188eu / wext)."""
        self._log(f"[*] Настройка AP через wpa_supplicant на {interface}: {ssid}")

        # Disconnect from NM
        subprocess.run(
            ["sudo", "nmcli", "device", "disconnect", interface],
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "nmcli", "device", "set", interface, "managed", "no"],
            capture_output=True,
        )

        # Kill stale processes
        subprocess.run(["sudo", "pkill", "-f", f"wpa_supplicant.*{interface}"], capture_output=True)
        subprocess.run(["sudo", "pkill", "-f", f"dnsmasq.*{interface}"], capture_output=True)
        time.sleep(0.3)

        # Set up IP
        ip, _ = ip_cidr.rsplit("/", 1)
        subprocess.run(["sudo", "ip", "addr", "flush", "dev", interface], capture_output=True)
        subprocess.run(["sudo", "ip", "addr", "add", ip_cidr, "dev", interface], capture_output=True)
        subprocess.run(["sudo", "ip", "link", "set", "dev", interface, "up"], capture_output=True)

        # Create wpa_supplicant config for AP
        conf_path = "/tmp/wpa-supplicant-wifi-auto-test.conf"
        with open(conf_path, "w") as f:
            f.write(
                "ctrl_interface=/var/run/wpa_supplicant\n"
                "ctrl_interface_group=0\n"
                "ap_scan=2\n"
                "\n"
                "network={\n"
                f'    ssid="{ssid}"\n'
                "    mode=2\n"
                "    frequency=2437\n"
                "    key_mgmt=WPA-PSK\n"
                f'    psk="{password}"\n'
                "    proto=RSN\n"
                "    pairwise=CCMP\n"
                "}\n"
            )

        # Start wpa_supplicant
        log_path = "/tmp/wpa-supplicant-wifi-auto-test.log"
        with open(log_path, "w") as logf:
            proc = subprocess.Popen(
                ["sudo", "wpa_supplicant", "-D", "wext", "-i", interface, "-c", conf_path],
                stdout=logf,
                stderr=subprocess.STDOUT,
            )
        time.sleep(2)

        if proc.poll() is not None:
            with open(log_path, "r") as f:
                err = f.read().strip()
            self._log(f"[!] wpa_supplicant failed: {err[:500]}")
            return False

        self._hostapd_pid = proc.pid

        # dnsmasq
        dhcp_start, dhcp_end = dhcp_range.split(",", 1)
        subprocess.run(
            ["sudo", "dnsmasq",
             f"--interface={interface}",
             "--bind-interfaces",
             f"--dhcp-range={dhcp_range}",
             "--conf-file=/dev/null",
             ],
            capture_output=True,
        )

        # NAT
        subprocess.run(
            ["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING",
             "-o", "end0", "-j", "MASQUERADE"],
            capture_output=True,
        )

        self._log(f"[+] AP {ssid} запущена через wpa_supplicant на {interface}")
        return True

    def _setup_ap_airbase_ng(
        self,
        interface: str,
        ssid: str,
        ip_cidr: str,
        dhcp_range: str,
    ) -> bool:
        """Fallback через airbase-ng для адаптеров без nl80211/wext (например RTL8188EUS)."""
        self._log(f"[*] Настройка AP через airbase-ng на {interface}: {ssid}")

        # Отключить от NM и убить старые процессы
        subprocess.run(
            ["sudo", "nmcli", "device", "disconnect", interface],
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "nmcli", "device", "set", interface, "managed", "no"],
            capture_output=True,
        )
        subprocess.run(["sudo", "pkill", "-f", f"airbase-ng.*{ssid}"], capture_output=True)
        subprocess.run(["sudo", "pkill", "-f", f"dnsmasq.*at0"], capture_output=True)
        time.sleep(0.3)

        # Перевести в monitor mode (airbase-ng требует monitor)
        subprocess.run(["sudo", "ip", "link", "set", "dev", interface, "down"], capture_output=True)
        subprocess.run(
            ["sudo", "iwconfig", interface, "mode", "monitor"],
            capture_output=True,
        )
        # fallback через iw если iwconfig не сработал
        subprocess.run(
            ["sudo", "iw", "dev", interface, "set", "type", "monitor"],
            capture_output=True,
        )
        subprocess.run(["sudo", "ip", "link", "set", "dev", interface, "up"], capture_output=True)
        time.sleep(0.5)

        # Запустить airbase-ng (открытая AP — WPA2 не поддерживается airbase-ng)
        log_path = "/tmp/airbase-ng-wifi-auto-test.log"
        with open(log_path, "w") as logf:
            proc = subprocess.Popen(
                ["sudo", "airbase-ng", "-e", ssid, "-c", "6", interface],
                stdout=logf,
                stderr=subprocess.STDOUT,
            )
        time.sleep(2)
        if proc.poll() is not None:
            with open(log_path, "r") as f:
                err = f.read().strip()
            self._log(f"[!] airbase-ng failed: {err[:500]}")
            return False
        self._hostapd_pid = proc.pid  # переиспользуем _hostapd_pid для airbase-ng

        # Настроить tap-интерфейс at0, созданный airbase-ng
        subprocess.run(["sudo", "ip", "addr", "flush", "dev", "at0"], capture_output=True)
        subprocess.run(
            ["sudo", "ip", "addr", "add", ip_cidr, "dev", "at0"],
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "ip", "link", "set", "dev", "at0", "up"],
            capture_output=True,
        )

        # dnsmasq на at0
        subprocess.run(
            ["sudo", "dnsmasq",
             "--interface=at0",
             "--bind-interfaces",
             f"--dhcp-range={dhcp_range}",
             "--conf-file=/dev/null",
             ],
            capture_output=True,
        )

        # NAT
        subprocess.run(
            ["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING",
             "-o", "end0", "-j", "MASQUERADE"],
            capture_output=True,
        )

        self._log(f"[+] AP {ssid} запущена через airbase-ng (открытая сеть) на {interface}")
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
        if self._hostapd_pid:
            subprocess.run(
                ["sudo", "pkill", "-f", f"hostapd.*{self._interface}"],
                capture_output=True,
            )
            subprocess.run(
                ["sudo", "pkill", "-f", f"wpa_supplicant.*{self._interface}"],
                capture_output=True,
            )
            subprocess.run(
                ["sudo", "pkill", "-f", f"airbase-ng.*{self._interface}"],
                capture_output=True,
            )
            subprocess.run(
                ["sudo", "pkill", "-f", f"dnsmasq.*{self._interface}"],
                capture_output=True,
            )
            subprocess.run(
                ["sudo", "pkill", "-f", "dnsmasq.*at0"],
                capture_output=True,
            )
            self._hostapd_pid = None
        self._log("[+] AP остановлена")
        return True

    def is_client_connected(self) -> bool:
        if not self._interface:
            return False
        # 1. Try iw station dump (works for both hostapd and wpa_supplicant)
        result = subprocess.run(
            ["sudo", "iw", "dev", self._interface, "station", "dump"],
            capture_output=True, text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            return len(result.stdout.strip().splitlines()) > 0
        # 2. Fallback: hostapd_cli list_sta
        result = subprocess.run(
            ["sudo", "hostapd_cli", "-i", self._interface, "list_sta"],
            capture_output=True, text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            return True
        # 3. Fallback: wpa_cli all_sta
        result = subprocess.run(
            ["sudo", "wpa_cli", "-i", self._interface, "all_sta"],
            capture_output=True, text=True,
        )
        if result.returncode == 0 and result.stdout.strip() and "dot11RSNAStatsSTAAddress" in result.stdout:
            return True
        # 4. Last resort: check ARP table for stations on AP subnet
        result = subprocess.run(
            ["sudo", "ip", "neigh", "show", "dev", self._interface],
            capture_output=True, text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().splitlines():
                if "REACHABLE" in line or "STALE" in line:
                    return True
        return False
