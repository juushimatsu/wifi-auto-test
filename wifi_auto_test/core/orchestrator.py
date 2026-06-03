import threading
import time
from typing import Callable, List, Optional

from wifi_auto_test.config.interfaces import IConfigStore
from wifi_auto_test.core.interfaces import IAttackEngine, IScanner
from wifi_auto_test.core.models import SessionState, TestResult, TestStatus, WiFiNetwork
from wifi_auto_test.state.interfaces import IStateRepository


class Orchestrator:
    def __init__(
        self,
        scanner: IScanner,
        attack_engine: IAttackEngine,
        state_repo: IStateRepository,
        config: IConfigStore,
        logger: Optional[Callable[[str], None]] = None,
    ):
        self._scanner = scanner
        self._attack = attack_engine
        self._repo = state_repo
        self._config = config
        self._log = logger or (lambda x: None)
        self._state = SessionState()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._priority_bssid: Optional[str] = None

    @property
    def state(self) -> SessionState:
        return self._state

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            self._log("[!] Оркестратор уже работает")
            return
        self._stop_event.clear()
        self._state.running = True
        self._state.paused = False
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self._log("[+] Оркестратор запущен")

    def stop(self) -> None:
        self._state.paused = True
        self._log("[*] Оркестратор остановлен (пауза после текущей сети)")

    def restart(self) -> None:
        self._state.paused = False
        if not self._thread or not self._thread.is_alive():
            self.start()
        else:
            self._log("[+] Оркестратор продолжает работу")

    def prioritize(self, bssid: str) -> None:
        self._priority_bssid = bssid
        self._log(f"[*] Приоритет задан: {bssid}")

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            if self._state.paused:
                time.sleep(1)
                continue

            try:
                self._state.running = True
                self._run_cycle()
            except Exception as e:
                self._log(f"[!] Ошибка цикла: {e}")
                time.sleep(5)

        self._state.running = False
        self._log("[*] Оркестратор завершён")

    def _run_cycle(self) -> None:
        self._log("[*] Начало цикла сканирования")
        networks = self._scanner.scan()
        self._state.total_scanned += len(networks)
        self._log(f"[*] Найдено сетей: {len(networks)}")

        if not networks:
            time.sleep(5)
            return

        # Фильтрация успешных
        success_bssids = set(self._repo.get_successful_bssids())
        pending = [n for n in networks if n.bssid not in success_bssids]

        # Сортировка по сигналу (от наименьшего отрицательного к наибольшему)
        pending.sort(key=lambda n: n.signal_dbm, reverse=True)

        # Приоритет
        if self._priority_bssid:
            for i, n in enumerate(pending):
                if n.bssid == self._priority_bssid:
                    pending.insert(0, pending.pop(i))
                    self._priority_bssid = None
                    break

        self._state.queue = pending

        for network in pending:
            if self._state.paused:
                self._log("[*] Пауза, остановка цикла")
                return

            self._state.current_network = network
            self._log(f"[*] Тестирование {network.ssid} ({network.bssid}) ch={network.channel}")

            result = self._attack.run(network)
            self._repo.add_test_run(result)

            if result.status == TestStatus.SUCCESS:
                self._log(f"[+] Успех: {network.ssid} — {result.pcap_file}")
                self._repo.upsert_network(network, TestStatus.SUCCESS)
                self._state.total_success += 1
            else:
                self._log(f"[-] Неудача: {network.ssid} — {result.status.value}")
                self._repo.upsert_network(network, TestStatus.PENDING_RETRY)
                self._state.total_failure += 1

        self._state.current_network = None
