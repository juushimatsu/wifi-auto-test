# План разработки утилиты WiFi Auto Test

## 1. Общее описание проекта

Утилита на Python для автоматизированного тестирования ближайших Wi-Fi сетей на уязвимость к PMKID-атаке с использованием `hcxdumptool`. Разработка ведётся на Windows 11, целевая платформа — Orange Pi Zero 2W под управлением Ubuntu/Arch Linux. Управление осуществляется через локальную web-панель на втором Wi-Fi адаптере, работающем в режиме точки доступа.

---

## 2. Архитектурные принципы (SOLID)

| Принцип | Применение в проекте |
|---------|---------------------|
| **SRP** | Каждый модуль отвечает за одну задачу: сканирование, выполнение атаки, хранение состояния, web-интерфейс, управление сетью. |
| **OCP** | Модули расширяются через интерфейсы/абстрактные классы: новые типы атак, новые парсеры вывода, новые бэкенды хранилища добавляются без изменения существующего кода. |
| **LSP** | Все реализации сканеров, атак и хранилищ взаимозаменяемы через единые интерфейсы. |
| **ISP** | Интерфейсы мелкие и специализированные: `IScanner`, `IAttackEngine`, `IStateRepository`, `IConfigStore`, `IAPManager`. |
| **DIP** | Основной оркестратор зависит от абстракций, а не от конкретных реализаций. Внедрение зависимостей через конструкторы. |

---

## 3. Структура проекта

```
wifi_auto_test/
├── main.py                  # Точка входа, инициализация DI-контейнера
├── config/
│   ├── __init__.py
│   ├── interfaces.py          # Абстракции конфигурации (IConfigStore)
│   ├── json_config.py         # Реализация хранения настроек в JSON
│   └── default_settings.py    # Значения по умолчанию
├── core/
│   ├── __init__.py
│   ├── interfaces.py          # Центральные абстракции (IScanner, IAttackEngine, ITarget)
│   ├── models.py              # Dataclasses: WiFiNetwork, TestResult, SessionState
│   └── orchestrator.py        # Главный цикл сканирования → тестирования → сканирования
├── scanner/
│   ├── __init__.py
│   ├── interfaces.py          # IScanner, INetworkParser
│   ├── wash_scanner.py        # Реализация через `wash -i <iface>`
│   └── wash_parser.py         # Парсер stdout wash в список WiFiNetwork
├── attack/
│   ├── __init__.py
│   ├── interfaces.py          # IAttackEngine
│   ├── hcxdump_attack.py      # Реализация через hcxdumptool
│   └── output_parser.py       # Парсер stdout hcxdumptool (M1M2E2 / M1M4)
├── state/
│   ├── __init__.py
│   ├── interfaces.py          # IStateRepository
│   └── sqlite_repo.py         # SQLite-хранилище: сети, результаты, сессии
├── web/
│   ├── __init__.py
│   ├── server.py              # FastAPI/Flask приложение
│   ├── routes.py              # API endpoints
│   ├── static/                # HTML/CSS/JS для панели управления
│   └── ws_manager.py          # WebSocket для логов в реальном времени
├── ap_manager/
│   ├── __init__.py
│   ├── interfaces.py          # IAPManager
│   └── linux_ap.py            # Настройка AP через hostapd + dnsmasq + iptables
├── installer/
│   ├── __init__.py
│   ├── interfaces.py          # IDependencyInstaller
│   ├── apt_installer.py       # Ubuntu/Debian
│   └── pacman_installer.py    # Arch Linux
├── logger/
│   ├── __init__.py
│   ├── interfaces.py          # ILogger, ITerminalBridge
│   └── file_ws_logger.py      # Запись в файл + broadcast через WebSocket
└── utils/
    ├── __init__.py
    └── process_runner.py      # Утилита для запуска subprocess с таймаутом и streaming stdout
```

---

## 4. Описание модулей

### 4.1 `config` — Конфигурация

- **IConfigStore**: интерфейс с методами `get(key)`, `set(key, value)`, `save()`.
- **JsonConfigStore**: хранит `settings.json` с полями:
  - `test_interface` — интерфейс для тестирования (wash/hcxdumptool)
  - `ap_interface` — интерфейс для точки доступа web-панели
  - `ap_ssid`, `ap_password` — параметры точки доступа
  - `attack_timeout_seconds` — таймаут ожидания кадров (по умолчанию 60)
  - `output_dir` — директория для `.pcapng` и логов
- При старте утилита читает `settings.json`. Если файла нет — создаётся с дефолтами.

### 4.2 `core` — Ядро оркестрации

- **WiFiNetwork**: `bssid`, `ssid`, `channel`, `signal_dbm`, `security`.
- **TestResult**: `network`, `status` (success/failure/timeout), `pcap_file`, `timestamp`, `captured_frames`.
- **SessionState**: текущий список сетей, индекс тестируемой сети, флаг "running/stopped".
- **Orchestrator**:
  1. Загружает из `IStateRepository` список ранее успешных/неуспешных сетей.
  2. Запускает `IScanner` → получает актуальный список сетей.
  3. Фильтрует: исключает сети со `status=success` (тест уже пройден, pcapng получен).
  4. Сортирует по `signal_dbm` (от наименьшего отрицательного к наибольшему).
  5. Для каждой сети вызывает `IAttackEngine.run(network)`.
  6. Если `status=success` → записывает в репозиторий, переходит к следующей.
  7. Если `status=failure` или `timeout` → записывает в репозиторий как `pending_retry`, переходит к следующей.
  8. После прохода по всем сетям → возвращается к шагу 2.
  9. Слушает команды из web-панели: STOP (пауза после текущей сети), START (продолжить), PRIORITIZE (вручную задать порядок).

### 4.3 `scanner` — Обнаружение сетей

- **WashScanner** (реализация `IScanner`):
  - Запускает `sudo wash -i <iface> -f` (или без `-f` для passive).
  - Читает stdout построчно через `ProcessRunner`.
  - Парсит строки формата: `BSSID`, `ESSID`, `Channel`, `RSSI`, `Encryption`.
  - Собирает уникальные сети за заданный интервал (например, 15 секунд).
  - Возвращает `List[WiFiNetwork]`.

### 4.4 `attack` — Выполнение PMKID-атаки

- **HcxdumpAttack** (реализация `IAttackEngine`):
  - Метод `run(network: WiFiNetwork) -> TestResult`:
    - Формирует команду: `sudo hcxdumptool -i <iface> -c <channel>a -w <output_dir>/<ssid_bssid>.pcapng --rds=4`
    - Запускает процесс через `ProcessRunner`.
    - Читает stdout/stderr в реальном времени.
    - Ищет паттерны: `M1M2E2` или `M1M4` (успех), `M12ROGUE`/`M12` (не факт успеха, но активность).
    - **Условие успеха**: обнаружен `M1M2E2` или `M1M4` в течение `attack_timeout_seconds`.
    - **Условие failure**: таймаут истёк, нужные кадры не получены.
    - По завершении корректно завершает subprocess (SIGTERM → SIGKILL).
    - Возвращает `TestResult` с путём к `.pcapng`.

### 4.5 `state` — Персистентность

- **SqliteStateRepository** (реализация `IStateRepository`):
  - Таблица `networks`: `bssid` (PK), `ssid`, `last_signal_dbm`, `last_seen`, `overall_status` (success/pending_retry/excluded).
  - Таблица `test_runs`: `id`, `bssid`, `timestamp`, `status`, `pcap_file`, `log_excerpt`.
  - Методы:
    - `upsert_network(network, status)` — добавить/обновить сеть.
    - `get_pending_networks()` — получить сети со статусом `pending_retry`.
    - `get_successful_bssids()` — получить список BSSID с `success` (для фильтрации).
    - `get_network_history(bssid)` — история тестов по сети.

### 4.6 `ap_manager` — Точка доступа управления

- **LinuxAPManager** (реализация `IAPManager`):
  - Метод `setup_ap(interface, ssid, password)`:
    - Останавливает NetworkManager/wpa_supplicant на данном интерфейсе.
    - Назначает статический IP (`192.168.4.1/24`).
    - Запускает `hostapd` с конфигом (генерируется временный `.conf`).
    - Запускает `dnsmasq` для DHCP (диапазон `192.168.4.10-50`).
    - Настраивает `iptables` для NAT если нужен выход в интернет (в нашем случае — локальный доступ без NAT).
  - Метод `stop_ap()` — убивает процессы, очищает iptables, поднимает NetworkManager обратно.
  - Метод `is_client_connected() -> bool` — для индикации на web-панели.

### 4.7 `web` — Панель управления

- **WebServer** (FastAPI):
  - **GET /** — загружает `index.html` (SPA или server-rendered).
  - **GET /api/status** — текущий статус оркестратора (running/stopped/paused), текущая тестируемая сеть, очередь.
  - **GET /api/networks** — список всех видимых сетей с историей.
  - **POST /api/command** — принимает JSON-команды: `{ "action": "start" | "stop" | "restart" | "prioritize", "bssid": "..." }`.
  - **GET /api/logs** — SSE (Server-Sent Events) или WebSocket для стриминга логов в реальном времени.
  - **GET /api/hcxdumptool_logs** — логи текущего/последнего запуска hcxdumptool.
  - **POST /api/settings** — обновление настроек (интерфейсы, таймауты).
  - **GET /api/pcapng/{filename}** — скачивание полученных `.pcapng`.
  - **WebSocket /ws/terminal** — мост к запуску произвольных команд? Или только логи. **Уточнение безопасности**: лучше не давать произвольный shell через web. Вместо этого — read-only логи + управляющие команды через REST.
- **Frontend** (минимальный HTML+JS, без внешних CDN, чтобы работать без интернета):
  - Статус оркестратора (круглый индикатор).
  - Таблица сетей: SSID, BSSID, уровень сигнала, статус (тестируется/в очереди/успех/неуспех), кнопка "Тестировать сейчас".
  - Журнал событий (автоскролл).
  - Кнопки управления: ▶️ Пуск, ⏸️ Стоп, 🔄 Перезапуск.
  - Настройки: селекторы интерфейсов.

### 4.8 `installer` — Установка зависимостей

- **IDependencyInstaller**: метод `install_all() -> bool`.
- **AptInstaller**: `apt-get install -y aircrack-ng hcxtools hostapd dnsmasq iptables python3-pip ...`.
- **PacmanInstaller**: `pacman -S --noconfirm aircrack-ng hcxtools hostapd dnsmasq iptables python-pip ...`.
- Детекция системы: читает `/etc/os-release`, ищет `ID=ubuntu/debian` или `ID=arch`.
- Дополнительно проверяет наличие Python-зависимостей (`fastapi`, `uvicorn`, `jinja2` etc.) и ставит через `pip` если нужно.

### 4.9 `logger` — Логирование и мост

- **FileWebSocketLogger**:
  - Пишет всё в `wifi_auto_test/logs/<datetime>.log`.
  - Одновременно broadcast через `WebSocketManager` подключённым клиентам.
  - Уровни: DEBUG, INFO, WARNING, ERROR.

### 4.10 `utils` — Запуск внешних процессов

- **ProcessRunner**:
  - `run(command: List[str], timeout: int, on_stdout: Callable, on_stderr: Callable, cwd=None) -> int`.
  - Запускает `subprocess.Popen` с `stdout=PIPE, stderr=PIPE`.
  - Отдельные потоки читают PIPE и вызывают колбэки.
  - Поддержка graceful termination: `terminate()` → `SIGTERM`, потом `SIGKILL`.

---

## 5. Этапы разработки

### Этап 1 — Инфраструктура и DI (День 1–2)
- [ ] Создать структуру папок.
- [ ] Определить все интерфейсы (`interfaces.py` в каждом пакете).
- [ ] Реализовать `ProcessRunner` с таймаутами и streaming.
- [ ] Реализовать `JsonConfigStore`.
- [ ] Создать простой DI-контейнер в `main.py` (ручной, без сторонних библиотек для минимизации зависимостей).

### Этап 2 — Сканер и парсер (День 2–3)
- [ ] Реализовать `WashScanner` и `WashParser`.
- [ ] Протестировать на Linux: запуск `wash`, парсинг BSSID/SSID/Channel/dBm.
- [ ] Обработка случая, когда `wash` требует `sudo`.

### Этап 3 — Движок атаки (День 3–4)
- [ ] Реализовать `HcxdumpAttack`.
- [ ] Настроить парсер stdout для вылавливания `M1M2E2`, `M1M4`.
- [ ] Реализовать логику таймаута 60 секунд.
- [ ] Проверить на Linux с реальными сетями: получается ли pcapng при уязвимости.
- [ ] Убедиться, что процесс hcxdumptool корректно убивается при таймауте.

### Этап 4 — Хранилище состояния (День 4)
- [ ] Реализовать `SqliteStateRepository`.
- [ ] Методы фильтрации успешных/неуспешных сетей.
- [ ] Проверить персистентность между перезапусками утилиты.

### Этап 5 — Оркестратор (День 5)
- [ ] Реализовать главный цикл `Orchestrator`.
- [ ] Логика: скан → фильтр (исключить success) → сортировка по сигналу → атака → сохранить результат → повтор.
- [ ] Обработка команд STOP/START.

### Этап 6 — AP Manager (День 6)
- [ ] Реализовать `LinuxAPManager`.
- [ ] Генерация конфигов `hostapd.conf`, `dnsmasq.conf`.
- [ ] Скрипты настройки/уборки интерфейса.
- [ ] Тест на Orange Pi: подключение телефона к AP.

### Этап 7 — Web-панель backend (День 7–8)
- [ ] Выбрать FastAPI (меньше зависимостей, встроенный Uvicorn, async).
- [ ] Реализовать REST endpoints: status, networks, command, logs.
- [ ] Реализовать WebSocket для стриминга логов.
- [ ] Связать с оркестратором (команды STOP/START/PRIORITIZE).

### Этап 8 — Web-панель frontend (День 8–9)
- [ ] Создать HTML/CSS/JS в `web/static/` (без внешних зависимостей).
- [ ] Страница: таблица сетей, индикаторы статуса, кнопки управления, окно логов.
- [ ] JavaScript: polling статуса + WebSocket для логов.
- [ ] Скачивание pcapng.

### Этап 9 — Установщик зависимостей (День 9)
- [ ] Реализовать `AptInstaller` и `PacmanInstaller`.
- [ ] Детекция ОС.
- [ ] Проверка наличия бинарников (`wash`, `hcxdumptool`, `hostapd`, `dnsmasq`).
- [ ] Автоустановка при первом запуске (или по флагу `--install-deps`).

### Этап 10 — Интеграция и тестирование на Orange Pi (День 10–12)
- [ ] Перенос кода на Orange Pi Zero 2W.
- [ ] Установка зависимостей через утилиту.
- [ ] Тестирование полного цикла: AP → подключение телефона → web-панель → запуск сканирования → PMKID тест.
- [ ] Проверка корректности остановки/перезапуска через web.
- [ ] Тест персистентности: перезапуск утилиты, проверка что успешные сети пропускаются.

### Этап 11 — Рефакторинг и документация (День 13)
- [ ] Проверка соответствия SOLID.
- [ ] Написание README.md с инструкциями по установке и запуску.
- [ ] Добавление комментариев к интерфейсам.

---

## 6. Технические детали реализации

### 6.1 Потоки/асинхронность

- **Оркестратор** работает в отдельном потоке (`threading.Thread`) или как `asyncio` Task, чтобы не блокировать web-сервер.
- **ProcessRunner** использует `threading` для чтения PIPE, чтобы избежать deadlock при заполнении буфера.
- **WebSocket** через `fastapi.WebSocket` + `asyncio.Queue` для передачи логов от синхронного потока в async.

### 6.2 Безопасность web-панели

- Web-панель доступна только на `192.168.4.1` (AP-интерфейс).
- Базовая аутентификация (HTTP Basic Auth или простой пароль в POST) — учитывая отсутствие интернета, сложная аутентификация не нужна, но не стоит оставлять панель совсем открытой.
- Никакого произвольного выполнения shell-команд через web.

### 6.3 Условие успешного теста (уточнение)

Успешным считается тест, если в stdout `hcxdumptool` обнаружены строки, содержащие:
- `M1M2E2` — получен PMKID
- `M1M4` — альтернативный успешный кадр

При этом утилита фиксирует success и сохраняет `.pcapng`. Если за 60 секунд ни один из паттернов не найден — `failure/timeout`, сеть помечается как `pending_retry`.

### 6.4 Сохранение pcapng

Имя файла: `<timestamp>_<ssid_sanitized>_<bssid>.pcapng`.
Путь: берётся из настроек (`output_dir`, по умолчанию `./captures/`).

### 6.5 Запуск утилиты

```bash
sudo python3 main.py --config settings.json
```

При первом запуске, если `settings.json` не существует:
1. Утилита запрашивает/проверяет наличие необходимых утилит.
2. Предлагает установить зависимости (`--install-deps`).
3. Запрашивает у пользователя (или берёт из аргументов CLI) `test_interface` и `ap_interface`.
4. Сохраняет в `settings.json`.
5. Поднимает AP на `ap_interface`.
6. Запускает web-сервер.
7. Запускает оркестратор.

### 6.6 Аргументы CLI

```
python3 main.py \
  --test-interface wlp2s0f0u6mon \
  --ap-interface wlp2s0f0u7 \
  --ap-ssid "WiFiTestAP" \
  --ap-password "test1234" \
  --install-deps \
  --headless            # не поднимать AP (если управление через SSH)
```

---

## 7. Используемые технологии

| Компонент | Технология |
|-----------|------------|
| Язык | Python 3.10+ |
| Web-фреймворк | FastAPI + Uvicorn |
| Frontend | Vanilla JS + HTML5 + CSS3 (встроены в проект, нет CDN) |
| Хранилище | SQLite (встроен в Python) |
| Конфигурация | JSON-файл |
| AP | hostapd + dnsmasq + iptables |
| Внешние инструменты | wash, hcxdumptool (hcxtools), aircrack-ng |

---

## 8. Риски и ограничения

- `hcxdumptool` требует root-привилегий и monitor mode на интерфейсе. Утилита должна сама переводить интерфейс в monitor mode (`airmon-ng` или `ip link set ... type monitor`) перед работой и возвращать в managed при остановке.
- Некоторые Wi-Fi чипсеты (особенно встроенные) не поддерживают monitor mode. Утилита должна проверять это при старте.
- Вторая точка доступа (`AP` интерфейс) должен поддерживать AP mode. Встроенный Wi-Fi Orange Pi может оказаться занят тестированием, поэтому **два адаптера критичны**.
- Без интернета на Orange Pi все Python-зависимости должны быть предустановлены или перенесены через `requirements.txt` + `pip download` на Windows-машине.

---

## 9. Файлы для ручного переноса на Orange Pi

На Windows-машине разработчика:
```bash
# Скачать зависимости для оффлайн установки
pip download -r requirements.txt -d ./offline_packages/
```

На Orange Pi:
```bash
pip install --no-index --find-links ./offline_packages/ -r requirements.txt
```

---

## 10. Критерии завершённости

- [ ] Утилита устанавливает зависимости автоматически на Ubuntu/Arch.
- [ ] После запуска поднимается AP, телефон к нему подключается.
- [ ] Web-панель открывается по `192.168.4.1`.
- [ ] Из панели видны сети, можно запустить/остановить тест.
- [ ] Утилита тестирует сети по убыванию сигнала.
- [ ] Успешно протестированные сети не тестируются повторно.
- [ ] Неуспешные сети повторно тестируются в следующем цикле.
- [ ] Логи и pcapng доступны через web-панель.
- [ ] Перезапуск утилиты сохраняет все настройки и историю.
