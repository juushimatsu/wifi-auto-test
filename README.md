# WiFi Auto Test

Автоматизированная утилита для тестирования Wi-Fi сетей на уязвимость к PMKID-атаке с использованием `hcxdumptool`.

## Требования

- Linux SBC или ПК с 2 Wi-Fi адаптерами:
  - Один в monitor mode для сканирования/атаки
  - Один в AP mode для web-панели управления
- Python 3.10+
- Ubuntu/Debian или Arch Linux

## Установка

```bash
git clone https://github.com/juushimatsu/wifi-auto-test.git
cd wifi-auto-test
pip install -r requirements.txt

sudo python3 main.py --install-deps --test-interface <monitor-interface> --ap-interface <ap-interface>
```

## Запуск

```bash
sudo python3 main.py \
  --test-interface <monitor-interface> \
  --ap-interface <ap-interface> \
  --ap-ssid "WiFiTestAP" \
  --ap-password "test1234"
```

Подключитесь к точке доступа `WiFiTestAP` и откройте в браузере:
http://192.168.4.1/

## Архитектура

Модули построены по SOLID-принципам с DI:
- `config/` — JSON-конфигурация
- `core/` — модели и оркестратор
- `scanner/` — `wash` для обнаружения сетей
- `attack/` — `hcxdumptool` для PMKID-атаки
- `state/` — SQLite-хранилище результатов
- `web/` — FastAPI + vanilla JS панель
- `ap_manager/` — `hostapd` + `dnsmasq`
- `installer/` — автоустановка зависимостей
- `logger/` — файловое логирование + WebSocket

## Команды web-панели

- **Пуск** — запуск/продолжение цикла сканирования и атаки
- **Стоп** — пауза после текущей сети
- **Приоритет** — тестировать выбранную сеть следующей
