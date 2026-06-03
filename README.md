# WiFi Auto Test

Автоматизированная утилита для тестирования Wi-Fi сетей на уязвимость к PMKID-атаке с использованием `hcxdumptool`.

## Требования

- Orange Pi Zero 2W (или любой Linux SBC) с 2 Wi-Fi адаптерами:
  - Один в monitor mode для сканирования/атаки
  - Один в AP mode для web-панели управления
- Python 3.10+
- Ubuntu/Debian или Arch Linux

## Установка

```bash
# На Windows-машине разработчика: скачать зависимости для offline-установки
pip download -r requirements.txt -d ./offline_packages/

# Перенести проект и offline_packages на Orange Pi
scp -r wifi_auto_test/ offline_packages/ orangepi@<ip>:~/wifi-auto-test/

# На Orange Pi
pip install --no-index --find-links ./offline_packages/ -r requirements.txt
sudo python3 main.py --install-deps --test-interface wlp2s0f0u6mon --ap-interface wlp2s0f0u7
```

## Запуск

```bash
sudo python3 main.py \
  --test-interface wlp2s0f0u6mon \
  --ap-interface wlp2s0f0u7 \
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
