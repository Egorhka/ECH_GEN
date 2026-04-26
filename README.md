# ECH Traffic Generator — генератор размеченного датасета

## Что делает

Автоматически генерирует сетевой трафик 4 классов и записывает его в pcap
с автоматической разметкой. Каждый сценарий → отдельный pcap → все потоки
в нём принадлежат одному классу.

| Класс | Что генерирует | Как |
|---|---|---|
| HTTPS | Обычный веб-браузинг | Playwright открывает сайты, скроллит, кликает |
| VIDEO | Потоковое видео | YouTube — воспроизведение видео |
| STREAM | Live-стриминг | Twitch — просмотр стримов |
| MESSENGER | Мессенджеры | Telegram Web, WhatsApp Web, Discord |

## Установка (Ubuntu 22.04 / 24.04)

```bash
sudo bash install.sh
```

## Использование

```bash
# Все классы, 3 раунда каждый
sudo python3 traffic_generator.py

# Только VIDEO и HTTPS, 5 раундов
sudo python3 traffic_generator.py --classes VIDEO HTTPS --rounds 5

# С перемешиванием порядка сценариев
sudo python3 traffic_generator.py --shuffle --rounds 10

# Указать интерфейс
sudo python3 traffic_generator.py --interface ens33
```

## Сборка датасета

```bash
# Извлекает признаки из pcap и создаёт features.csv
python3 build_dataset.py

# Указать другую директорию
python3 build_dataset.py --input my_dataset
```

## Структура результатов

```
dataset/
├── pcap/                          # отдельный pcap на каждый сценарий
│   ├── HTTPS_001_20250424_120000.pcap
│   ├── VIDEO_001_20250424_120130.pcap
│   ├── STREAM_001_20250424_120330.pcap
│   └── MESSENGER_001_20250424_120530.pcap
├── labels.csv                     # разметка: pcap → класс
├── scenario_log.jsonl             # подробный лог
└── features.csv                   # признаки + метки (после build_dataset.py)
```

## Настройка

Все параметры — в словаре `CONFIG` в начале `traffic_generator.py`:

- **Сайты**: добавьте/уберите URL в списках `sites` / `urls`
- **Длительности**: `duration` в секундах для каждого класса
- **Telegram Bot**: заполните `telegram_bot_token` и `telegram_chat_id`
  для генерации реального messenger-трафика
- **Интерфейс**: `interface` или через `--interface`

## Использование с VPN (VLESS+Reality)

Если на VM настроен Xray tproxy (setup_vm.sh), весь трафик Playwright
автоматически пойдёт через VPN. ECH будет работать прозрачно —
Chromium поддерживает ECH по умолчанию.

```bash
# Проверить что VPN работает
curl https://ifconfig.me

# Запустить генератор — трафик пойдёт через VLESS
sudo python3 traffic_generator.py
```

## Требования

- Ubuntu 22.04 / 24.04
- Python 3.10+
- tcpdump
- ~2 ГБ RAM (Chromium + tcpdump)
- Интернет (для генерации трафика)
