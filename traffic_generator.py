#!/usr/bin/env python3
"""
ECH Traffic Generator — генератор размеченного трафика
======================================================

Генерирует трафик 4 классов (HTTPS, VIDEO, STREAM, MESSENGER),
одновременно записывая pcap. Каждый сценарий → отдельный pcap →
автоматическая разметка.

Запуск:
    sudo python3 traffic_generator.py                    # все классы
    sudo python3 traffic_generator.py --classes VIDEO HTTPS
    sudo python3 traffic_generator.py --rounds 5         # 5 повторов

Результат:
    dataset/pcap/       — отдельный pcap на каждый сценарий
    dataset/labels.csv  — разметка (pcap_file, class, domain, ips, ...)
    dataset/features.csv — извлечённые признаки (если есть ech_classifier.py)

Требования:
    sudo apt install tcpdump tshark
    pip install playwright requests yt-dlp
    playwright install chromium

Автор: Никита / СПбПУ
"""

import argparse
import csv
import json
import logging
import os
import random
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

# ═══════════════════════════════════════════════════════════════════════════════
#                              КОНФИГУРАЦИЯ
#  Здесь можно легко менять сайты, длительности, параметры захвата
# ═══════════════════════════════════════════════════════════════════════════════

CONFIG = {
    # Сетевой интерфейс для захвата (None = автоопределение)
    "interface": None,

    # Директория для результатов
    "output_dir": "dataset",

    # Пауза между сценариями (сек) — даём памяти освободиться
    "pause_between": 15,

    # Прокси — None если запускаешь на VPS напрямую
    # "socks5://127.0.0.1:10808" если запускаешь на VM через Xray
    "proxy": None,

    # Режим экономии памяти (рекомендуется на VPS с 2GB RAM)
    # True  = отключить картинки/шрифты/медиа где возможно
    # False = полный браузер (нужен для VIDEO/STREAM)
    "low_memory": True,

    # ── HTTPS: обычный браузинг ──────────────────────────────────────────
    "HTTPS": {
        "enabled": True,
        "duration": 20,        # уменьшено с 30
        "sites": [
            "https://blog.cloudflare.com",
            "https://www.cloudflare.com",
            "https://workers.cloudflare.com",
            "https://discord.com",
            "https://canva.com",
            "https://www.shopify.com",
            "https://www.notion.so",
            "https://linear.app",
            "https://vercel.com",
            "https://www.figma.com",
        ],
        "sites_per_round": 2,  # уменьшено с 3
    },

    # ── VIDEO: потоковое видео ───────────────────────────────────────────
    "VIDEO": {
        "enabled": True,
        "duration": 40,        # уменьшено с 60
        "urls": [
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://www.youtube.com/watch?v=jNQXAC9IVRw",
            "https://www.youtube.com/watch?v=9bZkp7q19f0",
            "https://www.youtube.com/watch?v=kJQP7kiw5Fk",
            "https://www.youtube.com/watch?v=RgKAFK5djSk",
        ],
    },

    # ── STREAM: live-стримы ──────────────────────────────────────────────
    "STREAM": {
        "enabled": True,
        "duration": 40,        # уменьшено с 60
        "urls": [
            "https://www.twitch.tv/directory/all",
            "https://www.twitch.tv/shroud",
            "https://www.twitch.tv/pokimane",
            "https://www.twitch.tv/riotgames",
            "https://www.twitch.tv/esl_csgo",
        ],
    },

    # ── MESSENGER: мессенджеры ───────────────────────────────────────────
    "MESSENGER": {
        "enabled": True,
        "duration": 25,        # уменьшено с 45
        "urls": [
            "https://web.telegram.org/k/",
            "https://web.whatsapp.com",
            "https://discord.com/channels/@me",
        ],
        "telegram_bot_token": None,
        "telegram_chat_id":   None,
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
#                              ЛОГИРОВАНИЕ
# ═══════════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("traffic_gen")


# ═══════════════════════════════════════════════════════════════════════════════
#                          ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ═══════════════════════════════════════════════════════════════════════════════

def detect_interface() -> str:
    """Определяет основной сетевой интерфейс."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, check=True
        )
        # default via 10.0.2.2 dev ens33 proto dhcp ...
        parts = result.stdout.split()
        idx = parts.index("dev")
        return parts[idx + 1]
    except Exception:
        return "eth0"


def resolve_domains(urls: List[str]) -> Dict[str, List[str]]:
    """Резолвит домены из URL в IP-адреса для разметки."""
    domain_ips = {}
    for url in urls:
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).hostname
            if domain and domain not in domain_ips:
                ips = list({addr[4][0] for addr in socket.getaddrinfo(domain, 443)})
                domain_ips[domain] = ips
                log.debug(f"  {domain} → {ips}")
        except Exception as e:
            log.warning(f"  Не удалось резолвить {url}: {e}")
    return domain_ips


def start_capture(interface: str, pcap_path: str) -> subprocess.Popen:
    """Запускает tcpdump в фоне."""
    cmd = [
        "tcpdump",
        "-i", interface,
        "-w", pcap_path,
        "-U",                # flush после каждого пакета
        "-s", "0",           # полный пакет
        "tcp or udp",        # только TCP/UDP
    ]
    log.info(f"  tcpdump → {pcap_path}")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)  # даём tcpdump запуститься
    return proc


def stop_capture(proc: subprocess.Popen):
    """Останавливает tcpdump."""
    if proc and proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# ═══════════════════════════════════════════════════════════════════════════════
#                         ГЕНЕРАТОРЫ ТРАФИКА ПО КЛАССАМ
# ═══════════════════════════════════════════════════════════════════════════════

def get_chrome_args(ech_enabled: bool, profile: str = "default",
                    extra: List[str] = None) -> List[str]:
    """
    Формирует аргументы запуска Chromium с профилями под разные классы.

    Профили:
        lightweight — HTTPS/MESSENGER: без картинок, без JS рендеринга,
                      минимум памяти (~300-400 MB)
        media       — VIDEO/STREAM: нужен JS и медиа, но всё лишнее отключено
                      (~500-700 MB)
        default     — без ограничений

    На VPS с 2GB RAM рекомендуется low_memory=True в CONFIG.
    """
    low_memory = CONFIG.get("low_memory", True)

    # Базовые аргументы — всегда
    args = [
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",        # критично для VPS/контейнеров
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-sync",
        "--disable-background-networking",
        "--disable-default-apps",
        "--mute-audio",                   # без звука — меньше ресурсов
    ]

    if low_memory:
        if profile == "lightweight":
            # HTTPS и MESSENGER — JS нужен минимальный, картинки не нужны
            args += [
                "--disable-images",
                "--blink-settings=imagesEnabled=false",
                "--disable-plugins",
                "--disable-software-rasterizer",
                "--js-flags=--max-old-space-size=128",
                "--renderer-process-limit=1",
                "--single-process",
            ]
        elif profile == "media":
            # VIDEO и STREAM — нужен JS и медиа декодер, но всё остальное минимум
            args += [
                "--disable-plugins",
                "--disable-software-rasterizer",
                "--js-flags=--max-old-space-size=256",
                "--renderer-process-limit=1",
                "--autoplay-policy=no-user-gesture-required",
            ]
        else:
            # default — базовая экономия
            args += [
                "--disable-plugins",
                "--js-flags=--max-old-space-size=256",
            ]

    # ECH
    if not ech_enabled:
        args.append("--disable-features=EncryptedClientHello")

    # Прокси
    proxy = CONFIG.get("proxy")
    if proxy:
        args.append(f"--proxy-server={proxy}")
        log.debug(f"  Прокси: {proxy}")

    if extra:
        args.extend(extra)

    return args


def generate_https(cfg: dict, ech_enabled: bool = True):
    """HTTPS: открывает несколько сайтов, прокручивает страницы."""
    from playwright.sync_api import sync_playwright

    sites = random.sample(cfg["sites"], min(cfg["sites_per_round"], len(cfg["sites"])))
    log.info(f"  Открываю {len(sites)} сайтов: {[s.split('/')[2] for s in sites]}")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=get_chrome_args(ech_enabled, profile="lightweight"),
        )
        context = browser.new_context(
            viewport={"width": 1280, "height": 720},  # меньше viewport
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        )
        page = context.new_page()

        per_site = cfg["duration"] // len(sites)
        for url in sites:
            try:
                log.info(f"    → {url}")
                page.goto(url, wait_until="domcontentloaded", timeout=20000)

                deadline = time.time() + per_site
                while time.time() < deadline:
                    page.evaluate("window.scrollBy(0, 300)")
                    time.sleep(1 + random.random())

                    if random.random() < 0.15:
                        links = page.query_selector_all("a[href^='http']")
                        if links:
                            link = random.choice(links[:10])
                            try:
                                link.click(timeout=3000)
                                time.sleep(2)
                                page.go_back(timeout=5000)
                            except Exception:
                                pass
            except Exception as e:
                log.warning(f"    Ошибка на {url}: {e}")

        browser.close()


def generate_video(cfg: dict, ech_enabled: bool = True):
    """VIDEO: открывает видео на YouTube, смотрит заданное время."""
    from playwright.sync_api import sync_playwright

    url = random.choice(cfg["urls"])
    log.info(f"  Смотрю видео: {url}")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=get_chrome_args(ech_enabled, profile="media"),
        )
        context = browser.new_context(
            viewport={"width": 1280, "height": 720},
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        )
        page = context.new_page()

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            time.sleep(3)

            for selector in [
                'button[aria-label="Accept all"]',
                'button:has-text("Accept")',
                'button:has-text("Принять")',
                '.ytp-ad-skip-button',
                '.ytp-ad-skip-button-modern',
            ]:
                try:
                    page.click(selector, timeout=2000)
                    time.sleep(1)
                except Exception:
                    pass

            # Выбираем низкое качество — меньше нагрузка на сеть и CPU
            try:
                page.click(".ytp-settings-button", timeout=3000)
                time.sleep(0.5)
                page.click('text="Quality"', timeout=2000)
                time.sleep(0.5)
                for quality in ["360p", "480p", "240p"]:
                    try:
                        page.click(f'text="{quality}"', timeout=1000)
                        log.info(f"  Качество: {quality}")
                        break
                    except Exception:
                        continue
            except Exception:
                pass

            log.info(f"  Жду {cfg['duration']} сек (просмотр видео)...")
            time.sleep(cfg["duration"])

        except Exception as e:
            log.warning(f"  Ошибка видео: {e}")

        browser.close()


def generate_stream(cfg: dict, ech_enabled: bool = True):
    """STREAM: открывает Twitch стрим."""
    from playwright.sync_api import sync_playwright

    url = random.choice(cfg["urls"])
    log.info(f"  Смотрю стрим: {url}")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=get_chrome_args(ech_enabled, profile="media"),
        )
        context = browser.new_context(
            viewport={"width": 1280, "height": 720},
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        )
        page = context.new_page()

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            time.sleep(5)

            if "/directory" in url:
                try:
                    stream_link = page.query_selector(
                        'a[data-a-target="preview-card-image-link"]')
                    if stream_link:
                        stream_link.click()
                        time.sleep(5)
                except Exception:
                    pass

            try:
                page.click(
                    'button[data-a-target="content-classification-gate-overlay-start-watching-button"]',
                    timeout=3000)
            except Exception:
                pass

            # Низкое качество для экономии ресурсов
            try:
                page.click('[data-a-target="player-settings-button"]', timeout=3000)
                time.sleep(0.5)
                page.click('text="Quality"', timeout=2000)
                time.sleep(0.5)
                page.click('text="360p"', timeout=1000)
            except Exception:
                pass

            log.info(f"  Жду {cfg['duration']} сек (просмотр стрима)...")
            time.sleep(cfg["duration"])

        except Exception as e:
            log.warning(f"  Ошибка стрима: {e}")

        browser.close()


def generate_messenger(cfg: dict, ech_enabled: bool = True):
    """MESSENGER: открывает веб-мессенджеры + опционально Telegram Bot API."""
    import requests as req
    from playwright.sync_api import sync_playwright

    token = cfg.get("telegram_bot_token")
    chat_id = cfg.get("telegram_chat_id")

    if token and chat_id:
        log.info("  Отправляю сообщения через Telegram Bot API...")
        for i in range(10):
            try:
                msg = f"ECH test message #{i+1} at {datetime.now().isoformat()}"
                req.post(
                    f"https://api.telegram.org/bot{token}/sendMessage",
                    json={"chat_id": chat_id, "text": msg},
                    timeout=10,
                )
                time.sleep(random.uniform(1, 4))
            except Exception as e:
                log.warning(f"  Telegram API ошибка: {e}")

    url = random.choice(cfg["urls"])
    log.info(f"  Открываю мессенджер: {url}")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=get_chrome_args(ech_enabled, profile="lightweight"),
        )
        context = browser.new_context(
            viewport={"width": 1280, "height": 720},
        )
        page = context.new_page()

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            log.info(f"  Жду {cfg['duration']} сек (messenger idle)...")
            time.sleep(cfg["duration"])
        except Exception as e:
            log.warning(f"  Ошибка мессенджера: {e}")

        browser.close()


# Маппинг классов на генераторы
GENERATORS = {
    "HTTPS":     generate_https,
    "VIDEO":     generate_video,
    "STREAM":    generate_stream,
    "MESSENGER": generate_messenger,
}


# ═══════════════════════════════════════════════════════════════════════════════
#                            ОСНОВНОЙ PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScenarioResult:
    """Результат одного сценария."""
    traffic_class: str
    ech_enabled: bool
    pcap_file: str
    start_time: str
    end_time: str
    duration_s: float
    domains: List[str]
    resolved_ips: Dict[str, List[str]]
    success: bool
    error: str = ""


def run_scenario(
    traffic_class: str,
    cfg: dict,
    interface: str,
    output_dir: Path,
    round_num: int,
    ech_enabled: bool = True,
) -> ScenarioResult:
    """Запускает один сценарий: захват + генерация трафика."""

    ech_tag = "ech" if ech_enabled else "plain"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_name = f"{traffic_class}_{ech_tag}_{round_num:03d}_{timestamp}.pcap"
    pcap_path = str(output_dir / "pcap" / pcap_name)

    # Резолвим домены для разметки
    urls = cfg.get("urls") or cfg.get("sites", [])
    domain_ips = resolve_domains(urls)
    domains = list(domain_ips.keys())

    log.info(f"{'═'*60}")
    log.info(f"  СЦЕНАРИЙ: {traffic_class} (раунд {round_num}, ECH={'ON' if ech_enabled else 'OFF'})")
    log.info(f"  Домены: {domains[:5]}{'...' if len(domains) > 5 else ''}")
    log.info(f"{'═'*60}")

    start_time = datetime.now()
    capture_proc = start_capture(interface, pcap_path)
    success = True
    error = ""

    try:
        generator = GENERATORS[traffic_class]
        generator(cfg, ech_enabled=ech_enabled)
    except Exception as e:
        log.error(f"  Ошибка генерации {traffic_class}: {e}")
        success = False
        error = str(e)
    finally:
        stop_capture(capture_proc)

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    log.info(f"  Завершено за {duration:.1f}с, pcap: {pcap_name}")

    return ScenarioResult(
        traffic_class=traffic_class,
        ech_enabled=ech_enabled,
        pcap_file=pcap_name,
        start_time=start_time.isoformat(),
        end_time=end_time.isoformat(),
        duration_s=duration,
        domains=domains,
        resolved_ips=domain_ips,
        success=success,
        error=error,
    )


def write_labels(results: List[ScenarioResult], output_dir: Path):
    """Записывает labels.csv — главный файл разметки."""
    labels_path = output_dir / "labels.csv"
    with open(labels_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "pcap_file", "traffic_class", "ech_enabled", "start_time", "end_time",
            "duration_s", "domains", "resolved_ips", "success",
        ])
        for r in results:
            writer.writerow([
                r.pcap_file,
                r.traffic_class,
                r.ech_enabled,
                r.start_time,
                r.end_time,
                f"{r.duration_s:.1f}",
                ";".join(r.domains),
                json.dumps(r.resolved_ips),
                r.success,
            ])
    log.info(f"Разметка сохранена: {labels_path}")


def write_scenario_log(results: List[ScenarioResult], output_dir: Path):
    """Записывает подробный JSONL-лог."""
    log_path = output_dir / "scenario_log.jsonl"
    with open(log_path, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps({
                "traffic_class": r.traffic_class,
                "ech_enabled":   r.ech_enabled,
                "pcap_file":     r.pcap_file,
                "start_time":    r.start_time,
                "end_time":      r.end_time,
                "duration_s":    r.duration_s,
                "domains":       r.domains,
                "resolved_ips":  r.resolved_ips,
                "success":       r.success,
                "error":         r.error,
            }, ensure_ascii=False) + "\n")
    log.info(f"Лог сценариев: {log_path}")


# ═══════════════════════════════════════════════════════════════════════════════
#                                   CLI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Генератор размеченного ECH-трафика",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  sudo python3 traffic_generator.py                              # ECH + plain
  sudo python3 traffic_generator.py --ech-mode ech-only          # только ECH
  sudo python3 traffic_generator.py --ech-mode no-ech            # только plain
  sudo python3 traffic_generator.py --classes VIDEO HTTPS --rounds 3
  sudo python3 traffic_generator.py --interface ens33 --output my_dataset
        """,
    )
    parser.add_argument(
        "--classes", nargs="+",
        choices=["HTTPS", "VIDEO", "STREAM", "MESSENGER"],
        default=None,
        help="Какие классы генерировать (по умолч. все включённые)",
    )
    parser.add_argument(
        "--rounds", type=int, default=3,
        help="Сколько раундов для каждого класса (по умолч. 3)",
    )
    parser.add_argument(
        "--ech-mode", choices=["both", "ech-only", "no-ech"], default="both",
        help="Режим ECH: both = с ECH и без (по умолч.), "
             "ech-only = только ECH, no-ech = только обычный TLS",
    )
    parser.add_argument(
        "--interface", default=None,
        help="Сетевой интерфейс (по умолч. автоопределение)",
    )
    parser.add_argument(
        "--output", default=None,
        help="Директория для результатов (по умолч. dataset/)",
    )
    parser.add_argument(
        "--shuffle", action="store_true",
        help="Перемешать порядок сценариев (рекомендуется)",
    )
    args = parser.parse_args()

    # ── Проверки ──────────────────────────────────────────────────────────
    if os.geteuid() != 0:
        log.error("Нужен root для tcpdump. Запустите: sudo python3 traffic_generator.py")
        sys.exit(1)

    # ── Параметры ─────────────────────────────────────────────────────────
    interface = args.interface or CONFIG["interface"] or detect_interface()
    output_dir = Path(args.output or CONFIG["output_dir"])
    (output_dir / "pcap").mkdir(parents=True, exist_ok=True)

    # Определяем классы
    if args.classes:
        classes = args.classes
    else:
        classes = [c for c in GENERATORS if CONFIG.get(c, {}).get("enabled", True)]

    # Определяем режимы ECH
    ech_mode = getattr(args, 'ech_mode', 'both')
    if ech_mode == "both":
        ech_variants = [True, False]
    elif ech_mode == "ech-only":
        ech_variants = [True]
    else:  # no-ech
        ech_variants = [False]

    log.info(f"Интерфейс: {interface}")
    log.info(f"Классы: {classes}")
    log.info(f"Раундов: {args.rounds}")
    log.info(f"ECH режим: {ech_mode} → варианты: {['ECH' if e else 'plain' for e in ech_variants]}")
    log.info(f"Результаты: {output_dir}/")

    # ── Проверка прокси ───────────────────────────────────────────────────
    proxy = CONFIG.get("proxy")
    if proxy:
        log.info(f"Прокси: {proxy}")
        log.info("  Проверяю соединение через прокси...")
        try:
            import urllib.request
            host = proxy.replace("socks5://", "").replace("socks4://", "").replace("http://", "")
            ip_host, ip_port = host.rsplit(":", 1)

            import socket as _sock
            s = _sock.create_connection((ip_host, int(ip_port)), timeout=3)
            s.close()
            log.info("  Прокси доступен ✓")
        except Exception as e:
            log.warning(f"  Прокси недоступен: {e}")
            log.warning("  Трафик пойдёт напрямую (без VPN)")
    else:
        log.info("Прокси: не задан (прямое соединение)")

    # ── Формируем очередь сценариев ───────────────────────────────────────
    # При mode=both каждый класс прогоняется дважды: с ECH и без
    scenarios = []
    for round_num in range(1, args.rounds + 1):
        for cls in classes:
            for ech_on in ech_variants:
                scenarios.append((cls, round_num, ech_on))

    if args.shuffle:
        random.shuffle(scenarios)

    # ── Запуск ────────────────────────────────────────────────────────────
    results = []
    total = len(scenarios)

    for i, (cls, rnd, ech_on) in enumerate(scenarios, 1):
        ech_label = "ECH" if ech_on else "plain"
        log.info(f"\n[{i}/{total}] Запуск {cls} ({ech_label}, раунд {rnd})")

        result = run_scenario(
            traffic_class=cls,
            cfg=CONFIG[cls],
            interface=interface,
            output_dir=output_dir,
            round_num=rnd,
            ech_enabled=ech_on,
        )
        results.append(result)

        # Пауза между сценариями
        if i < total:
            pause = CONFIG["pause_between"]
            log.info(f"  Пауза {pause} сек...")
            time.sleep(pause)

    # ── Сохранение результатов ────────────────────────────────────────────
    write_labels(results, output_dir)
    write_scenario_log(results, output_dir)

    # ── Итоги ─────────────────────────────────────────────────────────────
    print("\n" + "═" * 60)
    print("  ИТОГИ ГЕНЕРАЦИИ")
    print("═" * 60)
    for cls in classes:
        for ech_on in ech_variants:
            tag = "ECH" if ech_on else "plain"
            cls_results = [r for r in results
                           if r.traffic_class == cls and r.ech_enabled == ech_on]
            ok_count = sum(1 for r in cls_results if r.success)
            print(f"  {cls:12s} [{tag:5s}]: {ok_count}/{len(cls_results)} успешных")
    print(f"\n  Всего сценариев: {len(results)}")
    print(f"  PCAP файлы:      {output_dir}/pcap/")
    print(f"  Разметка:        {output_dir}/labels.csv")
    print(f"  Лог:             {output_dir}/scenario_log.jsonl")
    print("═" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
