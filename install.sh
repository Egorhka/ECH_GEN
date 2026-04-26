#!/usr/bin/env bash
# ============================================================================
#  install.sh — Установка зависимостей для генератора трафика
#  Запуск: sudo bash install.sh
# ============================================================================
set -euo pipefail

log()  { printf "\033[1;34m[*]\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m[+]\033[0m %s\n" "$*"; }

[[ "$EUID" -eq 0 ]] || { echo "Запустите: sudo bash install.sh"; exit 1; }

# Определяем пользователя, который вызвал sudo
REAL_USER="${SUDO_USER:-$USER}"

# ─── 1. Системные пакеты ─────────────────────────────────────────────────────
log "Установка системных пакетов..."
apt-get update -q
apt-get install -yq \
    tcpdump \
    tshark \
    wireshark-common \
    python3-pip \
    python3-venv \
    ethtool

# ─── 2. Python-зависимости ───────────────────────────────────────────────────
log "Установка Python-пакетов..."
pip3 install --break-system-packages \
    scapy \
    playwright \
    requests \
    pandas \
    yt-dlp

# ─── 3. Playwright — скачиваем Chromium ──────────────────────────────────────
log "Установка Chromium для Playwright..."
# Playwright нужны системные зависимости
playwright install-deps chromium
su - "$REAL_USER" -c "playwright install chromium" || playwright install chromium

# ─── 4. Отключение NIC offload (для корректного tcpdump) ─────────────────────
IFACE=$(ip route show default | awk '/default/ {print $5}' | head -1)
if [[ -n "$IFACE" ]]; then
    log "Отключение NIC offload на $IFACE..."
    ethtool -K "$IFACE" tso off gso off gro off lro off 2>/dev/null || true
fi

# ─── Готово ───────────────────────────────────────────────────────────────────
echo
ok "Установка завершена!"
echo
echo "  Использование:"
echo "    sudo python3 traffic_generator.py                    # все классы, 3 раунда"
echo "    sudo python3 traffic_generator.py --classes VIDEO    # только VIDEO"
echo "    sudo python3 traffic_generator.py --rounds 5         # 5 раундов"
echo ""
echo "  После генерации:"
echo "    python3 build_dataset.py                             # собрать features.csv"
echo
