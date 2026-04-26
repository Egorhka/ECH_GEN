#!/usr/bin/env python3
"""
ECH Traffic Classifier (heuristic edition)
===========================================

Анализирует PCAP-файл и классифицирует TLS/ECH-потоки на 4 класса:
    MESSENGER  — мессенджеры (Telegram, WhatsApp, Signal)
    VIDEO      — потоковое видео (YouTube, Netflix, TikTok)
    STREAM     — live-стриминг (Twitch, WebRTC)
    HTTPS      — обычная веб-страница

Метод: чисто эвристический. Каскад правил по статистическим
характеристикам потока (без дешифрации полезной нагрузки).
Детектируется расширение ECH в ClientHello, но классификация
опирается на метаданные потока — то есть работоспособна и при ECH.

Использование:
    python ech_classifier.py <pcap_file> [-o report.html] [-j report.json]

Требования:
    pip install scapy

Автор: Никита / магистерская диссертация СПбПУ
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import math
import os
import statistics
import struct
import sys
import textwrap
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Tuple

# Подавим приветствия scapy
os.environ["SCAPY_NO_WARN"] = "1"
import logging
logging.getLogger("scapy").setLevel(logging.ERROR)

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, Raw  # type: ignore
except ImportError:
    print("ERROR: scapy не установлен. Выполните:  pip install scapy", file=sys.stderr)
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
#                                КЛАССЫ И КОНСТАНТЫ
# ═══════════════════════════════════════════════════════════════════════════════

class TrafficClass(str, Enum):
    MESSENGER = "MESSENGER"
    VIDEO     = "VIDEO"
    STREAM    = "STREAM"
    HTTPS     = "HTTPS"
    UNKNOWN   = "UNKNOWN"


CLASS_COLORS: Dict[str, str] = {
    "MESSENGER": "#4A90E2",
    "VIDEO":     "#E85D75",
    "STREAM":    "#F5A623",
    "HTTPS":     "#50C878",
    "UNKNOWN":   "#9E9E9E",
}

# TLS record types
TLS_HANDSHAKE = 0x16
TLS_APP_DATA  = 0x17

# ClientHello extensions
EXT_SNI      = 0x0000
EXT_ECH      = 0xfe0d   # Encrypted Client Hello (draft-ietf-tls-esni)
EXT_ECH_OLD  = 0xff02   # предыдущий draft-номер
EXT_ESNI     = 0xffce   # предшественник ECH

# Размеры пакетов (в байтах)
MTU_LARGE_THRESHOLD = 1400
SMALL_PKT_THRESHOLD = 200


# ═══════════════════════════════════════════════════════════════════════════════
#                             СТРУКТУРЫ ДАННЫХ
# ═══════════════════════════════════════════════════════════════════════════════

FlowKey = Tuple[str, str, int, int, str]


@dataclass
class PacketInfo:
    """Минимальная информация о пакете в потоке."""
    ts: float
    length: int                  # размер IP-пакета
    direction: int               # +1 = клиент→сервер, -1 = сервер→клиент
    tls_record_type: int = 0     # 0 = нет TLS, 0x16/0x17 = TLS
    is_client_hello: bool = False
    has_ech: bool = False
    sni: str = ""
    ech_payload_size: int = 0    # размер зашифрованного CHI


@dataclass
class Flow:
    """Сетевой поток (5-tuple) со всеми пакетами и вычисленными признаками."""
    key: FlowKey
    packets: List[PacketInfo] = field(default_factory=list)

    # заполняется после обработки всех пакетов
    features: Dict = field(default_factory=dict)
    predicted_class: str = TrafficClass.UNKNOWN.value
    confidence: float = 0.0
    reason: str = ""

    @property
    def src(self) -> str:   return self.key[0]
    @property
    def dst(self) -> str:   return self.key[1]
    @property
    def sport(self) -> int: return self.key[2]
    @property
    def dport(self) -> int: return self.key[3]
    @property
    def proto(self) -> str: return self.key[4]


# ═══════════════════════════════════════════════════════════════════════════════
#                       ПАРСИНГ TLS И ОБНАРУЖЕНИЕ ECH
# ═══════════════════════════════════════════════════════════════════════════════

def parse_client_hello(data: bytes) -> Tuple[bool, bool, str, int]:
    """
    Разбор TLS ClientHello. Возвращает:
        (is_client_hello, has_ech, sni, ech_payload_size)

    Работает в defensive-режиме: при любом нарушении структуры
    возвращает what-возможно и не падает.
    """
    try:
        # TLS record header (5 байт): type, version(2), length(2)
        if len(data) < 5:
            return False, False, "", 0
        rec_type = data[0]
        if rec_type != TLS_HANDSHAKE:
            return False, False, "", 0

        rec_len = struct.unpack(">H", data[3:5])[0]
        hs = data[5:5 + rec_len]
        if len(hs) < 4:
            return False, False, "", 0

        # Handshake header (4 байт): msg_type, length(3)
        msg_type = hs[0]
        if msg_type != 0x01:  # ClientHello
            return False, False, "", 0

        # Парсинг ClientHello
        # Пропускаем: legacy_version(2), random(32)
        off = 4 + 2 + 32
        if off >= len(hs):
            return True, False, "", 0

        # legacy_session_id
        sid_len = hs[off]; off += 1 + sid_len
        if off + 2 > len(hs):
            return True, False, "", 0

        # cipher_suites
        cs_len = struct.unpack(">H", hs[off:off+2])[0]
        off += 2 + cs_len
        if off >= len(hs):
            return True, False, "", 0

        # compression_methods
        comp_len = hs[off]; off += 1 + comp_len
        if off + 2 > len(hs):
            return True, False, "", 0

        # extensions
        ext_total_len = struct.unpack(">H", hs[off:off+2])[0]
        off += 2
        ext_end = off + ext_total_len
        if ext_end > len(hs):
            ext_end = len(hs)

        has_ech = False
        ech_payload_size = 0
        sni = ""

        while off + 4 <= ext_end:
            ext_type = struct.unpack(">H", hs[off:off+2])[0]
            ext_len  = struct.unpack(">H", hs[off+2:off+4])[0]
            off += 4
            if off + ext_len > ext_end:
                break
            ext_data = hs[off:off + ext_len]

            if ext_type == EXT_SNI:
                # server_name extension: list(2)→entry(type(1)+name_len(2)+name)
                try:
                    if len(ext_data) >= 5:
                        name_len = struct.unpack(">H", ext_data[3:5])[0]
                        sni = ext_data[5:5+name_len].decode("ascii", errors="ignore")
                except Exception:
                    pass

            elif ext_type in (EXT_ECH, EXT_ECH_OLD, EXT_ESNI):
                has_ech = True
                # ECH ext payload: config_id(1) + cipher_suite(4) + enc(len)+ payload(len)
                ech_payload_size = ext_len

            off += ext_len

        return True, has_ech, sni, ech_payload_size

    except Exception:
        return False, False, "", 0


def try_parse_tls(payload: bytes) -> Tuple[int, bool, bool, str, int]:
    """
    Определяет тип TLS-записи и разбирает ClientHello, если есть.
    Возвращает (rec_type, is_client_hello, has_ech, sni, ech_size).
    """
    if len(payload) < 5:
        return 0, False, False, "", 0
    rec_type = payload[0]
    if rec_type not in (TLS_HANDSHAKE, TLS_APP_DATA):
        return 0, False, False, "", 0

    if rec_type == TLS_HANDSHAKE:
        is_ch, has_ech, sni, ech_sz = parse_client_hello(payload)
        return rec_type, is_ch, has_ech, sni, ech_sz

    return rec_type, False, False, "", 0


# ═══════════════════════════════════════════════════════════════════════════════
#                         РАСЧЁТ ПРИЗНАКОВ ПОТОКА
# ═══════════════════════════════════════════════════════════════════════════════

def _safe_mean(xs):  return statistics.mean(xs) if xs else 0.0
def _safe_stdev(xs): return statistics.stdev(xs) if len(xs) >= 2 else 0.0

def _percentile(xs: List[float], p: float) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    k = (len(s) - 1) * p
    f = math.floor(k); c = math.ceil(k)
    if f == c:
        return s[int(k)]
    return s[f] * (c - k) + s[c] * (k - f)


def compute_features(flow: Flow) -> Dict:
    """Вычисляет все статистические признаки потока."""
    pkts = flow.packets
    if not pkts:
        return {}

    ts_list     = [p.ts for p in pkts]
    lengths     = [p.length for p in pkts]
    down_lens   = [p.length for p in pkts if p.direction == -1]
    up_lens     = [p.length for p in pkts if p.direction == +1]
    iats        = [ts_list[i] - ts_list[i-1] for i in range(1, len(ts_list))]

    duration    = max(ts_list[-1] - ts_list[0], 1e-6)
    total_bytes = sum(lengths)
    down_bytes  = sum(down_lens)
    up_bytes    = sum(up_lens)

    # burst detection: считаем «всплесками» пакеты, идущие с iat < 50 мс подряд
    burst_count = 0
    in_burst = False
    for iat in iats:
        if iat < 0.05:
            if not in_burst:
                burst_count += 1
                in_burst = True
        else:
            in_burst = False
    # Normalize: burst density
    burst_score = burst_count / max(duration, 1.0)

    # Periodicity score: низкий коэффициент вариации IAT = регулярный трафик
    iat_mean = _safe_mean(iats)
    iat_std  = _safe_stdev(iats)
    cv = (iat_std / iat_mean) if iat_mean > 0 else 0.0
    periodicity_score = 1.0 / (1.0 + cv)   # ∈ (0, 1], ближе к 1 = периодично

    large_count = sum(1 for l in lengths if l >= MTU_LARGE_THRESHOLD)
    small_count = sum(1 for l in lengths if l <= SMALL_PKT_THRESHOLD)

    # ECH detection: если хоть в одном ClientHello был ECH
    has_ech = any(p.has_ech for p in pkts)
    sni     = next((p.sni for p in pkts if p.sni), "")

    return {
        "pkt_count":           len(pkts),
        "duration_s":          duration,
        "total_bytes":         total_bytes,
        "down_bytes":          down_bytes,
        "up_bytes":            up_bytes,
        "down_up_ratio":       (down_bytes / up_bytes) if up_bytes > 0 else float(down_bytes),
        "mean_pkt_size":       _safe_mean(lengths),
        "mean_pkt_size_down":  _safe_mean(down_lens),
        "mean_pkt_size_up":    _safe_mean(up_lens),
        "std_pkt_size":        _safe_stdev(lengths),
        "min_pkt_size":        min(lengths),
        "max_pkt_size":        max(lengths),
        "p50_pkt_size":        _percentile(lengths, 0.5),
        "p95_pkt_size":        _percentile(lengths, 0.95),
        "bytes_per_sec":       total_bytes / duration,
        "pkts_per_sec":        len(pkts) / duration,
        "iat_mean":            iat_mean,
        "iat_std":             iat_std,
        "iat_cv":              cv,
        "large_pkt_ratio":     large_count / len(pkts),
        "small_pkt_ratio":     small_count / len(pkts),
        "burst_score":         burst_score,
        "periodicity_score":   periodicity_score,
        "has_ech":             has_ech,
        "sni":                 sni,
    }


# ═══════════════════════════════════════════════════════════════════════════════
#                       ЭВРИСТИЧЕСКИЙ КЛАССИФИКАТОР (каскад)
# ═══════════════════════════════════════════════════════════════════════════════

def classify_heuristic(f: Dict) -> Tuple[str, float, str]:
    """
    Каскадная классификация потока по вычисленным признакам.
    Возвращает (класс, уверенность ∈ [0,1], текстовое объяснение).
    """
    pc = f["pkt_count"]
    dur = f["duration_s"]
    total = f["total_bytes"]
    dur_ratio = f["down_up_ratio"]
    bps = f["bytes_per_sec"]
    large = f["large_pkt_ratio"]
    small = f["small_pkt_ratio"]
    mean_sz = f["mean_pkt_size"]
    burst = f["burst_score"]
    period = f["periodicity_score"]

    # ── Отсев слишком коротких потоков ────────────────────────────────────────
    if pc < 10:
        return (
            TrafficClass.UNKNOWN.value,
            0.0,
            f"Слишком мало пакетов для классификации ({pc} < 10)"
        )

    # ── VIDEO: сегментная скачка с большим bandwidth и высоким burst ─────────
    video_score = 0
    video_reasons = []
    if dur >= 10:
        video_score += 1; video_reasons.append(f"длительность {dur:.1f}s ≥ 10s")
    if dur_ratio >= 10:
        video_score += 2; video_reasons.append(f"down/up ratio {dur_ratio:.1f} ≥ 10")
    if large >= 0.5:
        video_score += 2; video_reasons.append(f"large packet ratio {large:.2f} ≥ 0.5")
    if bps >= 150_000:
        video_score += 2; video_reasons.append(f"bandwidth {bps/1024:.0f} КБ/с ≥ 150 КБ/с")
    if burst >= 0.3:
        video_score += 1; video_reasons.append(f"burst score {burst:.2f} ≥ 0.3")
    # Высокий down/up ratio + много больших пакетов = очень вероятно видео
    if dur_ratio >= 30 and large >= 0.8:
        video_score += 2; video_reasons.append(f"экстремальная асимметрия + full-MTU ({dur_ratio:.0f}×, {large:.2f})")

    if video_score >= 6:
        conf = min(0.99, 0.5 + 0.08 * video_score)
        return (
            TrafficClass.VIDEO.value,
            conf,
            "VIDEO: " + "; ".join(video_reasons)
        )

    # ── STREAM: постоянный битрейт, двунаправленная активность ───────────────
    stream_score = 0
    stream_reasons = []
    if dur >= 10:
        stream_score += 1; stream_reasons.append(f"длительность {dur:.1f}s ≥ 10s")
    if 100_000 <= bps < 2_000_000:
        stream_score += 2; stream_reasons.append(f"bandwidth {bps/1024:.0f} КБ/с в диапазоне стрима")
    if 2 <= dur_ratio < 10:
        stream_score += 2; stream_reasons.append(f"down/up ratio {dur_ratio:.1f} в диапазоне [2,10)")
    if period >= 0.5:
        stream_score += 2; stream_reasons.append(f"periodicity {period:.2f} ≥ 0.5")
    if burst < 0.3:
        stream_score += 1; stream_reasons.append(f"burst score {burst:.2f} < 0.3 (без пауз)")

    if stream_score >= 6:
        conf = min(0.95, 0.5 + 0.08 * stream_score)
        return (
            TrafficClass.STREAM.value,
            conf,
            "STREAM: " + "; ".join(stream_reasons)
        )

    # ── MESSENGER: малый объём, маленькие пакеты, keep-alive паттерн ─────────
    msg_score = 0
    msg_reasons = []
    if pc <= 100 or (dur > 30 and bps < 5_000):
        msg_score += 2; msg_reasons.append(
            f"малая активность (pkts={pc}, dur={dur:.1f}s, bps={bps:.0f})"
        )
    if mean_sz <= 400:
        msg_score += 2; msg_reasons.append(f"средний размер пакета {mean_sz:.0f} ≤ 400 байт")
    if small >= 0.6:
        msg_score += 2; msg_reasons.append(f"small packet ratio {small:.2f} ≥ 0.6")
    if total <= 500_000:
        msg_score += 1; msg_reasons.append(f"общий объём {total/1024:.0f} КБ ≤ 500 КБ")

    if msg_score >= 5:
        conf = min(0.92, 0.5 + 0.09 * msg_score)
        return (
            TrafficClass.MESSENGER.value,
            conf,
            "MESSENGER: " + "; ".join(msg_reasons)
        )

    # ── HTTPS: дефолт для всего остального ───────────────────────────────────
    https_reasons = []
    if dur < 30:
        https_reasons.append(f"длительность {dur:.1f}s < 30s")
    if 3 <= dur_ratio <= 20:
        https_reasons.append(f"down/up ratio {dur_ratio:.1f} в диапазоне HTTPS")
    if total < 5_000_000:
        https_reasons.append(f"объём {total/1024:.0f} КБ < 5 МБ")
    if not https_reasons:
        https_reasons.append("не подошёл ни под один специфичный класс")

    return (
        TrafficClass.HTTPS.value,
        0.55,
        "HTTPS (по умолчанию): " + "; ".join(https_reasons)
    )


# ═══════════════════════════════════════════════════════════════════════════════
#                        PIPELINE: PCAP → FLOWS → CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

def make_flow_key(pkt) -> Optional[FlowKey]:
    """Строит каноничный ключ потока (направление нормализовано)."""
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    else:
        return None

    if TCP in pkt:
        sport, dport, proto = pkt[TCP].sport, pkt[TCP].dport, "TCP"
    elif UDP in pkt:
        sport, dport, proto = pkt[UDP].sport, pkt[UDP].dport, "UDP"
    else:
        return None

    # Каноническая нормализация: клиент (высокий порт) всегда первым,
    # сервер (низкий порт, например 443) — вторым.
    # Это обеспечивает правильное направление: +1 = клиент→сервер (up),
    #                                          -1 = сервер→клиент (down)
    if sport >= dport:
        # Исходный src - клиент
        return (src, dst, sport, dport, proto)
    # Исходный src - сервер, меняем местами
    return (dst, src, dport, sport, proto)


def extract_flows(pcap_path: str, verbose: bool = True) -> Dict[FlowKey, Flow]:
    """Читает PCAP и группирует пакеты в потоки."""
    if verbose:
        print(f"[*] Чтение {pcap_path}...")
    packets = rdpcap(pcap_path)
    if verbose:
        print(f"[*] Загружено {len(packets)} пакетов, группировка по потокам...")

    flows: Dict[FlowKey, Flow] = {}

    for pkt in packets:
        key = make_flow_key(pkt)
        if key is None:
            continue

        # Определяем направление относительно канонического ключа
        if IP in pkt:
            src = pkt[IP].src
        elif IPv6 in pkt:
            src = pkt[IPv6].src
        else:
            continue
        direction = +1 if src == key[0] else -1

        # Извлекаем TLS payload (если есть)
        tls_type = 0; is_ch = False; has_ech = False; sni = ""; ech_sz = 0
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            tls_type, is_ch, has_ech, sni, ech_sz = try_parse_tls(payload)

        pi = PacketInfo(
            ts=float(pkt.time),
            length=len(pkt),
            direction=direction,
            tls_record_type=tls_type,
            is_client_hello=is_ch,
            has_ech=has_ech,
            sni=sni,
            ech_payload_size=ech_sz,
        )

        if key not in flows:
            flows[key] = Flow(key=key)
        flows[key].packets.append(pi)

    if verbose:
        print(f"[*] Сформировано {len(flows)} потоков")

    return flows


def classify_all(flows: Dict[FlowKey, Flow], verbose: bool = True) -> None:
    """Вычисляет признаки и применяет классификатор ко всем потокам."""
    tls_flows = 0
    ech_flows = 0
    for flow in flows.values():
        flow.features = compute_features(flow)
        cls, conf, reason = classify_heuristic(flow.features)
        flow.predicted_class = cls
        flow.confidence = conf
        flow.reason = reason
        if any(p.tls_record_type for p in flow.packets):
            tls_flows += 1
        if flow.features.get("has_ech"):
            ech_flows += 1

    if verbose:
        print(f"[*] Классифицировано {len(flows)} потоков")
        print(f"[*] Из них TLS: {tls_flows}, с ECH: {ech_flows}")


# ═══════════════════════════════════════════════════════════════════════════════
#                              ВЫВОД: КОНСОЛЬ
# ═══════════════════════════════════════════════════════════════════════════════

def print_summary(flows: Dict[FlowKey, Flow]) -> None:
    counts: Dict[str, int] = defaultdict(int)
    for f in flows.values():
        counts[f.predicted_class] += 1

    total = sum(counts.values())
    print()
    print("═" * 60)
    print("  РАСПРЕДЕЛЕНИЕ КЛАССОВ")
    print("═" * 60)
    for cls in ("MESSENGER", "VIDEO", "STREAM", "HTTPS", "UNKNOWN"):
        n = counts[cls]
        pct = (100.0 * n / total) if total else 0.0
        bar = "█" * int(pct / 2)
        print(f"  {cls:10s} {n:5d}  {pct:5.1f}%  {bar}")
    print(f"  {'─' * 56}")
    print(f"  {'TOTAL':10s} {total:5d}")
    print()


def print_details(flows: Dict[FlowKey, Flow], limit: int = 20) -> None:
    items = list(flows.values())
    # сортировка: по классу, потом по уверенности убывающая
    items.sort(key=lambda f: (f.predicted_class, -f.confidence))
    print("═" * 98)
    print(f"  ДЕТАЛИ ПОТОКОВ (первые {limit})")
    print("═" * 98)
    hdr = f"  {'CLASS':10s} {'CONF':>5s}  {'PKTS':>6s} {'BYTES':>10s} {'DUR':>7s}  ECH SNI"
    print(hdr)
    print("  " + "─" * 94)
    for f in items[:limit]:
        feat = f.features
        ech = "★" if feat.get("has_ech") else " "
        sni = feat.get("sni", "") or "-"
        if len(sni) > 30: sni = sni[:27] + "..."
        print(f"  {f.predicted_class:10s} {f.confidence:5.2f}  "
              f"{feat['pkt_count']:>6d} {feat['total_bytes']:>10d} "
              f"{feat['duration_s']:>6.1f}s  {ech}  {sni}")
    if len(items) > limit:
        print(f"  ... и ещё {len(items) - limit} потоков")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
#                            ВЫВОД: JSON ОТЧЁТ
# ═══════════════════════════════════════════════════════════════════════════════

def write_json(flows: Dict[FlowKey, Flow], path: str) -> None:
    records = []
    for flow in flows.values():
        records.append({
            "src":        flow.src,
            "dst":        flow.dst,
            "sport":      flow.sport,
            "dport":      flow.dport,
            "proto":      flow.proto,
            "predicted":  flow.predicted_class,
            "confidence": round(flow.confidence, 3),
            "reason":     flow.reason,
            "features":   flow.features,
        })
    out = {
        "meta": {
            "flow_count":  len(flows),
            "generated":   time.strftime("%Y-%m-%d %H:%M:%S"),
            "tool":        "ech_classifier.py",
        },
        "flows": records,
    }
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(out, fp, indent=2, ensure_ascii=False, default=str)
    print(f"[*] JSON отчёт сохранён: {path}")


# ═══════════════════════════════════════════════════════════════════════════════
#                        ВЫВОД: HTML ОТЧЁТ С ГРАФИКАМИ
# ═══════════════════════════════════════════════════════════════════════════════

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>ECH Classifier Report</title>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
    background: #f5f5f7; color: #1d1d1f; margin: 0; padding: 32px;
    line-height: 1.5;
  }
  h1 { font-weight: 500; margin: 0 0 8px 0; font-size: 28px; }
  h2 { font-weight: 500; margin: 32px 0 16px 0; font-size: 20px; color: #444; }
  .meta { color: #666; font-size: 14px; margin-bottom: 24px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .card {
    background: #fff; padding: 16px; border-radius: 10px;
    border: 1px solid #e5e5e7;
  }
  .card .n { font-size: 28px; font-weight: 500; }
  .card .l { font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: 0.5px; }
  .swatch { display: inline-block; width: 12px; height: 12px; border-radius: 3px; margin-right: 6px; vertical-align: middle; }
  .chart-wrap { background: #fff; padding: 20px; border-radius: 10px; margin-bottom: 20px; border: 1px solid #e5e5e7; }
  svg { max-width: 100%; display: block; }
  table {
    width: 100%; border-collapse: collapse; background: #fff;
    border-radius: 10px; overflow: hidden; border: 1px solid #e5e5e7;
    font-size: 13px;
  }
  th { background: #fafafa; text-align: left; padding: 10px 12px; font-weight: 500; color: #666; border-bottom: 1px solid #e5e5e7; }
  td { padding: 10px 12px; border-bottom: 1px solid #f0f0f0; }
  tr:last-child td { border-bottom: none; }
  tr:hover { background: #fafafa; }
  .class-pill {
    display: inline-block; padding: 3px 10px; border-radius: 12px;
    font-size: 11px; font-weight: 500; color: #fff;
  }
  .conf { font-family: monospace; color: #666; font-size: 12px; }
  .reason { font-size: 12px; color: #666; }
  .ech-star { color: #d4a017; font-weight: bold; }
  details summary { cursor: pointer; color: #0066cc; font-size: 13px; }
</style>
</head>
<body>
  <h1>ECH Traffic Classifier — отчёт</h1>
  <div class="meta">
    Сгенерировано {TIMESTAMP} · {TOTAL_FLOWS} потоков · {TLS_FLOWS} TLS · {ECH_FLOWS} с ECH
  </div>

  <div class="cards">
    {STAT_CARDS}
  </div>

  <h2>Распределение классов</h2>
  <div class="chart-wrap">
    {PIE_CHART}
  </div>

  <h2>Scatter: bytes/s × down/up ratio</h2>
  <div class="chart-wrap">
    {SCATTER_CHART}
  </div>

  <h2>Длительность потоков (гистограмма)</h2>
  <div class="chart-wrap">
    {HISTO_CHART}
  </div>

  <h2>Все потоки ({TOTAL_FLOWS})</h2>
  <table>
    <thead>
      <tr>
        <th>#</th><th>Class</th><th>Conf</th><th>Src → Dst</th>
        <th>Proto</th><th>Pkts</th><th>Bytes</th><th>Dur</th>
        <th>bps</th><th>ECH</th><th>SNI</th><th>Reason</th>
      </tr>
    </thead>
    <tbody>
      {TABLE_ROWS}
    </tbody>
  </table>
</body>
</html>
"""


def _svg_pie(counts: Dict[str, int]) -> str:
    """Круговая диаграмма в SVG."""
    total = sum(counts.values()) or 1
    cx, cy, r = 180, 180, 140
    segments = []
    legend_items = []
    start = -math.pi / 2  # начало сверху

    sorted_items = sorted(counts.items(), key=lambda x: -x[1])

    for cls, n in sorted_items:
        if n == 0: continue
        frac = n / total
        angle = frac * 2 * math.pi
        end = start + angle
        large = 1 if angle > math.pi else 0

        x1 = cx + r * math.cos(start); y1 = cy + r * math.sin(start)
        x2 = cx + r * math.cos(end);   y2 = cy + r * math.sin(end)

        if frac >= 0.999:
            # Полный круг
            path = f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{CLASS_COLORS[cls]}" stroke="#fff" stroke-width="2"/>'
        else:
            path = (
                f'<path d="M{cx},{cy} L{x1:.2f},{y1:.2f} '
                f'A{r},{r} 0 {large},1 {x2:.2f},{y2:.2f} Z" '
                f'fill="{CLASS_COLORS[cls]}" stroke="#fff" stroke-width="2"/>'
            )
        segments.append(path)

        # подпись внутри сегмента
        mid = start + angle / 2
        tx = cx + (r * 0.65) * math.cos(mid)
        ty = cy + (r * 0.65) * math.sin(mid)
        pct = frac * 100
        if frac >= 0.05:
            segments.append(
                f'<text x="{tx:.1f}" y="{ty:.1f}" fill="#fff" '
                f'font-size="13" text-anchor="middle" dominant-baseline="central" '
                f'font-weight="500">{pct:.0f}%</text>'
            )

        legend_items.append(
            f'<div><span class="swatch" style="background:{CLASS_COLORS[cls]}"></span>'
            f'<strong>{cls}</strong>: {n} ({pct:.1f}%)</div>'
        )

        start = end

    svg = f'''
    <div style="display: flex; gap: 40px; align-items: center;">
      <svg viewBox="0 0 360 360" width="320" height="320">
        {''.join(segments)}
      </svg>
      <div style="font-size: 14px; line-height: 1.9;">
        {''.join(legend_items)}
      </div>
    </div>
    '''
    return svg


def _svg_scatter(flows: Dict[FlowKey, Flow]) -> str:
    """Scatter: X = log10(bytes/sec), Y = log10(down/up ratio). Цвет — класс."""
    W, H = 680, 360
    pad_l, pad_r, pad_t, pad_b = 60, 20, 20, 40

    pts = []
    for f in flows.values():
        feat = f.features
        if feat.get("pkt_count", 0) < 5: continue
        bps = max(feat.get("bytes_per_sec", 1), 1)
        ratio = max(feat.get("down_up_ratio", 0.01), 0.01)
        pts.append((math.log10(bps), math.log10(ratio), f.predicted_class))

    if not pts:
        return '<div style="color:#999;padding:20px;">Нет данных для визуализации</div>'

    xs = [p[0] for p in pts]; ys = [p[1] for p in pts]
    xmin, xmax = min(xs), max(xs)
    ymin, ymax = min(ys), max(ys)
    if xmax - xmin < 0.5: xmax = xmin + 0.5
    if ymax - ymin < 0.5: ymax = ymin + 0.5

    def sx(x): return pad_l + (x - xmin) / (xmax - xmin) * (W - pad_l - pad_r)
    def sy(y): return H - pad_b - (y - ymin) / (ymax - ymin) * (H - pad_t - pad_b)

    dots = []
    for x, y, cls in pts:
        dots.append(
            f'<circle cx="{sx(x):.1f}" cy="{sy(y):.1f}" r="5" '
            f'fill="{CLASS_COLORS[cls]}" fill-opacity="0.7" '
            f'stroke="#fff" stroke-width="1"/>'
        )

    # оси
    axes = f'''
    <line x1="{pad_l}" y1="{H-pad_b}" x2="{W-pad_r}" y2="{H-pad_b}" stroke="#999" stroke-width="1"/>
    <line x1="{pad_l}" y1="{pad_t}" x2="{pad_l}" y2="{H-pad_b}" stroke="#999" stroke-width="1"/>
    <text x="{W/2}" y="{H-10}" text-anchor="middle" font-size="12" fill="#666">log₁₀(bytes/sec)</text>
    <text x="15" y="{H/2}" text-anchor="middle" font-size="12" fill="#666" transform="rotate(-90 15 {H/2})">log₁₀(down/up ratio)</text>
    '''

    # метки делений
    ticks = []
    for i in range(5):
        xt = xmin + (xmax - xmin) * i / 4
        ticks.append(
            f'<text x="{sx(xt):.1f}" y="{H-pad_b+16}" text-anchor="middle" font-size="11" fill="#999">'
            f'{10**xt:,.0f}</text>'
        )
        yt = ymin + (ymax - ymin) * i / 4
        ticks.append(
            f'<text x="{pad_l-8}" y="{sy(yt)+4:.1f}" text-anchor="end" font-size="11" fill="#999">'
            f'{10**yt:,.1f}</text>'
        )

    # легенда
    legend_x = W - pad_r - 100
    legend = []
    for i, cls in enumerate(("MESSENGER", "VIDEO", "STREAM", "HTTPS", "UNKNOWN")):
        y0 = pad_t + 10 + i * 18
        legend.append(
            f'<circle cx="{legend_x}" cy="{y0}" r="5" fill="{CLASS_COLORS[cls]}"/>'
            f'<text x="{legend_x+10}" y="{y0+4}" font-size="11" fill="#333">{cls}</text>'
        )

    return f'<svg viewBox="0 0 {W} {H}" width="100%" height="{H}">{axes}{"".join(ticks)}{"".join(dots)}{"".join(legend)}</svg>'


def _svg_histogram(flows: Dict[FlowKey, Flow]) -> str:
    """Гистограмма длительностей потоков (log-bins)."""
    W, H = 680, 280
    pad_l, pad_r, pad_t, pad_b = 50, 20, 20, 40

    durations = [f.features.get("duration_s", 0) for f in flows.values()]
    durations = [d for d in durations if d > 0]
    if not durations:
        return '<div style="color:#999;padding:20px;">Нет данных</div>'

    # log-биннинг: 0.01s, 0.1s, 1s, 10s, 100s, 1000s
    bins_edges = [0, 0.1, 1, 5, 10, 30, 60, 300, float('inf')]
    bin_labels = ["<0.1s", "0.1-1s", "1-5s", "5-10s", "10-30s", "30-60s", "1-5m", ">5m"]
    bin_counts = [0] * len(bin_labels)

    for d in durations:
        for i in range(len(bins_edges) - 1):
            if bins_edges[i] <= d < bins_edges[i+1]:
                bin_counts[i] += 1
                break

    max_count = max(bin_counts) or 1
    bar_w = (W - pad_l - pad_r) / len(bin_labels) - 6

    bars = []
    labels = []
    for i, (lbl, cnt) in enumerate(zip(bin_labels, bin_counts)):
        x = pad_l + i * ((W - pad_l - pad_r) / len(bin_labels)) + 3
        h = (cnt / max_count) * (H - pad_t - pad_b) if cnt else 0
        y = H - pad_b - h
        bars.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{h:.1f}" '
            f'fill="#4A90E2" fill-opacity="0.8" rx="2"/>'
        )
        if cnt > 0:
            bars.append(
                f'<text x="{x+bar_w/2:.1f}" y="{y-4:.1f}" text-anchor="middle" '
                f'font-size="11" fill="#333">{cnt}</text>'
            )
        labels.append(
            f'<text x="{x+bar_w/2:.1f}" y="{H-pad_b+16}" text-anchor="middle" '
            f'font-size="11" fill="#666">{lbl}</text>'
        )

    return f'''<svg viewBox="0 0 {W} {H}" width="100%" height="{H}">
      <line x1="{pad_l}" y1="{H-pad_b}" x2="{W-pad_r}" y2="{H-pad_b}" stroke="#999"/>
      {"".join(bars)}
      {"".join(labels)}
    </svg>'''


def _html_row(i: int, flow: Flow) -> str:
    f = flow.features
    sni = f.get("sni", "") or "—"
    if len(sni) > 40: sni = sni[:37] + "…"
    ech = '<span class="ech-star">★</span>' if f.get("has_ech") else "—"

    bps = f.get("bytes_per_sec", 0)
    if bps >= 1e6:   bps_s = f"{bps/1e6:.1f}M"
    elif bps >= 1e3: bps_s = f"{bps/1e3:.1f}K"
    else:            bps_s = f"{bps:.0f}"

    total = f.get("total_bytes", 0)
    if total >= 1e6:   total_s = f"{total/1e6:.1f}M"
    elif total >= 1e3: total_s = f"{total/1e3:.1f}K"
    else:              total_s = str(total)

    src_short = flow.src if len(flow.src) < 20 else flow.src[:17] + "…"
    dst_short = flow.dst if len(flow.dst) < 20 else flow.dst[:17] + "…"

    return f'''
    <tr>
      <td>{i}</td>
      <td><span class="class-pill" style="background:{CLASS_COLORS[flow.predicted_class]}">{flow.predicted_class}</span></td>
      <td class="conf">{flow.confidence:.2f}</td>
      <td><code style="font-size:11px">{src_short}:{flow.sport}<br>→ {dst_short}:{flow.dport}</code></td>
      <td>{flow.proto}</td>
      <td>{f.get('pkt_count', 0)}</td>
      <td>{total_s}</td>
      <td>{f.get('duration_s', 0):.1f}s</td>
      <td>{bps_s}</td>
      <td>{ech}</td>
      <td><code style="font-size:11px">{sni}</code></td>
      <td class="reason">{flow.reason}</td>
    </tr>
    '''


def write_html(flows: Dict[FlowKey, Flow], path: str) -> None:
    counts: Dict[str, int] = defaultdict(int)
    for f in flows.values():
        counts[f.predicted_class] += 1

    tls_flows = sum(1 for f in flows.values() if any(p.tls_record_type for p in f.packets))
    ech_flows = sum(1 for f in flows.values() if f.features.get("has_ech"))

    # карточки вверху
    cards_html = ""
    for cls in ("MESSENGER", "VIDEO", "STREAM", "HTTPS"):
        n = counts.get(cls, 0)
        cards_html += f'''
        <div class="card" style="border-top: 3px solid {CLASS_COLORS[cls]}">
          <div class="n">{n}</div>
          <div class="l">{cls}</div>
        </div>'''
    cards_html += f'''
        <div class="card" style="border-top: 3px solid #666">
          <div class="n">{ech_flows}</div>
          <div class="l">с ECH</div>
        </div>'''

    # сортируем потоки для таблицы: сначала с более высокой conf, потом по pkt_count
    flow_list = sorted(
        flows.values(),
        key=lambda fl: (fl.predicted_class, -fl.confidence, -fl.features.get("pkt_count", 0))
    )
    rows_html = "\n".join(_html_row(i+1, f) for i, f in enumerate(flow_list))

    html = (HTML_TEMPLATE
        .replace("{TIMESTAMP}", time.strftime("%Y-%m-%d %H:%M:%S"))
        .replace("{TOTAL_FLOWS}", str(len(flows)))
        .replace("{TLS_FLOWS}", str(tls_flows))
        .replace("{ECH_FLOWS}", str(ech_flows))
        .replace("{STAT_CARDS}", cards_html)
        .replace("{PIE_CHART}", _svg_pie(counts))
        .replace("{SCATTER_CHART}", _svg_scatter(flows))
        .replace("{HISTO_CHART}", _svg_histogram(flows))
        .replace("{TABLE_ROWS}", rows_html)
    )

    with open(path, "w", encoding="utf-8") as fp:
        fp.write(html)
    print(f"[*] HTML отчёт сохранён: {path}")


# ═══════════════════════════════════════════════════════════════════════════════
#                                    CLI
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Эвристический классификатор ECH/TLS-трафика",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Примеры:
              python ech_classifier.py capture.pcap
              python ech_classifier.py capture.pcap -o report.html -j report.json
              python ech_classifier.py capture.pcap --limit 50
        """)
    )
    parser.add_argument("pcap", help="Путь к PCAP-файлу")
    parser.add_argument("-o", "--html", default="ech_report.html",
                        help="Путь к выходному HTML-отчёту (по умолчанию: ech_report.html)")
    parser.add_argument("-j", "--json", default=None,
                        help="Путь к выходному JSON-отчёту")
    parser.add_argument("--limit", type=int, default=20,
                        help="Сколько потоков показать в консоли (по умолчанию: 20)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Минимальный вывод")
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"ERROR: Файл не найден: {args.pcap}", file=sys.stderr)
        return 1

    flows = extract_flows(args.pcap, verbose=not args.quiet)
    classify_all(flows, verbose=not args.quiet)

    if not args.quiet:
        print_summary(flows)
        print_details(flows, limit=args.limit)

    write_html(flows, args.html)
    if args.json:
        write_json(flows, args.json)

    return 0


if __name__ == "__main__":
    sys.exit(main())
