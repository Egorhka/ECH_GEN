#!/usr/bin/env python3
"""
build_dataset.py — Собирает размеченный датасет из pcap + labels.csv
====================================================================

Берёт pcap-файлы, сгенерированные traffic_generator.py,
извлекает признаки потоков и присваивает метки класса.

Вход:
    dataset/pcap/*.pcap     — файлы захвата
    dataset/labels.csv      — разметка (pcap_file → class)

Выход:
    dataset/features.csv    — признаки + метки, готово для sklearn/pytorch

Использование:
    python3 build_dataset.py
    python3 build_dataset.py --input my_dataset --output my_dataset/features.csv

Требования:
    pip install scapy pandas
"""

import argparse
import csv
import json
import os
import subprocess
import shutil
import sys
from pathlib import Path
from collections import defaultdict

# Переиспользуем код из ech_classifier.py
# Добавь путь, если файл лежит в другом месте
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from ech_classifier import extract_flows, compute_features, Flow, FlowKey
except ImportError:
    print("ОШИБКА: Не найден ech_classifier.py в текущей директории.")
    print("Скопируйте его сюда или укажите путь.")
    sys.exit(1)

try:
    import pandas as pd
except ImportError:
    print("ОШИБКА: pandas не установлен. Выполните: pip install pandas")
    sys.exit(1)


def load_labels(labels_path: str) -> dict:
    """Загружает labels.csv → {pcap_file: {class, ech_enabled}}."""
    labels = {}
    with open(labels_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            labels[row["pcap_file"]] = {
                "traffic_class": row["traffic_class"],
                "ech_enabled": row.get("ech_enabled", "True") == "True",
            }
    return labels


def process_pcap(pcap_path: str, traffic_class: str, ech_enabled: bool) -> list:
    """Обрабатывает один pcap, возвращает список словарей (строк датасета)."""
    try:
        flows = extract_flows(pcap_path, verbose=False)
    except Exception as e:
        print(f"  Ошибка при чтении {pcap_path}: {e}")
        return []

    rows = []
    for flow in flows.values():
        features = compute_features(flow)
        if not features:
            continue

        # Пропускаем слишком маленькие потоки
        if features.get("pkt_count", 0) < 5:
            continue

        row = {
            "label": traffic_class,
            "ech_enabled_scenario": int(ech_enabled),   # ECH был включён в браузере
            "src": flow.src,
            "dst": flow.dst,
            "sport": flow.sport,
            "dport": flow.dport,
            "proto": flow.proto,
            "pcap_file": os.path.basename(pcap_path),
        }
        # Добавляем все числовые признаки
        for k, v in features.items():
            if k in ("sni", "has_ech"):
                # sni — строка, has_ech — bool → кодируем
                if k == "has_ech":
                    row["has_ech"] = int(v)
                elif k == "sni":
                    row["sni"] = v
            else:
                row[k] = v

        rows.append(row)

    return rows


def merge_pcaps(labels: dict, pcap_dir: Path, output_dir: Path):
    """
    Объединяет pcap-файлы через mergecap (из пакета wireshark-common).
    Создаёт три файла:
        merged_all.pcap   — все сценарии (смешанный трафик)
        merged_ech.pcap   — только ECH-сценарии
        merged_plain.pcap — только plain (без ECH)
    """
    if not shutil.which("mergecap"):
        print("\n  ⚠ mergecap не найден — пропускаю объединение pcap")
        print("    Установите: sudo apt install wireshark-common")
        print("    Или вручную: mergecap -w merged.pcap dataset/pcap/*.pcap")
        return

    # Группируем файлы по режиму ECH
    all_files = []
    ech_files = []
    plain_files = []

    for pcap_file, meta in labels.items():
        pcap_path = pcap_dir / pcap_file
        if not pcap_path.exists():
            continue
        all_files.append(str(pcap_path))
        if meta["ech_enabled"]:
            ech_files.append(str(pcap_path))
        else:
            plain_files.append(str(pcap_path))

    merged_dir = output_dir / "merged"
    merged_dir.mkdir(exist_ok=True)

    merges = [
        ("merged_all.pcap",   all_files,   "все"),
        ("merged_ech.pcap",   ech_files,   "ECH"),
        ("merged_plain.pcap", plain_files, "plain"),
    ]

    print(f"\n  Объединение pcap (mergecap):")
    for name, files, desc in merges:
        if not files:
            print(f"    {name}: пропущен (нет {desc}-файлов)")
            continue
        out_path = merged_dir / name
        try:
            subprocess.run(
                ["mergecap", "-w", str(out_path)] + files,
                check=True, capture_output=True,
            )
            size_mb = out_path.stat().st_size / (1024 * 1024)
            print(f"    {name}: {len(files)} файлов → {size_mb:.1f} МБ")
        except subprocess.CalledProcessError as e:
            print(f"    {name}: ошибка mergecap — {e.stderr.decode()}")


def main():
    parser = argparse.ArgumentParser(
        description="Сборка размеченного датасета из pcap-файлов"
    )
    parser.add_argument("--input", default="dataset",
                        help="Директория с pcap/ и labels.csv")
    parser.add_argument("--output", default=None,
                        help="Путь к выходному CSV (по умолч. dataset/features.csv)")
    parser.add_argument("--min-packets", type=int, default=5,
                        help="Мин. пакетов в потоке (по умолч. 5)")
    parser.add_argument("--no-merge", action="store_true",
                        help="Не объединять pcap файлы")
    args = parser.parse_args()

    input_dir = Path(args.input)
    labels_path = input_dir / "labels.csv"
    pcap_dir = input_dir / "pcap"
    output_path = args.output or str(input_dir / "features.csv")

    if not labels_path.exists():
        print(f"ОШИБКА: Не найден {labels_path}")
        print("Сначала запустите traffic_generator.py")
        sys.exit(1)

    labels = load_labels(str(labels_path))
    print(f"Загружено {len(labels)} записей из labels.csv")

    all_rows = []
    for pcap_file, meta in labels.items():
        pcap_path = pcap_dir / pcap_file
        traffic_class = meta["traffic_class"]
        ech_enabled = meta["ech_enabled"]

        if not pcap_path.exists():
            print(f"  Пропущен (не найден): {pcap_file}")
            continue

        ech_tag = "ECH" if ech_enabled else "plain"
        print(f"  Обрабатываю: {pcap_file} → {traffic_class} [{ech_tag}]")
        rows = process_pcap(str(pcap_path), traffic_class, ech_enabled)
        all_rows.extend(rows)
        print(f"    → {len(rows)} потоков")

    if not all_rows:
        print("ОШИБКА: Не удалось извлечь ни одного потока")
        sys.exit(1)

    df = pd.DataFrame(all_rows)

    # Статистика
    print(f"\n{'═'*50}")
    print("  ДАТАСЕТ СОБРАН")
    print(f"{'═'*50}")
    print(f"  Всего потоков: {len(df)}")
    print(f"\n  Распределение классов:")
    for cls, count in df["label"].value_counts().items():
        print(f"    {cls:12s}: {count:6d} ({100*count/len(df):.1f}%)")
    if "ech_enabled_scenario" in df.columns:
        ech_count = df["ech_enabled_scenario"].sum()
        plain_count = len(df) - ech_count
        print(f"\n  По режиму ECH:")
        print(f"    ECH:         {ech_count:6d} ({100*ech_count/len(df):.1f}%)")
        print(f"    plain (TLS): {plain_count:6d} ({100*plain_count/len(df):.1f}%)")

    # Убираем строковые столбцы из признаков, но сохраняем в CSV
    df.to_csv(output_path, index=False, encoding="utf-8")
    print(f"\n  Сохранено: {output_path}")
    print(f"  Столбцы: {list(df.columns)}")

    # ── Объединение pcap ──────────────────────────────────────────────────
    if not args.no_merge:
        merge_pcaps(labels, pcap_dir, input_dir)

    # ── Итоговая структура ────────────────────────────────────────────────
    print(f"\n{'═'*50}")
    print("  ГОТОВЫЕ ФАЙЛЫ")
    print(f"{'═'*50}")
    print(f"  {output_path}")
    print(f"      → features.csv для обучения ML/DL")
    if not args.no_merge and shutil.which("mergecap"):
        print(f"  {input_dir}/merged/merged_all.pcap")
        print(f"      → весь трафик для ech_classifier.py")
        print(f"  {input_dir}/merged/merged_ech.pcap")
        print(f"      → только ECH-трафик")
        print(f"  {input_dir}/merged/merged_plain.pcap")
        print(f"      → только обычный TLS")
        print(f"\n  Тест классификатора:")
        print(f"    python3 ech_classifier.py {input_dir}/merged/merged_all.pcap -o report.html")
    print(f"{'═'*50}")


if __name__ == "__main__":
    main()
