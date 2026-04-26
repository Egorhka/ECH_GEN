#!/usr/bin/env python3
"""
evaluate_heuristic.py — Оценка эвристического классификатора
=============================================================

Запускает ech_classifier на каждом pcap отдельно,
сопоставляет предсказания с реальными метками из labels.csv,
вычисляет Accuracy, Precision, Recall, F1 и строит Confusion Matrix.

Запуск:
    python evaluate_heuristic.py
    python evaluate_heuristic.py --pcap-dir dataset/pcap --labels dataset/labels.csv
"""

import argparse
import csv
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

# Добавляем путь к ech_classifier.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from ech_classifier import extract_flows, compute_features, classify_heuristic
except ImportError:
    print("ОШИБКА: Не найден ech_classifier.py рядом со скриптом")
    sys.exit(1)

try:
    import pandas as pd
    from sklearn.metrics import (classification_report, confusion_matrix,
                                  accuracy_score)
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use("Agg")
    import seaborn as sns
except ImportError:
    print("ОШИБКА: Установите зависимости:")
    print("  pip install scikit-learn pandas matplotlib seaborn")
    sys.exit(1)


CLASSES = ["HTTPS", "VIDEO", "STREAM", "MESSENGER"]


def evaluate(pcap_dir: str, labels_path: str, output_dir: str,
             min_packets: int = 10, skip_unknown: bool = True):

    # ── Загрузка меток ────────────────────────────────────────────────────────
    labels = {}
    with open(labels_path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            labels[row["pcap_file"]] = {
                "class": row["traffic_class"],
                "ech":   row.get("ech_enabled", "True") == "True",
            }

    print(f"Загружено меток: {len(labels)}")
    print(f"Директория pcap: {pcap_dir}")
    print()

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    y_true_all = []
    y_pred_all = []

    # Раздельно для ECH и plain
    y_true_ech   = []; y_pred_ech   = []
    y_true_plain = []; y_pred_plain = []

    per_file_results = []
    total_flows = 0
    unknown_count = 0

    # ── Обработка каждого pcap ────────────────────────────────────────────────
    for pcap_file, meta in labels.items():
        pcap_path = os.path.join(pcap_dir, pcap_file)
        true_class = meta["class"]
        ech_enabled = meta["ech"]

        if not os.path.exists(pcap_path):
            print(f"  Пропущен (не найден): {pcap_file}")
            continue

        print(f"  [{true_class:9s}|{'ECH' if ech_enabled else 'plain'}] {pcap_file}")

        try:
            flows = extract_flows(pcap_path, verbose=False)
        except Exception as e:
            print(f"    Ошибка чтения: {e}")
            continue

        file_true = []
        file_pred = []
        file_unknown = 0

        for flow in flows.values():
            features = compute_features(flow)
            if not features:
                continue
            if features.get("pkt_count", 0) < min_packets:
                continue

            predicted, conf, reason = classify_heuristic(features)

            if predicted == "UNKNOWN":
                unknown_count += 1
                file_unknown += 1
                if skip_unknown:
                    continue

            file_true.append(true_class)
            file_pred.append(predicted)

        total_flows += len(file_true) + file_unknown

        if file_true:
            file_acc = accuracy_score(file_true, file_pred)
            print(f"    → {len(file_true)} потоков, accuracy={file_acc:.2f}")

            y_true_all.extend(file_true)
            y_pred_all.extend(file_pred)

            if ech_enabled:
                y_true_ech.extend(file_true)
                y_pred_ech.extend(file_pred)
            else:
                y_true_plain.extend(file_true)
                y_pred_plain.extend(file_pred)

            per_file_results.append({
                "pcap_file":   pcap_file,
                "true_class":  true_class,
                "ech_enabled": ech_enabled,
                "n_flows":     len(file_true),
                "n_unknown":   file_unknown,
                "accuracy":    round(file_acc, 4),
            })

    print()
    print(f"Всего потоков обработано: {total_flows}")
    print(f"UNKNOWN (пропущено):      {unknown_count}")
    print(f"Использовано для оценки:  {len(y_true_all)}")

    if not y_true_all:
        print("ОШИБКА: нет данных для оценки")
        sys.exit(1)

    # ── Общие метрики ─────────────────────────────────────────────────────────
    print()
    print("═" * 65)
    print("  РЕЗУЛЬТАТЫ — ВЕСЬ ДАТАСЕТ (ECH + plain)")
    print("═" * 65)
    acc = accuracy_score(y_true_all, y_pred_all)
    print(f"  Accuracy: {acc:.4f} ({acc*100:.1f}%)")
    print()
    report_all = classification_report(
        y_true_all, y_pred_all, labels=CLASSES, zero_division=0)
    print(report_all)

    # ── ECH метрики ───────────────────────────────────────────────────────────
    if y_true_ech:
        print("═" * 65)
        print("  РЕЗУЛЬТАТЫ — ТОЛЬКО ECH ТРАФИК")
        print("═" * 65)
        acc_ech = accuracy_score(y_true_ech, y_pred_ech)
        print(f"  Accuracy: {acc_ech:.4f} ({acc_ech*100:.1f}%)")
        print()
        print(classification_report(
            y_true_ech, y_pred_ech, labels=CLASSES, zero_division=0))

    # ── Plain метрики ─────────────────────────────────────────────────────────
    if y_true_plain:
        print("═" * 65)
        print("  РЕЗУЛЬТАТЫ — ТОЛЬКО PLAIN TLS (без ECH)")
        print("═" * 65)
        acc_plain = accuracy_score(y_true_plain, y_pred_plain)
        print(f"  Accuracy: {acc_plain:.4f} ({acc_plain*100:.1f}%)")
        print()
        print(classification_report(
            y_true_plain, y_pred_plain, labels=CLASSES, zero_division=0))

    # ── Confusion Matrix — всё ────────────────────────────────────────────────
    def save_cm(y_t, y_p, title, filename):
        cm = confusion_matrix(y_t, y_p, labels=CLASSES)
        plt.figure(figsize=(7, 6))
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                    xticklabels=CLASSES, yticklabels=CLASSES)
        plt.title(title)
        plt.ylabel("Истинный класс")
        plt.xlabel("Предсказанный класс")
        plt.tight_layout()
        path = os.path.join(output_dir, filename)
        plt.savefig(path, dpi=150)
        plt.close()
        print(f"  Сохранено: {path}")

    print("═" * 65)
    print("  ГРАФИКИ")
    print("═" * 65)
    save_cm(y_true_all,   y_pred_all,
            "Эвристика — Все потоки", "cm_all.png")
    if y_true_ech:
        save_cm(y_true_ech,   y_pred_ech,
                "Эвристика — ECH трафик", "cm_ech.png")
    if y_true_plain:
        save_cm(y_true_plain, y_pred_plain,
                "Эвристика — Plain TLS",  "cm_plain.png")

    # ── Сравнительный график ECH vs Plain ────────────────────────────────────
    if y_true_ech and y_true_plain:
        from sklearn.metrics import f1_score
        fig, ax = plt.subplots(figsize=(9, 5))
        x = range(len(CLASSES))
        width = 0.35

        f1_ech   = f1_score(y_true_ech,   y_pred_ech,
                            labels=CLASSES, average=None, zero_division=0)
        f1_plain = f1_score(y_true_plain, y_pred_plain,
                            labels=CLASSES, average=None, zero_division=0)

        bars1 = ax.bar([i - width/2 for i in x], f1_ech,   width,
                       label="ECH",   color="#4A90E2", alpha=0.85)
        bars2 = ax.bar([i + width/2 for i in x], f1_plain, width,
                       label="Plain TLS", color="#50C878", alpha=0.85)

        ax.set_xlabel("Класс трафика")
        ax.set_ylabel("F1-score")
        ax.set_title("F1-score по классам: ECH vs Plain TLS\n(Эвристический классификатор)")
        ax.set_xticks(list(x))
        ax.set_xticklabels(CLASSES)
        ax.set_ylim(0, 1.05)
        ax.legend()
        ax.grid(axis="y", alpha=0.3)

        for bar in bars1:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, h + 0.01,
                    f"{h:.2f}", ha="center", va="bottom", fontsize=9)
        for bar in bars2:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, h + 0.01,
                    f"{h:.2f}", ha="center", va="bottom", fontsize=9)

        plt.tight_layout()
        path = os.path.join(output_dir, "f1_ech_vs_plain.png")
        plt.savefig(path, dpi=150)
        plt.close()
        print(f"  Сохранено: {path}")

    # ── CSV с результатами по файлам ──────────────────────────────────────────
    df_per_file = pd.DataFrame(per_file_results)
    csv_path = os.path.join(output_dir, "heuristic_per_file.csv")
    df_per_file.to_csv(csv_path, index=False)
    print(f"  Сохранено: {csv_path}")

    # ── Сводная таблица для диссертации ──────────────────────────────────────
    print()
    print("═" * 65)
    print("  СВОДКА ДЛЯ ДИССЕРТАЦИИ")
    print("═" * 65)
    from sklearn.metrics import precision_score, recall_score, f1_score

    summary = {
        "Метод": "Эвристика (каскад правил)",
        "Accuracy (все)":    f"{accuracy_score(y_true_all, y_pred_all):.4f}",
        "Macro F1 (все)":    f"{f1_score(y_true_all, y_pred_all, average='macro', labels=CLASSES, zero_division=0):.4f}",
        "Accuracy (ECH)":    f"{accuracy_score(y_true_ech, y_pred_ech):.4f}" if y_true_ech else "—",
        "Macro F1 (ECH)":    f"{f1_score(y_true_ech, y_pred_ech, average='macro', labels=CLASSES, zero_division=0):.4f}" if y_true_ech else "—",
        "Accuracy (plain)":  f"{accuracy_score(y_true_plain, y_pred_plain):.4f}" if y_true_plain else "—",
        "Macro F1 (plain)":  f"{f1_score(y_true_plain, y_pred_plain, average='macro', labels=CLASSES, zero_division=0):.4f}" if y_true_plain else "—",
        "Потоков оценено":   len(y_true_all),
        "UNKNOWN пропущено": unknown_count,
    }

    for k, v in summary.items():
        print(f"  {k:25s}: {v}")


def main():
    parser = argparse.ArgumentParser(
        description="Оценка эвристического классификатора ECH-трафика"
    )
    parser.add_argument("--pcap-dir", default="dataset/pcap",
                        help="Директория с pcap файлами")
    parser.add_argument("--labels",   default="dataset/labels.csv",
                        help="Файл разметки labels.csv")
    parser.add_argument("--output",   default="dataset/eval",
                        help="Директория для графиков и результатов")
    parser.add_argument("--min-packets", type=int, default=10,
                        help="Мин. пакетов в потоке (по умолч. 10)")
    parser.add_argument("--keep-unknown", action="store_true",
                        help="Включать UNKNOWN потоки в оценку")
    args = parser.parse_args()

    evaluate(
        pcap_dir=args.pcap_dir,
        labels_path=args.labels,
        output_dir=args.output,
        min_packets=args.min_packets,
        skip_unknown=not args.keep_unknown,
    )


if __name__ == "__main__":
    main()
