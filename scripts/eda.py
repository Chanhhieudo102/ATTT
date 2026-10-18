"""Exploratory analysis of the official Cardiff runtime-telemetry dataset."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from process_guard.cardiff import METRICS, load_cardiff_csv, make_sequences, remove_ambiguous_sample_ids


def run(source: Path = ROOT / "data/raw/cardiff_data_2.csv"):
    data = load_cardiff_csv(source)
    total_samples = data["sample_id"].nunique()
    data, excluded = remove_ambiguous_sample_ids(data)
    report_dir = ROOT / "artifacts/reports/cardiff"; report_dir.mkdir(parents=True, exist_ok=True)
    sequences, labels, _, sample_ids, metrics = make_sequences(source, seconds=5)
    sample_labels = pd.DataFrame({"sample_id": sample_ids, "malware": labels})
    sample_labels["label_name"] = sample_labels["malware"].map({0: "benign", 1: "malicious"})
    balance = sample_labels["label_name"].value_counts().reindex(["benign", "malicious"], fill_value=0)
    balance.rename_axis("label").rename("samples").to_csv(report_dir / "cardiff_class_balance.csv")

    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.bar(balance.index, balance.values, color=["#4e79a7", "#e15759"])
    for bar, count in zip(bars, balance.values):
        ax.annotate(f"{count:,} ({count / max(1, len(sample_labels)):.1%})",
                    (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                    xytext=(0, 5), textcoords="offset points", ha="center", fontsize=10)
    ax.set(title="Cardiff Dataset 2 — sample-level class balance",
           xlabel="Class label", ylabel="Executable samples", ylim=(0, max(balance.values) * 1.18))
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(report_dir / "cardiff_eda_class_balance.png", dpi=140)
    plt.close(fig)

    data.groupby("malware")[METRICS].agg(["mean", "median", "std"]).to_csv(report_dir / "cardiff_eda_by_label.csv")
    sample_means = pd.DataFrame(sequences.mean(axis=1), columns=metrics)
    sample_means.insert(0, "malware", labels)
    sample_means.groupby("malware")[metrics].agg(["mean", "median", "std"]).to_csv(
        report_dir / "cardiff_eda_by_sample_5s.csv")

    for metric in ("cpu_system", "cpu_user", "memory", "total_processes", "rx_bytes", "tx_bytes"):
        metric_index = metrics.index(metric)
        fig, ax = plt.subplots(figsize=(8, 4))
        for label, label_name, color in ((0, "benign", "#4e79a7"), (1, "malicious", "#e15759")):
            class_sequences = sequences[labels == label, :, metric_index]
            ax.plot(np.arange(5), class_sequences.mean(axis=0), marker="o", linewidth=2,
                    label=f"{label_name} (n={len(class_sequences):,})", color=color)
        ax.set_title(f"{metric}: per-sample mean during first 5 seconds")
        ax.set_xlabel("Seconds from sample start")
        ax.set_ylabel(metric)
        ax.set_xticks(np.arange(5))
        ax.grid(alpha=0.25)
        ax.legend(frameon=False)
        plt.tight_layout()
        plt.savefig(report_dir / f"cardiff_eda_{metric}.png", dpi=140)
        plt.close()
    print(f"Samples retained: {sample_labels.shape[0]} / {total_samples} | ambiguous IDs excluded: {excluded} | observations: {len(data)}")
    print(f"EDA files saved to {report_dir}")
    print("These plots describe machine-level sandbox telemetry, not process-attributed telemetry.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=ROOT / "data/raw/cardiff_data_2.csv")
    args = parser.parse_args()
    run(args.source)
