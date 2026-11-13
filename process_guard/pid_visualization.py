"""Headless PID dataset EDA and model comparison figures."""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from .features import FEATURE_COLUMNS
from .pid_data import load_observations


def analyze_observations(sources, output: Path) -> dict:
    data, provenance = load_observations(sources)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    counts = data.groupby("label").agg(snapshots=("label", "size"), executable_paths=("group", "nunique"),
                                      label_sources=("label_source", "nunique")).reindex([0, 1], fill_value=0)
    counts.index.name = "label"
    counts.to_csv(output / "class_balance.csv")
    data.groupby("label")[FEATURE_COLUMNS].agg(["mean", "median", "std", "min", "max"]).to_csv(
        output / "feature_statistics.csv")
    duplicate_fields = ["source_file", "group", "label", *FEATURE_COLUMNS]
    summary = {"sources": provenance, "snapshot_count": len(data),
               "class_counts": {str(int(k)): int(v) for k, v in data.label.value_counts().items()},
               "executable_paths": int(data.group.nunique()),
               "paths_with_both_labels": int(data.groupby("group").label.nunique().gt(1).sum()),
               "identical_feature_rows_within_source": int(data.duplicated(duplicate_fields).sum()),
               "constant_features": [column for column in FEATURE_COLUMNS if data[column].nunique() <= 1],
               "notes": ["Labels are operator supplied, not verified by EDA.",
                         "Snapshots are correlated; executable path counts are not binary hash counts.",
                         "Identical features can be legitimate idle observations and are not automatically removed.",
                         "Signature/Sysmon checked flags may reflect missing enrichment, not negative findings."]}
    (output / "eda_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for ax, column, title in zip(axes, ["snapshots", "executable_paths"], ["Labeled snapshots", "Executable paths per class"]):
        ax.bar(["Benign", "Simulated"], counts[column], color=["#2563eb", "#ea580c"])
        ax.set_title(title)
        ax.set_ylabel("Count")
    fig.suptitle("PID observations - operator labels")
    fig.tight_layout()
    fig.savefig(output / "class_balance.png", dpi=140)
    plt.close(fig)
    features = ["cpu_percent", "memory_percent", "thread_count", "connection_count",
                "file_read_rate_kbps", "file_write_rate_kbps"]
    fig, axes = plt.subplots(2, 3, figsize=(12, 7))
    for ax, column in zip(axes.flat, features):
        classes = sorted(data.label.unique())
        ax.boxplot([data.loc[data.label.eq(label), column].to_numpy() for label in classes])
        ax.set_xticks(range(1, len(classes) + 1), ["Benign" if label == 0 else "Simulated" for label in classes])
        ax.set_title(column)
        ax.set_yscale("symlog", linthresh=1)
        ax.grid(axis="y", alpha=0.2)
    fig.suptitle("Runtime features - correlated snapshots, symlog scale")
    fig.tight_layout()
    fig.savefig(output / "runtime_features.png", dpi=140)
    plt.close(fig)
    return summary


def plot_pid_training_results(report_dir: Path) -> list[Path]:
    report_dir = Path(report_dir)
    comparison = pd.read_csv(report_dir / "model_comparison.csv")
    outputs = []
    fig, ax = plt.subplots(figsize=(11, 5))
    x = np.arange(len(comparison))
    for i, metric in enumerate(("accuracy", "precision", "recall", "f1", "false_positive_rate")):
        ax.bar(x + (i - 2) * 0.15, comparison[metric], width=0.14, label=metric)
    ax.set_xticks(x, comparison.model.str.replace(" (unsupervised)", "", regex=False))
    ax.set_ylim(0, 1.05)
    ax.set_title("PID held-out test - ML only, alert threshold 0.65")
    ax.legend(ncols=3, fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.12))
    fig.tight_layout()
    path = report_dir / "model_comparison.png"
    fig.savefig(path, dpi=140, bbox_inches="tight")
    outputs.append(path)
    plt.close(fig)
    fig, axes = plt.subplots(2, 2, figsize=(9, 8))
    for ax, name in zip(axes.flat, ["decision_tree", "random_forest", "extra_trees", "isolation_forest"]):
        report = json.loads((report_dir / f"{name}_confusion.json").read_text(encoding="utf-8"))
        matrix = np.array(report["confusion_matrix"])
        ax.imshow(matrix, cmap="Blues", vmin=0, vmax=max(1, int(matrix.max())))
        for (i, j), value in np.ndenumerate(matrix):
            ax.text(j, i, str(value), ha="center", va="center",
                    color="white" if value > matrix.max() / 2 else "black")
        ax.set(title=name.replace("_", " "), xlabel="Predicted", ylabel="Actual")
        ax.set_xticks([0, 1], ["Benign", "Simulated"])
        ax.set_yticks([0, 1], ["Benign", "Simulated"])
    fig.tight_layout()
    path = report_dir / "confusion_matrices.png"
    fig.savefig(path, dpi=140)
    outputs.append(path)
    plt.close(fig)
    for name in ("decision_tree", "random_forest", "extra_trees"):
        importance = pd.read_csv(report_dir / f"{name}_feature_importance.csv").head(12).iloc[::-1]
        fig, ax = plt.subplots(figsize=(9, 5))
        ax.barh(importance.feature, importance.importance, color="#2563eb")
        ax.set_title(f"{name.replace('_', ' ')} - feature importance")
        fig.tight_layout()
        path = report_dir / f"{name}_feature_importance.png"
        fig.savefig(path, dpi=140)
        outputs.append(path)
        plt.close(fig)
    return outputs
