"""Full exploratory data analysis of Cardiff Dataset 2 (raw data, before any modelling).

Outputs tables (CSV/JSON) and figures (PNG) to artifacts/reports/cardiff_eda/.
Usage: python scripts/eda_cardiff_full.py [--source data/raw/cardiff_data_2.csv]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from process_guard.cardiff import METRICS, load_cardiff_csv, remove_ambiguous_sample_ids

OUT = ROOT / "artifacts/reports/cardiff_eda"
BENIGN, MALICIOUS = "#2563eb", "#dc2626"
LABELS = {0: "Lành tính", 1: "Độc hại"}
UNITS = {"cpu_system": "%", "cpu_user": "%", "memory": "byte", "swap": "byte", "total_processes": "tiến trình",
         "max_pid": "PID", "rx_bytes": "byte (cộng dồn)", "tx_bytes": "byte (cộng dồn)",
         "rx_packets": "gói (cộng dồn)", "tx_packets": "gói (cộng dồn)"}


def save(fig, name: str) -> Path:
    path = OUT / name
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "data/raw/cardiff_data_2.csv")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    summary: dict = {}

    # ---------------------------------------------------------------- 1. raw structure
    raw = pd.read_csv(args.source, low_memory=False)
    summary["raw_rows"], summary["raw_columns"] = int(raw.shape[0]), int(raw.shape[1])
    summary["columns"] = list(raw.columns)
    summary["missing_per_column"] = {k: int(v) for k, v in raw.isna().sum().items()}
    summary["duplicate_rows"] = int(raw.duplicated().sum())
    summary["duplicate_column_total_pro_identical"] = bool((raw["total_pro"] == raw["total_pro.1"]).all())
    summary["raw_samples"] = int(raw["sample_id"].nunique())
    per_sample = raw.groupby("sample_id")
    summary["conflicting_label_ids"] = int((per_sample["malware"].nunique() > 1).sum())
    summary["conflicting_test_set_ids"] = int((per_sample["test_set"].nunique() > 1).sum())
    summary["vector_min"], summary["vector_max"] = int(raw["vector"].min()), int(raw["vector"].max())
    duplicated_seconds = raw.duplicated(["sample_id", "vector"]).sum()
    summary["rows_sharing_sample_and_second"] = int(duplicated_seconds)
    raw.describe().T.to_csv(OUT / "raw_describe.csv")

    # ---------------------------------------------------------------- 2. cleaning (same as pipeline)
    data = load_cardiff_csv(args.source)
    data, excluded = remove_ambiguous_sample_ids(data)
    summary["excluded_ambiguous_ids"] = excluded
    samples = data.groupby("sample_id").agg(malware=("malware", "first"), test_set=("test_set", "first"),
                                            rows=("vector", "size"), seconds=("vector", "nunique"),
                                            family=("family", "first"))
    summary["clean_rows"], summary["clean_samples"] = int(len(data)), int(len(samples))
    summary["class_counts"] = {LABELS[k]: int(v) for k, v in samples["malware"].value_counts().sort_index().items()}
    split = samples.groupby(["test_set", "malware"]).size().unstack(fill_value=0)
    split.to_csv(OUT / "split_by_class.csv")
    summary["split"] = {("test" if str(k).lower() == "true" else "train"): {LABELS[c]: int(v) for c, v in row.items()}
                        for k, row in split.iterrows()}

    # Figure 1: class balance overall and by published split
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    counts = samples["malware"].value_counts().sort_index()
    bars = axes[0].bar([LABELS[i] for i in counts.index], counts.values, color=[BENIGN, MALICIOUS])
    axes[0].bar_label(bars, labels=[f"{v:,} ({v / counts.sum():.1%})" for v in counts.values])
    axes[0].set_title("Số mẫu theo nhãn (sau làm sạch)")
    axes[0].set_ylim(0, counts.max() * 1.18)
    width = 0.38
    x = np.arange(len(split.index))
    for offset, label, color in ((-width / 2, 0, BENIGN), (width / 2, 1, MALICIOUS)):
        b = axes[1].bar(x + offset, split[label].values, width, label=LABELS[label], color=color)
        axes[1].bar_label(b)
    axes[1].set_xticks(x, ["Train" if str(v).lower() != "true" else "Test" for v in split.index])
    axes[1].set_title("Phân chia train/test do tác giả công bố")
    axes[1].legend(frameon=False)
    for ax in axes:
        ax.set_ylabel("Số mẫu (file thực thi)")
        ax.grid(axis="y", alpha=0.25)
    save(fig, "01_class_balance_split.png")

    # Figure 2: trace length per sample
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    bins = np.arange(0.5, samples["seconds"].max() + 1.5)
    for label, color in ((0, BENIGN), (1, MALICIOUS)):
        axes[0].hist(samples.loc[samples.malware == label, "seconds"], bins=bins, alpha=0.6, color=color,
                     label=LABELS[label])
    axes[0].set_title("Số giây có dữ liệu của mỗi mẫu")
    axes[0].set_xlabel("Số giây (giá trị vector khác nhau)")
    axes[0].set_ylabel("Số mẫu")
    axes[0].legend(frameon=False)
    coverage = [(samples["seconds"] >= s).mean() * 100 for s in range(1, 21)]
    axes[1].plot(range(1, 21), coverage, marker="o", color="#7c3aed")
    axes[1].axvline(5, color="#64748b", linestyle="--")
    axes[1].text(5.3, 20, "cửa sổ 5 giây\ndùng để huấn luyện", fontsize=9, color="#475569")
    axes[1].set_title("Tỷ lệ mẫu có đủ ít nhất N giây")
    axes[1].set_xlabel("N (giây)")
    axes[1].set_ylabel("% mẫu")
    axes[1].set_ylim(0, 105)
    for ax in axes:
        ax.grid(alpha=0.25)
    save(fig, "02_trace_length.png")
    summary["seconds_per_sample"] = samples["seconds"].describe().round(2).to_dict()
    summary["samples_with_at_least_5_seconds_pct"] = round(float((samples["seconds"] >= 5).mean() * 100), 2)

    # Figure 3: malware family distribution
    families = samples.loc[samples.malware == 1, "family"].fillna("(không ghi)").value_counts()
    families.to_csv(OUT / "malware_families.csv")
    fig, ax = plt.subplots(figsize=(10, 4.8))
    bars = ax.barh(families.index[::-1], families.values[::-1], color=MALICIOUS, alpha=0.8)
    ax.bar_label(bars, padding=3, fontsize=8)
    ax.set_title("Phân bố họ mã độc trong lớp độc hại")
    ax.set_xlabel("Số mẫu")
    ax.grid(axis="x", alpha=0.25)
    save(fig, "03_malware_families.png")
    summary["malware_families"] = {k: int(v) for k, v in families.items()}

    # Per-sample statistics over the first 5 seconds (unit = one executable).
    first5 = data[data["vector"] < 5].groupby(["sample_id", "vector"])[METRICS].mean().reset_index()
    sample_mean = first5.groupby("sample_id")[METRICS].mean().join(samples["malware"])
    stats = sample_mean.groupby("malware")[METRICS].agg(["mean", "median", "std"]).T
    stats.to_csv(OUT / "per_sample_first5s_stats.csv")

    # Figure 4: boxplots of each feature by class (log scale where needed)
    fig, axes = plt.subplots(2, 5, figsize=(17, 7))
    for ax, metric in zip(axes.flat, METRICS):
        groups = [sample_mean.loc[sample_mean.malware == label, metric].to_numpy() for label in (0, 1)]
        box = ax.boxplot(groups, patch_artist=True, showfliers=True, widths=0.6,
                         flierprops={"markersize": 2, "alpha": 0.3})
        for patch, color in zip(box["boxes"], (BENIGN, MALICIOUS)):
            patch.set_facecolor(color)
            patch.set_alpha(0.45)
        ax.set_xticks([1, 2], [LABELS[0], LABELS[1]])
        ax.set_title(metric)
        if metric not in ("cpu_system", "cpu_user", "total_processes"):
            ax.set_yscale("log")
        ax.grid(axis="y", alpha=0.25)
    fig.suptitle("Phân phối giá trị trung bình 5 giây đầu của từng mẫu (thang log với đặc trưng lớn)")
    fig.tight_layout()
    save(fig, "04_feature_boxplots.png")

    # Figure 5: CPU histograms
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    for ax, metric in zip(axes, ("cpu_user", "cpu_system")):
        for label, color in ((0, BENIGN), (1, MALICIOUS)):
            ax.hist(sample_mean.loc[sample_mean.malware == label, metric], bins=40, alpha=0.55, color=color,
                    label=LABELS[label], density=True)
        ax.set_title(f"Phân phối {metric} (TB 5 giây đầu)")
        ax.set_xlabel("%")
        ax.set_ylabel("Mật độ")
        ax.legend(frameon=False)
        ax.grid(alpha=0.25)
    save(fig, "05_cpu_histograms.png")

    # Figure 6: per-second mean curves with 95% CI for all metrics
    fig, axes = plt.subplots(2, 5, figsize=(17, 7))
    for ax, metric in zip(axes.flat, METRICS):
        for label, color in ((0, BENIGN), (1, MALICIOUS)):
            part = first5.merge(samples[["malware"]], left_on="sample_id", right_index=True)
            part = part[part.malware == label].groupby("vector")[metric]
            mean, sem = part.mean(), part.sem()
            ax.plot(mean.index, mean.values, marker="o", color=color, label=LABELS[label])
            ax.fill_between(mean.index, mean - 1.96 * sem, mean + 1.96 * sem, color=color, alpha=0.15)
        ax.set_title(metric)
        ax.set_xticks(range(5))
        ax.set_xlabel("Giây")
        ax.grid(alpha=0.25)
    axes.flat[0].legend(frameon=False)
    fig.suptitle("Giá trị trung bình theo từng giây trong 5 giây đầu (dải mờ: khoảng tin cậy 95%)")
    fig.tight_layout()
    save(fig, "06_per_second_curves.png")

    # Cumulative network counters: share of non-decreasing traces
    monotonic = {}
    for metric in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets"):
        per = data.groupby("sample_id")[metric].apply(lambda s: bool(np.all(np.diff(s.to_numpy()) >= 0)))
        monotonic[metric] = round(float(per.mean() * 100), 2)
    summary["network_counters_non_decreasing_pct"] = monotonic

    # Figure 7: network growth during first 5 seconds (delta from second 0)
    pivot = first5.pivot_table(index="sample_id", columns="vector", values=["rx_bytes", "tx_packets"])
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    for ax, metric in zip(axes, ("rx_bytes", "tx_packets")):
        growth = pivot[metric].sub(pivot[metric][0], axis=0).join(samples["malware"])
        for label, color in ((0, BENIGN), (1, MALICIOUS)):
            median = growth[growth.malware == label].drop(columns="malware").median()
            ax.plot(median.index, median.values, marker="o", color=color, label=LABELS[label])
        ax.set_title(f"Mức tăng {metric} so với giây 0 (trung vị)")
        ax.set_xlabel("Giây")
        ax.set_xticks(range(5))
        ax.legend(frameon=False)
        ax.grid(alpha=0.25)
    save(fig, "07_network_growth.png")

    # Figure 8: correlation heatmap (Spearman) on per-sample means + label
    corr = sample_mean[METRICS + ["malware"]].corr(method="spearman")
    corr.to_csv(OUT / "spearman_correlation.csv")
    fig, ax = plt.subplots(figsize=(8.5, 7))
    image = ax.imshow(corr.to_numpy(), cmap="RdBu_r", vmin=-1, vmax=1)
    ax.set_xticks(range(len(corr)), corr.columns, rotation=45, ha="right")
    ax.set_yticks(range(len(corr)), corr.index)
    for i in range(len(corr)):
        for j in range(len(corr)):
            value = corr.iloc[i, j]
            ax.text(j, i, f"{value:.2f}", ha="center", va="center", fontsize=8,
                    color="white" if abs(value) > 0.6 else "#111827")
    fig.colorbar(image, ax=ax, shrink=0.8, label="Hệ số Spearman")
    ax.set_title("Tương quan Spearman giữa các đặc trưng và nhãn")
    save(fig, "08_correlation.png")
    summary["spearman_with_label"] = corr["malware"].drop("malware").round(3).sort_values().to_dict()

    # Outliers (IQR rule) on raw observations
    outliers = {}
    for metric in METRICS:
        q1, q3 = data[metric].quantile([0.25, 0.75])
        iqr = q3 - q1
        outliers[metric] = round(float(((data[metric] < q1 - 1.5 * iqr) | (data[metric] > q3 + 1.5 * iqr)).mean() * 100), 2)
    summary["outlier_pct_iqr"] = outliers

    # Effect size: standardized mean difference per feature (per-sample means)
    effect = {}
    for metric in METRICS:
        a = sample_mean.loc[sample_mean.malware == 0, metric]
        b = sample_mean.loc[sample_mean.malware == 1, metric]
        pooled = np.sqrt((a.var() + b.var()) / 2)
        effect[metric] = round(float((b.mean() - a.mean()) / pooled), 3) if pooled else 0.0
    summary["cohens_d_malicious_minus_benign"] = effect
    fig, ax = plt.subplots(figsize=(8, 4.2))
    ordered = pd.Series(effect).sort_values()
    ax.barh(ordered.index, ordered.values, color=[MALICIOUS if v > 0 else BENIGN for v in ordered.values])
    ax.axvline(0, color="#334155", linewidth=0.8)
    ax.set_title("Độ chênh chuẩn hóa (Cohen's d): độc hại − lành tính")
    ax.set_xlabel("d > 0: độc hại cao hơn; d < 0: lành tính cao hơn")
    ax.grid(axis="x", alpha=0.25)
    save(fig, "09_effect_size.png")

    (OUT / "eda_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, default=str),
                                          encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
