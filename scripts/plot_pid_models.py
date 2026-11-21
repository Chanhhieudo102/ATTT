"""Summaries and figures for scripts/pid_model_benchmark.py (artifacts/reports/pid_paper)."""
from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
R = ROOT / "artifacts/reports/pid_paper"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6"]
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"
ORDER = ["Decision Tree", "Random Forest", "Extra Trees", "Extra Trees (tinh chỉnh)", "XGBoost",
         "XGBoost (tinh chỉnh)", "Isolation Forest (không giám sát)", "LiteSE-BiLSTM-Attn",
         "LiteSE-BiLSTM-Attn (tinh chỉnh)", "Hybrid CNN-SE + XGBoost", "Hybrid CNN-SE + XGBoost (tinh chỉnh)"]


def style(ax, grid="y"):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(MUTED)
    ax.tick_params(colors=MUTED, labelsize=8.5)
    ax.grid(axis=grid, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def main():
    t = pd.read_csv(R / "test_metrics.csv")
    num = ["accuracy", "precision", "recall", "f1", "fpr", "auc", "cv_f1", "cv_ap", "params", "train_seconds",
           "infer_ms", "epochs_run"]
    for c in num:
        if c not in t:
            t[c] = np.nan
    g = t.groupby("model")
    summ = g[num].mean()
    summ["recall_std"] = g["recall"].std().fillna(0)
    summ["seeds"] = g.size()
    summ = summ.reindex([m for m in ORDER if m in summ.index])
    summ.to_csv(R / "test_summary.csv")

    # Figure 1: recall / FPR / F1 per model on test
    fig, ax = plt.subplots(figsize=(9, 5.6), dpi=160)
    y = np.arange(len(summ))[::-1]
    h = 0.27
    for i, (col, label) in enumerate((("recall", "Recall"), ("f1", "F1"), ("fpr", "FPR"))):
        ax.barh(y + (1 - i) * h, summ[col], h * 0.9, color=SERIES[[0, 2, 1][i]], label=label)
    ax.set_yticks(y, [m.replace(" (không giám sát)", " (*)") for m in summ.index], fontsize=8)
    ax.set_xlim(0, 1.05)
    ax.set_xlabel("Giá trị trên tập test (ngưỡng 0,65; (*) = không giám sát)", color=INK)
    style(ax, grid="x")
    ax.legend(frameon=False, fontsize=8.5, ncol=3, loc="lower right")
    fig.tight_layout()
    fig.savefig(R / "fig_pid_models_test.png")
    plt.close(fig)

    # Figure 2: early detection (recall by number of snapshots seen)
    e = pd.read_csv(R / "early_detection.csv")
    e = e.groupby(["model", "position"])[["recall", "fpr"]].mean().reset_index()
    e.to_csv(R / "early_detection_summary.csv", index=False)
    pick = [m for m in ("Extra Trees", "XGBoost", "LiteSE-BiLSTM-Attn", "Hybrid CNN-SE + XGBoost",
                        "Hybrid CNN-SE + XGBoost (tinh chỉnh)") if m in set(e.model)]
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8), dpi=160)
    for i, m in enumerate(pick):
        d = e[e.model == m]
        axes[0].plot(d.position, d.recall, marker="o", ms=3.5, lw=2, color=SERIES[i], label=m)
        axes[1].plot(d.position, d.fpr * 100, marker="o", ms=3.5, lw=2, color=SERIES[i], label=m)
    axes[0].set_title("Recall theo số snapshot đã thấy", fontsize=10, color=INK)
    axes[1].set_title("FPR (%) theo số snapshot đã thấy", fontsize=10, color=INK)
    for ax in axes:
        ax.set_xlabel("Snapshot thứ n của tiến trình (cách nhau ~2 giây)", color=INK, fontsize=8.5)
        style(ax)
    axes[0].set_ylim(0, 1.05)
    axes[0].legend(frameon=False, fontsize=7.5)
    fig.tight_layout()
    fig.savefig(R / "fig_pid_early_detection.png")
    plt.close(fig)

    # Figure 3: leave-one-out heatmap
    loo = pd.read_csv(R / "leave_one_out.csv")
    cols = [m for m in ORDER if m in set(loo.model)]
    piv = loo.pivot(index="held_out_executable", columns="model", values="detection_rate")[cols]
    s = loo.groupby("model")[["detection_rate", "benign_false_positive_rate"]].mean().reindex(cols)
    s.to_csv(R / "leave_one_out_summary.csv")
    fig, ax = plt.subplots(figsize=(10, 3.9), dpi=160)
    im = ax.imshow(piv.to_numpy(), cmap="Blues", vmin=0, vmax=1, aspect="auto")
    short = {"Extra Trees": "ET", "Extra Trees (tinh chỉnh)": "ET\ntinh chỉnh", "XGBoost": "XGBoost",
             "LiteSE-BiLSTM-Attn": "LiteSE", "LiteSE-BiLSTM-Attn (tinh chỉnh)": "LiteSE\ntinh chỉnh",
             "Hybrid CNN-SE + XGBoost": "Hybrid", "Hybrid CNN-SE + XGBoost (tinh chỉnh)": "Hybrid\ntinh chỉnh"}
    ax.set_xticks(range(len(cols)), [short.get(c, c) for c in cols], fontsize=8.5)
    ax.set_yticks(range(len(piv.index)), piv.index, fontsize=8.5)
    for i in range(piv.shape[0]):
        for j in range(piv.shape[1]):
            v = piv.iloc[i, j]
            ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=8.5,
                    color="white" if v > 0.6 else INK)
    fig.colorbar(im, ax=ax, label="Tỉ lệ snapshot bị cảnh báo")
    fig.tight_layout()
    fig.savefig(R / "fig_pid_leave_one_out.png")
    plt.close(fig)
    print(summ[["recall", "precision", "f1", "fpr", "auc", "cv_f1", "cv_ap", "params"]].round(4).to_string())
    print(s.round(3).to_string())


if __name__ == "__main__":
    main()
