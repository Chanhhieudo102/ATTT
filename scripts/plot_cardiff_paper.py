"""Summarise the paper-style Cardiff benchmark and draw comparison figures.

Reads artifacts/reports/cardiff_paper/{classical_metrics,deep_metrics,tuned_metrics,classical_cv10_train,*_cost}.csv
and writes summary tables + PNG figures in the same folder. Paper numbers are
copied from Rhode et al. (2018), Tables 5, 6, 7 and 14 (time in seconds).
"""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

REPORT = ROOT / "artifacts/reports/cardiff_paper"

# ---- paper reference values ------------------------------------------------
PAPER_T7 = {  # RNN config A on test, t = 1..20 s
    "acc": [80, 85, 87, 91, 93, 94, 93, 95, 95, 94, 95, 94, 95, 95, 95, 95, 94, 95, 96, 93],
    "fn": [12, 14, 16, 14, 10, 9, 10, 5, 7, 9, 6, 9, 6, 7, 7, 6, 9, 7, 5, 7],
    "fp": [33, 17, 9, 2, 2, 3, 2, 3, 2, 2, 2, 2, 4, 3, 2, 4, 3, 3, 3, 5]}
PAPER_T14 = {  # ensemble on test, t = 1..20 s
    "acc": [79.5, 83.69, 88.48, 91.92, 93.95, 95.28, 95.12, 95.48, 96.02, 95.11, 96.13, 95.46, 95.6, 95.93,
            95.87, 96.54, 96.5, 96.43, 96.26, 94.85],
    "fp": [33.5, 25.73, 15.05, 8.74, 3.4, 4.37, 4.85, 4.88, 4.39, 5.45, 4.95, 5.47, 5.97, 5.03, 4.57, 4.08,
           3.06, 4.12, 4.23, 8.22],
    "fn": [12.03, 10.16, 9.21, 7.64, 7.84, 4.97, 4.9, 4.26, 3.68, 4.48, 3.04, 3.82, 3.15, 3.29, 3.77, 2.94,
           3.86, 3.1, 3.3, 3.31]}
PAPER_T6 = {  # best test accuracy over first 20 s: (acc, time, FP, FN)
    "RandomForest": (92.05, 20, 4.29, 12.29), "MLP": (91.07, 18, 5.53, 12.98), "KNN": (90.38, 18, 4.66, 15.12),
    "SVM": (90.57, 20, 5.13, 14.39), "DecisionTree(J48)": (89.17, 12, 5.22, 17.22),
    "AdaBoost": (87.82, 19, 7.24, 17.72), "NaiveBayes": (76.25, 0, 24.74, 21.13),
    "GBDT": (92.62, 20, 4.33, 11.08), "GRU-A (paper)": (96.01, 19, 3.17, 4.72)}
PAPER_T5 = {  # best 10-fold CV accuracy on train: (acc, time, FP, FN)
    "RandomForest": (95.29, 19, 5.03, 4.5), "MLP": (85.01, 20, 21.3, 9.83), "KNN": (86.3, 20, 17.53, 10.96),
    "SVM": (82.39, 10, 24.5, 10.62), "DecisionTree(J48)": (93.41, 20, 7.87, 5.72),
    "AdaBoost": (83.94, 2, 19.78, 12.03), "NaiveBayes": (77.44, 2, 29.78, 10.7),
    "GBDT": (95.81, 19, 5.44, 3.32), "GRU-A (paper)": (87.75, 20, 10.93, 15.15)}

SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6"]
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"


def disp(name):
    return (name.replace("GRU Ensemble max(A,B,C) (paper)", "Ensemble GRU max(A,B,C) (tái lập)")
            .replace(" (paper)", " (tái lập)").replace("Hybrid CNN-SE-BiLSTM + XGBoost", "Hybrid CNN-SE + XGBoost")
            .replace("(ablation)", "(bóc tách)"))


def load():
    frames = [pd.read_csv(p) for p in (REPORT / "classical_metrics.csv", REPORT / "deep_metrics.csv",
                                       REPORT / "tuned_metrics.csv") if p.exists()]
    return pd.concat(frames, ignore_index=True)


def per_t(df, split="test"):
    """Mean (and std) over seeds for each model and second."""
    g = df[df["split"] == split].groupby(["model", "t_sec"])
    mean = g[["accuracy", "precision", "recall", "f1", "fpr", "fnr", "auc"]].mean()
    std = g["accuracy"].std().fillna(0.0).rename("acc_std")
    return mean.join(std).reset_index()


def style(ax):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(MUTED)
    ax.tick_params(colors=MUTED, labelsize=9)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def main():
    df = load()
    test, val = per_t(df, "test"), per_t(df, "val")
    families = df.drop_duplicates("model").set_index("model")["family"]
    cost = pd.concat([pd.read_csv(p) for p in (REPORT / "deep_cost.csv", REPORT / "tuned_cost.csv") if p.exists()])
    cost_m = cost.groupby("model")[["params", "epochs_run", "train_seconds", "infer_ms"]].mean()
    gru = [m for m in cost_m.index if m.startswith("GRU-")]
    if len(gru) == 3:
        cost_m.loc["GRU Ensemble max(A,B,C) (paper)"] = cost_m.loc[gru].sum()
    infer_cls =df[df["family"] == "classical"].groupby("model")["infer_ms"].first()

    # ---- overall summary (Table 6 analogue + early points) ----------------
    rows = []
    for model, g in test.groupby("model"):
        g = g.set_index("t_sec")
        best_t = int(g["accuracy"].idxmax())
        v = val[val["model"] == model]["accuracy"].mean()
        rows.append({"model": model, "family": families.get(model, ""),
                     "val_mean_acc": v, "test_mean_acc_0_19": g["accuracy"].mean(),
                     "acc_1s": g.loc[1, "accuracy"], "acc_4s": g.loc[4, "accuracy"], "acc_5s": g.loc[5, "accuracy"],
                     "fpr_5s": g.loc[5, "fpr"], "fnr_5s": g.loc[5, "fnr"], "f1_5s": g.loc[5, "f1"],
                     "auc_5s": g.loc[5, "auc"], "acc_19s": g.loc[19, "accuracy"],
                     "best_acc": g.loc[best_t, "accuracy"], "best_t": best_t,
                     "best_fpr": g.loc[best_t, "fpr"], "best_fnr": g.loc[best_t, "fnr"],
                     "acc_std_5s": g.loc[5, "acc_std"],
                     "params": cost_m["params"].get(model, np.nan),
                     "train_seconds": cost_m["train_seconds"].get(model, np.nan),
                     "epochs_run": cost_m["epochs_run"].get(model, np.nan),
                     "infer_ms": cost_m["infer_ms"].get(model, infer_cls.get(model, np.nan))})
    summary = pd.DataFrame(rows).sort_values("test_mean_acc_0_19", ascending=False)
    summary.to_csv(REPORT / "summary_test.csv", index=False)

    # ---- Table 6 vs paper --------------------------------------------------
    t6 = []
    for name, (acc, t, fp, fn) in PAPER_T6.items():
        s = summary[summary["model"] == name]
        ours = s.iloc[0] if len(s) else None
        t6.append({"model": name, "paper_acc": acc, "paper_t": t, "paper_fp": fp, "paper_fn": fn,
                   "our_acc": ours["best_acc"] * 100 if ours is not None else np.nan,
                   "our_t": ours["best_t"] if ours is not None else np.nan,
                   "our_fp": ours["best_fpr"] * 100 if ours is not None else np.nan,
                   "our_fn": ours["best_fnr"] * 100 if ours is not None else np.nan})
    pd.DataFrame(t6).to_csv(REPORT / "table6_vs_paper.csv", index=False)

    # ---- Table 5 (10-fold CV on train) vs paper ---------------------------
    cvp = REPORT / "classical_cv10_train.csv"
    if cvp.exists():
        cv = pd.read_csv(cvp)
        t5 = []
        for name, (acc, t, fp, fn) in PAPER_T5.items():
            g = cv[cv["model"] == name]
            if g.empty:
                t5.append({"model": name, "paper_acc": acc, "paper_t": t, "paper_fp": fp, "paper_fn": fn})
                continue
            b = g.loc[g["accuracy"].idxmax()]
            t5.append({"model": name, "paper_acc": acc, "paper_t": t, "paper_fp": fp, "paper_fn": fn,
                       "our_acc": b["accuracy"] * 100, "our_t": int(b["t_sec"]), "our_fp": b["fpr"] * 100,
                       "our_fn": b["fnr"] * 100})
        pd.DataFrame(t5).to_csv(REPORT / "table5_vs_paper.csv", index=False)

    # ---- per-second table (Table 7 / 14 analogue) --------------------------
    key = ["GRU-A (paper)", "GRU Ensemble max(A,B,C) (paper)", "LiteSE-BiLSTM-Attn (tuned)",
           "Hybrid CNN-SE-BiLSTM + XGBoost (tuned)", "LiteSE-BiLSTM-Attn", "Hybrid CNN-SE-BiLSTM + XGBoost"]
    per = []
    for t in range(20):
        r = {"t_sec": t}
        if t >= 1:
            r.update({"paper_rnnA_acc": PAPER_T7["acc"][t - 1], "paper_ens_acc": PAPER_T14["acc"][t - 1],
                      "paper_ens_fp": PAPER_T14["fp"][t - 1], "paper_ens_fn": PAPER_T14["fn"][t - 1]})
        for m in key:
            g = test[(test["model"] == m) & (test["t_sec"] == t)]
            if len(g):
                r[f"{m}|acc"] = g["accuracy"].iloc[0] * 100
                r[f"{m}|fp"] = g["fpr"].iloc[0] * 100
                r[f"{m}|fn"] = g["fnr"].iloc[0] * 100
        per.append(r)
    pd.DataFrame(per).to_csv(REPORT / "per_second_vs_paper.csv", index=False)

    # ---- figure 1: accuracy vs time (test) --------------------------------
    best_cls = summary[summary["family"] == "classical"].iloc[0]["model"]
    lines = [("GRU Ensemble max(A,B,C) (paper)", "Ensemble GRU (nhóm tái lập)"),
             (best_cls, f"{best_cls} (tốt nhất nhóm cổ điển)"),
             ("LiteSE-BiLSTM-Attn", "LiteSE-BiLSTM-Attn (đề xuất)"),
             ("Hybrid CNN-SE-BiLSTM + XGBoost", "Hybrid CNN-SE + XGBoost (đề xuất)")]
    fig, ax = plt.subplots(figsize=(9, 4.8), dpi=160)
    ts = np.arange(1, 21)
    ax.plot(ts, PAPER_T14["acc"], color=SERIES[6], lw=2, ls="--", label="Bài báo: Ensemble RNN (Table 14)")
    ax.plot(ts, PAPER_T7["acc"], color=MUTED, lw=1.5, ls=":", label="Bài báo: RNN cấu hình A (Table 7)")
    for i, (m, label) in enumerate(lines):
        g = test[test["model"] == m].sort_values("t_sec")
        if g.empty:
            continue
        ax.plot(g["t_sec"], g["accuracy"] * 100, color=SERIES[i], lw=2, marker="o", ms=3.5, label=label)
    ax.set_xlabel("Thời gian thực thi (giây)", color=INK)
    ax.set_ylabel("Accuracy trên tập test (%)", color=INK)
    ax.set_xticks(range(0, 21, 2))
    ax.set_ylim(70, 100)
    ax.set_xlim(-0.5, 20.5)
    style(ax)
    ax.legend(frameon=False, fontsize=8.5, loc="lower right")
    fig.tight_layout()
    fig.savefig(REPORT / "fig_acc_vs_time_vs_paper.png")
    plt.close(fig)

    # ---- figure 2: all models at 5 s, accuracy bars -----------------------
    s5 = summary.sort_values("acc_5s")
    fig, ax = plt.subplots(figsize=(9, 0.32 * len(s5) + 1.2), dpi=160)
    colors = [SERIES[{"classical": 0, "paper-rnn": 6, "proposed": 1, "proposed-tuned": 2}.get(f, 0)]
              for f in s5["family"]]
    ax.barh([disp(m) for m in s5["model"]], s5["acc_5s"] * 100, color=colors, height=0.62)
    for y, v in enumerate(s5["acc_5s"] * 100):
        ax.text(v + 0.3, y, f"{v:.1f}", va="center", fontsize=8, color=INK)
    ax.axvline(93.95, color=SERIES[6], ls="--", lw=1.2)
    ax.text(93.95, len(s5) - 0.4, " bài báo 93,95%", color=MUTED, fontsize=8, va="bottom")
    ax.set_xlim(50, 100)
    ax.set_xlabel("Accuracy test tại 5 s (%)", color=INK)
    style(ax)
    ax.grid(axis="x", color=GRID)
    ax.grid(axis="y", visible=False)
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=SERIES[0], label="Baseline cổ điển"),
                       Patch(color=SERIES[6], label="RNN của bài báo"),
                       Patch(color=SERIES[1], label="Đề xuất (mặc định)"),
                       Patch(color=SERIES[2], label="Đề xuất (tuned)")],
              frameon=False, fontsize=8, loc="lower right")
    fig.tight_layout()
    fig.savefig(REPORT / "fig_acc_5s_all_models.png")
    plt.close(fig)

    # ---- figure 3: params vs accuracy (deep models) ----------------------
    d = summary.dropna(subset=["params"])
    d = d[~d["model"].str.startswith("Hybrid")]
    fig, ax = plt.subplots(figsize=(7.5, 4.2), dpi=160)
    for _, r in d.iterrows():
        c = SERIES[{"paper-rnn": 6, "proposed": 1, "proposed-tuned": 2}.get(r["family"], 0)]
        ax.scatter(r["params"], r["test_mean_acc_0_19"] * 100, s=60, color=c, edgecolor="white", linewidth=2,
                   zorder=3)
        ax.annotate(disp(r["model"]), (r["params"], r["test_mean_acc_0_19"] * 100),
                    textcoords="offset points", xytext=(6, 4), fontsize=7.5, color=INK)
    ax.set_xscale("log")
    ax.set_xlabel("Số tham số (thang log)", color=INK)
    ax.set_ylabel("Accuracy test trung bình 0–19 s (%)", color=INK)
    style(ax)
    fig.tight_layout()
    fig.savefig(REPORT / "fig_params_vs_acc.png")
    plt.close(fig)

    # ---- figure 4: FPR / FNR over time for best proposed vs paper ensemble ----
    best_prop = summary[summary["family"].isin(["proposed", "proposed-tuned"])].iloc[0]["model"]
    g = test[test["model"] == best_prop].sort_values("t_sec")
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.4), dpi=160, sharey=True)
    for ax, key_, title, paper in ((axes[0], "fpr", "Tỉ lệ báo nhầm (FPR)", PAPER_T14["fp"]),
                                   (axes[1], "fnr", "Tỉ lệ bỏ sót (FNR)", PAPER_T14["fn"])):
        ax.plot(ts, paper, color=SERIES[6], ls="--", lw=2, label="Bài báo (ensemble)")
        ax.plot(g["t_sec"], g[key_] * 100, color=SERIES[2], lw=2, marker="o", ms=3, label=disp(best_prop))
        ax.set_title(title, fontsize=10, color=INK)
        ax.set_xlabel("Giây", color=INK)
        style(ax)
    axes[0].set_ylabel("%", color=INK)
    axes[0].legend(frameon=False, fontsize=7.5)
    fig.tight_layout()
    fig.savefig(REPORT / "fig_fpr_fnr_vs_paper.png")
    plt.close(fig)
    print(summary[["model", "val_mean_acc", "test_mean_acc_0_19", "acc_4s", "acc_5s", "acc_19s", "best_acc",
                   "best_t", "params"]].to_string(index=False))


if __name__ == "__main__":
    main()
