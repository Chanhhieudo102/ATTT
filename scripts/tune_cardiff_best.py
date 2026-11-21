"""Random-search hyper-parameter tuning for the proposed lightweight models.

Stage 1 tunes LiteSE-BiLSTM-Attn (architecture + optimiser) on the validation set.
Stage 2 tunes the XGBoost head of the hybrid on top of the tuned backbone.
Objective: mean validation accuracy over t = 0..19 s (early detection matters).
The test set is only scored after selection, for the final tuned-vs-default table.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np
import pandas as pd
from sklearn.model_selection import ParameterSampler
from scipy.stats import uniform

from scripts.cardiff_paper_benchmark import (REPORT, load_split, train_deep, hybrid_probs, rows_for,
                                             LITE_DEFAULT, TRAIN_DEFAULT, infer_ms)
from process_guard.cardiff_deep import predict_prefixes, count_params

LITE = "LiteSE-BiLSTM-Attn"
HYB = "Hybrid CNN-SE-BiLSTM + XGBoost"

SPACE = {"filters": [16, 32, 48], "kernel": [3, 5], "reduction": [2, 4, 8], "hidden": [16, 32, 48, 64],
         "heads": [1, 2, 4], "dropout": [0.0, 0.1, 0.2, 0.3, 0.4], "lr": [3e-4, 1e-3, 3e-3],
         "weight_decay": [0.0, 1e-5, 1e-4], "batch": [32, 64, 128], "transform": ["zscore", "log1p"]}
XGB_SPACE = {"n_estimators": [200, 400, 800], "max_depth": [3, 4, 5, 6], "learning_rate": [0.02, 0.05, 0.1],
             "subsample": uniform(0.6, 0.4), "colsample_bytree": uniform(0.5, 0.5), "min_child_weight": [1, 3, 5],
             "reg_lambda": [0.5, 1.0, 2.0, 5.0]}
ARCH = ("filters", "kernel", "reduction", "hidden", "heads", "dropout")


def mean_acc(y, probs):
    return float(np.mean([((p >= 0.5) == y).mean() for p in probs]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", type=Path, default=ROOT / "data/raw/cardiff_data_2.csv")
    ap.add_argument("--trials", type=int, default=30)
    ap.add_argument("--xgb-trials", type=int, default=20)
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44])
    ap.add_argument("--threads", type=int, default=8)
    a = ap.parse_args()
    import torch
    torch.set_num_threads(a.threads)
    data = {t: load_split(a.source, transform=t)[0] for t in ("zscore", "log1p")}
    _, y, train, val, test, _ = load_split(a.source)

    trials = []
    for i, params in enumerate(ParameterSampler(SPACE, n_iter=a.trials, random_state=7)):
        cfg = {k: params[k] for k in ARCH}
        tc = {k: params[k] for k in ("lr", "weight_decay", "batch")}
        t0 = time.perf_counter()
        Xs = data[params["transform"]]
        model, hist = train_deep(LITE, Xs, y, train, val, 42, 150, cfg, tc)
        score = mean_acc(y[val], predict_prefixes(model, Xs[val]))
        trials.append({"trial": i, **params, "params": count_params(model), "epochs_run": hist["epochs_run"],
                       "val_mean_acc": score, "seconds": time.perf_counter() - t0})
        print(f"[lite] trial {i:2d} val_mean_acc={score:.4f} params={count_params(model):,} {params}", flush=True)
    td = pd.DataFrame(trials).sort_values("val_mean_acc", ascending=False)
    td.to_csv(REPORT / "tuning_trials_lite.csv", index=False)
    best = td.iloc[0].to_dict()
    best_cfg = {k: (int(best[k]) if k != "dropout" else float(best[k])) for k in ARCH}
    best_tc = {"lr": float(best["lr"]), "weight_decay": float(best["weight_decay"]), "batch": int(best["batch"])}
    best_tf = str(best["transform"])
    Xs = data[best_tf]

    # Stage 2: XGBoost head on the tuned backbone (seed 42)
    backbone, _ = train_deep(LITE, Xs, y, train, val, 42, 150, best_cfg, best_tc)
    xtrials = []
    for i, params in enumerate(ParameterSampler(XGB_SPACE, n_iter=a.xgb_trials, random_state=11)):
        params = {k: (float(v) if isinstance(v, (float, np.floating)) else v) for k, v in params.items()}
        hp = hybrid_probs(backbone, Xs, y, train, val, test, 42, params)
        score = mean_acc(y[val], hp["val"])
        xtrials.append({"trial": i, **params, "val_mean_acc": score})
        print(f"[xgb] trial {i:2d} val_mean_acc={score:.4f} {params}", flush=True)
    xd = pd.DataFrame(xtrials).sort_values("val_mean_acc", ascending=False)
    xd.to_csv(REPORT / "tuning_trials_hybrid_xgb.csv", index=False)
    best_xgb = {k: v for k, v in xd.iloc[0].to_dict().items() if k not in ("trial", "val_mean_acc")}
    best_xgb = {k: (int(v) if k in ("n_estimators", "max_depth", "min_child_weight") else float(v))
                for k, v in best_xgb.items()}

    rows, cost = [], []
    for seed in a.seeds:
        model, hist = train_deep(LITE, Xs, y, train, val, seed, 150, best_cfg, best_tc)
        ms = infer_ms(model, Xs[test])
        for split_name, idx in (("val", val), ("test", test)):
            rows += rows_for(f"{LITE} (tuned)", seed, split_name, y[idx], predict_prefixes(model, Xs[idx]),
                             {"family": "proposed-tuned", "infer_ms": ms})
        cost.append({"model": f"{LITE} (tuned)", "seed": seed, "params": count_params(model),
                     "epochs_run": hist["epochs_run"], "train_seconds": hist["train_seconds"],
                     "best_val_loss": hist["best_val_loss"], "infer_ms": ms})
        hp = hybrid_probs(model, Xs, y, train, val, test, seed, best_xgb)
        for split_name in ("val", "test"):
            idx = val if split_name == "val" else test
            rows += rows_for(f"{HYB} (tuned)", seed, split_name, y[idx], hp[split_name],
                             {"family": "proposed-tuned", "infer_ms": float("nan")})
        print(f"[final] seed={seed} hybrid(tuned) test acc@5s={rows[-15]['accuracy']:.4f}", flush=True)
    pd.DataFrame(rows).to_csv(REPORT / "tuned_metrics.csv", index=False)
    pd.DataFrame(cost).to_csv(REPORT / "tuned_cost.csv", index=False)
    (REPORT / "tuned_best_config.json").write_text(json.dumps(
        {"lite_arch": best_cfg, "lite_train": best_tc, "input_transform": best_tf, "hybrid_xgb": best_xgb,
         "objective": "mean validation accuracy over t=0..19 s", "lite_trials": a.trials,
         "xgb_trials": a.xgb_trials}, indent=2), encoding="utf-8")

    # tuned vs default summary (test, mean over seeds)
    default = pd.read_csv(REPORT / "deep_metrics.csv")
    allm = pd.concat([default, pd.DataFrame(rows)])
    allm = allm[allm["model"].isin([LITE, HYB, f"{LITE} (tuned)", f"{HYB} (tuned)"])]
    summ = []
    for (model, split_name), g in allm.groupby(["model", "split"]):
        per_t = g.groupby("t_sec")["accuracy"].mean()
        summ.append({"model": model, "split": split_name, "mean_acc_0_19": per_t.mean(),
                     "acc_4s": per_t.loc[4], "acc_5s": per_t.loc[5], "acc_19s": per_t.loc[19],
                     "best_acc": per_t.max(), "best_t": int(per_t.idxmax())})
    pd.DataFrame(summ).to_csv(REPORT / "tuned_vs_default.csv", index=False)
    print(pd.DataFrame(summ).to_string(), flush=True)


if __name__ == "__main__":
    main()
