"""Re-run and extend the PID (self-collected, per-process) experiments without re-collecting data.

Same data and the same grouped train/validation/test split as artifacts/reports/pid_live
(no executable crosses partitions). Adds XGBoost, the lightweight sequence model
LiteSE-BiLSTM-Attn and the Hybrid CNN-SE + XGBoost (proposed on Cardiff), random-search
tuning by grouped CV F1, leave-one-simulated-executable-out and scoring of the new-instance
evaluation sessions. Threshold 0.65 everywhere, exactly as in the live system.

Stages: --stage base | tune | all   (tune reads/writes tuned_config.json)
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
import warnings

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np
import pandas as pd
from scipy.stats import uniform
from sklearn.base import clone
from sklearn.ensemble import ExtraTreesClassifier, IsolationForest, RandomForestClassifier
from sklearn.model_selection import ParameterSampler, StratifiedGroupKFold
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

from process_guard.features import PID_MODEL_FEATURES
from process_guard.ml import ALERT_THRESHOLD, model_scores
from process_guard.pid_data import load_observations
from process_guard.pid_sequence import order_snapshots, build_windows, fit_scaler
from process_guard import cardiff_deep as cd

REPORT = ROOT / "artifacts/reports/pid_paper"
K = 8
LITE_DEFAULT = dict(filters=32, kernel=3, reduction=4, hidden=32, heads=2, dropout=0.2)
TRAIN_DEFAULT = dict(lr=1e-3, batch=128, weight_decay=1e-5)
XGB_FLAT = dict(n_estimators=300, max_depth=4, learning_rate=0.05, subsample=0.85, colsample_bytree=0.85)
XGB_HEAD = dict(n_estimators=400, max_depth=4, learning_rate=0.05, subsample=0.85, colsample_bytree=0.85)
ET_DEFAULT = dict(n_estimators=250, min_samples_leaf=2, class_weight="balanced", max_features="sqrt")
THR = ALERT_THRESHOLD


# ------------------------------------------------------------------ data
def load_data():
    summary = json.loads((ROOT / "artifacts/reports/pid_live/dataset_summary.json").read_text(encoding="utf-8"))
    sources = [s["path"] for s in summary["source_files"]]
    data, _ = load_observations(sources)
    manifest = pd.read_csv(ROOT / "artifacts/reports/pid_live/split_manifest.csv",
                           usecols=["source_file", "source_row", "partition"])
    data = data.merge(manifest, on=["source_file", "source_row"], how="left", validate="one_to_one")
    if data["partition"].isna().any():
        raise ValueError("Some rows are missing from split_manifest.csv")
    return order_snapshots(data).reset_index(drop=True), sources


def load_eval_sessions():
    # Same sources as the reported integration evaluation (artifacts/reports/pid_eval_final).
    meta = json.loads((ROOT / "artifacts/reports/pid_eval_final/evaluation.json").read_text(encoding="utf-8"))
    files = [Path(s["path"]) for s in meta["sources"]]
    data, _ = load_observations(files)
    return order_snapshots(data).reset_index(drop=True), [str(f) for f in files]


# ------------------------------------------------------------------ models
def flat_models(et=None, xgb=None, spw=9.0):
    return {
        "Decision Tree": DecisionTreeClassifier(max_depth=9, class_weight="balanced", random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=250, min_samples_leaf=2, class_weight="balanced",
                                                n_jobs=-1, random_state=42),
        "Extra Trees": ExtraTreesClassifier(**(et or ET_DEFAULT), n_jobs=-1, random_state=42),
        "XGBoost": XGBClassifier(**(xgb or XGB_FLAT), tree_method="hist", scale_pos_weight=spw, n_jobs=8,
                                 random_state=42, eval_metric="logloss"),
    }


def train_lite(W, y, tr, va, seed, cfg=None, tc=None, epochs=100, early=True):
    import torch
    torch.manual_seed(seed)
    cfg, tc = {**LITE_DEFAULT, **(cfg or {})}, {**TRAIN_DEFAULT, **(tc or {})}
    model = cd.LiteSEBiLSTMAttn(W.shape[2], **cfg)
    pos = max(1, int(y[tr].sum()))
    pw = (len(tr) - pos) / pos
    va = va if va is not None else tr[:256]
    return cd.train_model(model, W[tr], y[tr], W[va], y[va], epochs=epochs, lr=tc["lr"], batch=tc["batch"],
                          weight_decay=tc["weight_decay"], early_stopping=early, patience=10, seed=seed,
                          pos_weight=pw, val_prefixes=(W.shape[1],), random_prefix=False)


def lite_scores(model, W):
    return cd.predict_prefixes(model, W, lengths=[W.shape[1]])[0]


def hybrid_features(model, W):
    return np.concatenate([cd.extract_embeddings(model, W, W.shape[1]), cd.summary_features(W, W.shape[1])], 1)


def fit_head(F, y, tr, va, seed, params=None):
    pos = max(1, int(y[tr].sum()))
    m = XGBClassifier(**{**XGB_HEAD, **(params or {})}, tree_method="hist", scale_pos_weight=(len(tr) - pos) / pos,
                      n_jobs=8, random_state=seed, eval_metric="logloss",
                      early_stopping_rounds=20 if va is not None else None)
    if va is not None:
        m.fit(F[tr], y[tr], eval_set=[(F[va], y[va])], verbose=False)
    else:
        m.fit(F[tr], y[tr], verbose=False)
    return m


# ------------------------------------------------------------------ metrics
def metrics(y, score):
    r = cd.binary_metrics(y, score, THR)
    return {k: (float(v) if not isinstance(v, int) else v) for k, v in r.items()}


def by_position(y, score, position, upto=K):
    rows = []
    for p in range(1, upto + 1):
        sel = position == p
        mal, ben = sel & (y == 1), sel & (y == 0)
        rows.append({"position": p, "recall": float((score[mal] >= THR).mean()) if mal.any() else np.nan,
                     "fpr": float((score[ben] >= THR).mean()) if ben.any() else np.nan,
                     "n_mal": int(mal.sum()), "n_ben": int(ben.sum())})
    return rows


def instance_metrics(frame, score):
    f = frame.assign(alert=score >= THR)
    inst = f.groupby(["source_file", "group", "process_pid", "process_create_time"]).agg(
        label=("label", "first"), alert=("alert", "any"))
    tp = int(((inst.label == 1) & inst.alert).sum()); fn = int(((inst.label == 1) & ~inst.alert).sum())
    fp = int(((inst.label == 0) & inst.alert).sum()); tn = int(((inst.label == 0) & ~inst.alert).sum())
    return {"instances": len(inst), "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "recall": tp / max(tp + fn, 1), "fpr": fp / max(fp + tn, 1)}


# ------------------------------------------------------------------ grouped CV
def cv_folds(y, groups):
    n = int(min(5, pd.Series(groups[y == 1]).nunique(), pd.Series(groups[y == 0]).nunique()))
    out = []
    for fit, held in StratifiedGroupKFold(n_splits=n, shuffle=True, random_state=42).split(
            np.zeros(len(y)), y, groups):
        if set(y[held]) == {0, 1} and set(y[fit]) == {0, 1}:
            out.append((fit, held))
    return out


def cv_f1_flat(model, X, y, folds):
    """Grouped CV -> (mean F1 at the live threshold, mean average precision)."""
    from sklearn.metrics import f1_score, average_precision_score
    f, a = [], []
    for fit, held in folds:
        m = clone(model).fit(X[fit], y[fit])
        sc = model_scores(m, X[held])
        f.append(f1_score(y[held], (sc >= THR).astype(int), zero_division=0))
        a.append(average_precision_score(y[held], sc))
    return float(np.mean(f)), float(np.mean(a))


def cv_f1_seq(data, y, dev, folds, cfg, tc, epochs, head_params=None, hybrid=True, cache=None):
    """Fold-wise: refit scaler + backbone (fixed epochs) on the fold, score held-out executables.

    ``cache`` (dict) keeps the per-fold backbone outputs so that tuning the XGBoost head does not
    retrain the same backbone again.
    """
    from sklearn.metrics import f1_score, average_precision_score
    s_lite, s_hyb, a_lite, a_hyb = [], [], [], []
    for k_fold, (fit, held) in enumerate(folds):
        fit_i, held_i = dev[fit], dev[held]
        if cache is not None and k_fold in cache:
            sc, F = cache[k_fold]
        else:
            mean, std = fit_scaler(data.iloc[fit_i])
            W = build_windows(data, K, mean, std)
            model, _ = train_lite(W, y, fit_i, None, 42, cfg, tc, epochs=epochs, early=False)
            sc = lite_scores(model, W[held_i])
            F = hybrid_features(model, W) if hybrid else None
            if cache is not None:
                cache[k_fold] = (sc, F)
        s_lite.append(f1_score(y[held_i], (sc >= THR).astype(int), zero_division=0))
        a_lite.append(average_precision_score(y[held_i], sc))
        if hybrid:
            head = fit_head(F, y, fit_i, None, 42, head_params)
            sc = head.predict_proba(F[held_i])[:, 1]
            s_hyb.append(f1_score(y[held_i], (sc >= THR).astype(int), zero_division=0))
            a_hyb.append(average_precision_score(y[held_i], sc))
    m = lambda v: float(np.mean(v)) if v else np.nan
    return {"lite_f1": m(s_lite), "lite_ap": m(a_lite), "hyb_f1": m(s_hyb), "hyb_ap": m(a_hyb)}


# ------------------------------------------------------------------ stages
def base(data, cfgs, seeds, tag=""):
    X = data[PID_MODEL_FEATURES].to_numpy(float)
    y = data["label"].to_numpy()
    groups = data["group"].to_numpy()
    part = data["partition"].to_numpy()
    tr, va, te = (np.flatnonzero(part == p) for p in ("train", "validation", "test"))
    dev = np.concatenate([tr, va])
    pos_dev = y[dev].sum()
    spw = (len(dev) - pos_dev) / pos_dev
    folds = cv_folds(y[dev], groups[dev])
    position = data["position"].to_numpy()
    rows, early, cost = [], [], []

    def record(name, score, cv, seed=0, extra=None):
        cvf1, cvap = cv if isinstance(cv, tuple) else (cv, np.nan)
        r = {"model": name, "seed": seed, **metrics(y[te], score[te] if len(score) == len(y) else score),
             "cv_f1": cvf1, "cv_ap": cvap, **(extra or {})}
        rows.append(r)
        sc = score[te] if len(score) == len(y) else score
        for e in by_position(y[te], sc, position[te]):
            early.append({"model": name, "seed": seed, **e})

    # flat models: fit on train+validation (as the live pipeline)
    for name, model in flat_models(cfgs.get("et"), cfgs.get("xgb"), spw).items():
        label = name + (" (tinh chỉnh)" if (name == "Extra Trees" and cfgs.get("et")) or
                        (name == "XGBoost" and cfgs.get("xgb")) else "")
        cvf1 = cv_f1_flat(model, X[dev], y[dev], folds)
        t0 = time.perf_counter()
        model.fit(X[dev], y[dev])
        fit_s = time.perf_counter() - t0
        t0 = time.perf_counter()
        score = model_scores(model, X[te])
        inf = (time.perf_counter() - t0) / len(te) * 1000
        full = np.zeros(len(y)); full[te] = score
        record(label + tag, full, cvf1, extra={"family": "flat", "train_seconds": fit_s, "infer_ms": inf})
        cost.append({"model": label + tag, "train_seconds": fit_s, "infer_ms": inf, "params": np.nan})
        print(f"[flat] {label}: cv={cvf1} {rows[-1]['recall']:.3f}/{rows[-1]['fpr']:.4f}", flush=True)
    # unsupervised
    iso = IsolationForest(n_estimators=250, contamination="auto", random_state=42).fit(X[dev][y[dev] == 0])
    full = np.zeros(len(y)); full[te] = model_scores(iso, X[te], True)
    record("Isolation Forest (không giám sát)", full, np.nan, extra={"family": "unsupervised"})

    # sequence models: train on train, early stopping on validation; 3 seeds
    mean, std = fit_scaler(data.iloc[tr])
    W = build_windows(data, K, mean, std)
    lite_cfg, tc, head = cfgs.get("lite"), cfgs.get("tc"), cfgs.get("head")
    suffix = " (tinh chỉnh)" if lite_cfg else ""
    epochs_seen = []
    for seed in seeds:
        model, hist = train_lite(W, y, tr, va, seed, lite_cfg, tc)
        epochs_seen.append(hist["epochs_run"])
        full = np.zeros(len(y)); full[te] = lite_scores(model, W[te])
        t0 = time.perf_counter(); lite_scores(model, W[te]); inf = (time.perf_counter() - t0) / len(te) * 1000
        record("LiteSE-BiLSTM-Attn" + suffix + tag, full, np.nan, seed,
               {"family": "proposed", "params": cd.count_params(model), "epochs_run": hist["epochs_run"],
                "train_seconds": hist["train_seconds"], "infer_ms": inf})
        t0 = time.perf_counter()
        F = hybrid_features(model, W)
        hm = fit_head(F, y, tr, va, seed, head)
        head_s = time.perf_counter() - t0
        full = np.zeros(len(y)); full[te] = hm.predict_proba(F[te])[:, 1]
        record("Hybrid CNN-SE + XGBoost" + suffix + tag, full, np.nan, seed,
               {"family": "proposed", "params": cd.count_params(model),
                "train_seconds": hist["train_seconds"] + head_s, "infer_ms": inf})
        print(f"[seq] seed={seed} lite {rows[-2]['recall']:.3f}/{rows[-2]['fpr']:.4f} "
              f"hybrid {rows[-1]['recall']:.3f}/{rows[-1]['fpr']:.4f} epochs={hist['epochs_run']}", flush=True)
    # Grouped CV uses a fixed epoch budget (no validation inside folds): the tuned budget when tuning
    # chose one, otherwise the median epoch count reached by early stopping above.
    ep = int(np.median(epochs_seen))
    cvs = cv_f1_seq(data, y, dev, folds, lite_cfg, tc, cfgs.get("lite_epochs") or ep, head)
    for r in rows:
        if r["model"] == "LiteSE-BiLSTM-Attn" + suffix + tag:
            r["cv_f1"], r["cv_ap"] = cvs["lite_f1"], cvs["lite_ap"]
        if r["model"] == "Hybrid CNN-SE + XGBoost" + suffix + tag:
            r["cv_f1"], r["cv_ap"] = cvs["hyb_f1"], cvs["hyb_ap"]
    print(f"[seq] grouped CV {cvs} (fixed {ep} epochs)", flush=True)
    return rows, early, ep


def loo(data, cfgs, epochs):
    """Leave one simulated executable (and a disjoint benign fold) out, as scripts/pid_leave_one_out.py."""
    X = data[PID_MODEL_FEATURES].to_numpy(float)
    y = data["label"].to_numpy()
    groups = data["group"].to_numpy()
    mal = sorted(set(groups[y == 1]))
    ben = np.array(sorted(set(groups[y == 0])))
    folds = np.array_split(np.random.default_rng(42).permutation(ben), len(mal))
    rows = []
    for held_mal, held_ben in zip(mal, folds):
        held = np.isin(groups, [held_mal, *held_ben]); fit = np.flatnonzero(~held); hi = np.flatnonzero(held)
        pos = y[fit].sum(); spw = (len(fit) - pos) / pos
        scores = {}
        for name, model in flat_models(None, None, spw).items():
            if name in ("Extra Trees", "XGBoost"):
                scores[name] = model_scores(model.fit(X[fit], y[fit]), X[hi])
        if cfgs.get("et"):
            m = flat_models(cfgs["et"], None, spw)["Extra Trees"].fit(X[fit], y[fit])
            scores["Extra Trees (tinh chỉnh)"] = model_scores(m, X[hi])
        mean, std = fit_scaler(data.iloc[fit])
        W = build_windows(data, K, mean, std)
        for suffix, cfg, tc, head, ep in (("", None, None, None, epochs["default"]),
                                          (" (tinh chỉnh)", cfgs.get("lite"), cfgs.get("tc"), cfgs.get("head"),
                                           epochs.get("tuned"))):
            if suffix and not cfgs.get("lite"):
                continue
            model, _ = train_lite(W, y, fit, None, 42, cfg, tc, epochs=ep, early=False)
            scores["LiteSE-BiLSTM-Attn" + suffix] = lite_scores(model, W[hi])
            F = hybrid_features(model, W)
            scores["Hybrid CNN-SE + XGBoost" + suffix] = fit_head(F, y, fit, None, 42, head).predict_proba(F[hi])[:, 1]
        hy = y[hi]
        name_exe = Path(held_mal.replace("\\", "/")).name
        for name, sc in scores.items():
            alert = sc >= THR
            rows.append({"held_out_executable": name_exe, "model": name,
                         "detection_rate": float(alert[hy == 1].mean()),
                         "benign_false_positive_rate": float(alert[hy == 0].mean())})
        print(f"[loo] {name_exe}: " + ", ".join(f"{r['model']}={r['detection_rate']:.2f}"
                                                 for r in rows[-len(scores):]), flush=True)
    return rows


def eval_sessions(data, cfgs, epochs):
    """Score the new-instance evaluation sessions with models trained on the full training data."""
    ev, files = load_eval_sessions()
    X = data[PID_MODEL_FEATURES].to_numpy(float); y = data["label"].to_numpy()
    part = data["partition"].to_numpy()
    tr, va = np.flatnonzero(part == "train"), np.flatnonzero(part == "validation")
    dev = np.concatenate([tr, va])
    Xe, ye = ev[PID_MODEL_FEATURES].to_numpy(float), ev["label"].to_numpy()
    pos = y[dev].sum(); spw = (len(dev) - pos) / pos
    out = []

    def add(name, score):
        out.append({"model": name, "unit": "snapshot", **metrics(ye, score)})
        out.append({"model": name, "unit": "instance", **instance_metrics(ev, score)})

    for name, model in flat_models(None, None, spw).items():
        if name in ("Extra Trees", "XGBoost"):
            add(name, model_scores(model.fit(X[dev], y[dev]), Xe))
    if cfgs.get("et"):
        add("Extra Trees (tinh chỉnh)", model_scores(flat_models(cfgs["et"], None, spw)["Extra Trees"]
                                                     .fit(X[dev], y[dev]), Xe))
    mean, std = fit_scaler(data.iloc[tr])
    W = build_windows(data, K, mean, std)
    We = build_windows(ev, K, mean, std)
    for suffix, cfg, tc, head in (("", None, None, None),
                                  (" (tinh chỉnh)", cfgs.get("lite"), cfgs.get("tc"), cfgs.get("head"))):
        if suffix and not cfgs.get("lite"):
            continue
        model, _ = train_lite(W, y, tr, va, 42, cfg, tc)
        add("LiteSE-BiLSTM-Attn" + suffix, lite_scores(model, We))
        F, Fe = hybrid_features(model, W), hybrid_features(model, We)
        add("Hybrid CNN-SE + XGBoost" + suffix, fit_head(F, y, tr, va, 42, head).predict_proba(Fe)[:, 1])
    print(pd.DataFrame(out)[["model", "unit", "recall", "fpr"]].to_string(), flush=True)
    return out, files


def tune(data, n_et=25, n_xgb=15, n_lite=8, n_head=15):
    X = data[PID_MODEL_FEATURES].to_numpy(float)
    y = data["label"].to_numpy(); groups = data["group"].to_numpy(); part = data["partition"].to_numpy()
    tr, va = np.flatnonzero(part == "train"), np.flatnonzero(part == "validation")
    dev = np.concatenate([tr, va]); folds = cv_folds(y[dev], groups[dev])
    pos = y[dev].sum(); spw = (len(dev) - pos) / pos
    trials = []
    et_space = {"n_estimators": [150, 250, 400, 600], "max_features": ["sqrt", "log2", 0.3, 0.5, 0.8],
                "min_samples_leaf": [1, 2, 4, 8], "class_weight": ["balanced", "balanced_subsample", None]}
    for i, p in enumerate(ParameterSampler(et_space, n_iter=n_et, random_state=1)):
        f1, ap = cv_f1_flat(ExtraTreesClassifier(**p, n_jobs=-1, random_state=42), X[dev], y[dev], folds)
        trials.append({"search": "Extra Trees", "trial": i, "cv_f1": f1, "cv_ap": ap, **{k: str(v) for k, v in p.items()}})
        print(f"[tune-et] {i} f1={f1:.3f} ap={ap:.3f} {p}", flush=True)
    xgb_space = {"n_estimators": [150, 300, 600], "max_depth": [2, 3, 4, 6], "learning_rate": [0.03, 0.05, 0.1],
                 "subsample": uniform(0.6, 0.4), "colsample_bytree": uniform(0.4, 0.6), "min_child_weight": [1, 5, 10]}
    for i, p in enumerate(ParameterSampler(xgb_space, n_iter=n_xgb, random_state=2)):
        p = {k: (float(v) if isinstance(v, (float, np.floating)) else v) for k, v in p.items()}
        m = XGBClassifier(**p, tree_method="hist", scale_pos_weight=spw, n_jobs=8, random_state=42,
                          eval_metric="logloss")
        f1, ap = cv_f1_flat(m, X[dev], y[dev], folds)
        trials.append({"search": "XGBoost", "trial": i, "cv_f1": f1, "cv_ap": ap, **{k: str(v) for k, v in p.items()}})
        print(f"[tune-xgb] {i} f1={f1:.3f} ap={ap:.3f}", flush=True)
    lite_space = {"filters": [16, 32, 48], "kernel": [3, 5], "reduction": [2, 4], "hidden": [16, 32, 48],
                  "heads": [1, 2], "dropout": [0.1, 0.2, 0.3], "lr": [3e-4, 1e-3, 3e-3], "batch": [64, 128, 256],
                  "weight_decay": [0.0, 1e-5, 1e-4], "epochs": [8, 12, 20]}
    best_lite = None
    for i, p in enumerate(ParameterSampler(lite_space, n_iter=n_lite, random_state=3)):
        cfg = {k: p[k] for k in ("filters", "kernel", "reduction", "hidden", "heads", "dropout")}
        tc = {k: p[k] for k in ("lr", "batch", "weight_decay")}
        cvs = cv_f1_seq(data, y, dev, folds, cfg, tc, p["epochs"])
        trials.append({"search": "LiteSE backbone", "trial": i, "cv_f1": cvs["lite_f1"], "cv_ap": cvs["lite_ap"],
                       "hybrid_cv_f1": cvs["hyb_f1"], "hybrid_cv_ap": cvs["hyb_ap"],
                       **{k: str(v) for k, v in p.items()}})
        print(f"[tune-lite] {i} {cvs} {p}", flush=True)
        score = np.nanmax([cvs["lite_ap"], cvs["hyb_ap"]])
        if best_lite is None or score > best_lite[0]:
            best_lite = (score, cfg, tc, p["epochs"])
    head_space = {"n_estimators": [200, 400, 800], "max_depth": [3, 4, 6], "learning_rate": [0.03, 0.05, 0.1],
                  "subsample": uniform(0.6, 0.4), "colsample_bytree": uniform(0.4, 0.6), "min_child_weight": [1, 5, 10]}
    best_head = None
    cache = {}
    for i, p in enumerate(ParameterSampler(head_space, n_iter=n_head, random_state=4)):
        p = {k: (float(v) if isinstance(v, (float, np.floating)) else v) for k, v in p.items()}
        cvs = cv_f1_seq(data, y, dev, folds, best_lite[1], best_lite[2], best_lite[3], p, cache=cache)
        trials.append({"search": "Hybrid head", "trial": i, "cv_f1": cvs["hyb_f1"], "cv_ap": cvs["hyb_ap"],
                       **{k: str(v) for k, v in p.items()}})
        print(f"[tune-head] {i} f1={cvs['hyb_f1']:.3f} ap={cvs['hyb_ap']:.3f}", flush=True)
        if best_head is None or cvs["hyb_ap"] > best_head[0]:
            best_head = (cvs["hyb_ap"], p)
    t = pd.DataFrame(trials)
    t.to_csv(REPORT / "tuning_trials.csv", index=False)

    def best_params(search):
        g = t[t.search == search].sort_values(["cv_ap", "cv_f1"], ascending=False).iloc[0]
        return g

    et_row = best_params("Extra Trees")
    et = {"n_estimators": int(et_row.n_estimators), "min_samples_leaf": int(et_row.min_samples_leaf),
          "max_features": (et_row.max_features if et_row.max_features in ("sqrt", "log2")
                           else float(et_row.max_features)),
          "class_weight": None if et_row.class_weight == "None" else et_row.class_weight}
    xr = best_params("XGBoost")
    xgb = {"n_estimators": int(xr.n_estimators), "max_depth": int(xr.max_depth),
           "learning_rate": float(xr.learning_rate), "subsample": float(xr.subsample),
           "colsample_bytree": float(xr.colsample_bytree), "min_child_weight": int(xr.min_child_weight)}
    cfg = {"et": et, "xgb": xgb, "lite": best_lite[1], "tc": best_lite[2], "lite_epochs": best_lite[3],
           "head": {k: (int(v) if k in ("n_estimators", "max_depth", "min_child_weight") else float(v))
                    for k, v in best_head[1].items()},
           "objective": "grouped CV average precision (StratifiedGroupKFold by executable on train+validation); "
                        "F1 at threshold 0.65 reported alongside"}
    (REPORT / "tuned_config.json").write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    return cfg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=["base", "tune", "extra", "all"], default="all",
                    help="base: re-run models; tune: random search + tuned models; extra: leave-one-out + eval session")
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44])
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--quick", action="store_true", help="smoke test: few trials")
    a = ap.parse_args()
    import torch
    torch.set_num_threads(a.threads)
    warnings.filterwarnings("ignore")
    REPORT.mkdir(parents=True, exist_ok=True)
    data, sources = load_data()
    split = data.groupby(["partition", "label"]).agg(rows=("label", "size"), executables=("group", "nunique"))
    split.reset_index().to_csv(REPORT / "split_summary.csv", index=False)
    print(split, flush=True)
    seeds = a.seeds if not a.quick else [42]
    if a.stage in ("base", "all"):
        r, e, ep = base(data, {}, seeds)
        pd.DataFrame(r).to_csv(REPORT / "test_metrics_base.csv", index=False)
        pd.DataFrame(e).to_csv(REPORT / "early_detection_base.csv", index=False)
        (REPORT / "default_epochs.json").write_text(json.dumps({"epochs": ep}), encoding="utf-8")
    ep = json.loads((REPORT / "default_epochs.json").read_text())["epochs"]
    cfgs = {}
    if a.stage in ("tune", "all"):
        cfgs = tune(data, *((3, 2, 1, 2) if a.quick else (25, 15, 6, 15)))
        r, e, _ = base(data, cfgs, seeds)
        pd.DataFrame([x for x in r if "tinh chỉnh" in x["model"]]).to_csv(REPORT / "test_metrics_tuned.csv", index=False)
        pd.DataFrame([x for x in e if "tinh chỉnh" in x["model"]]).to_csv(REPORT / "early_detection_tuned.csv",
                                                                            index=False)
    elif (REPORT / "tuned_config.json").exists():
        cfgs = json.loads((REPORT / "tuned_config.json").read_text(encoding="utf-8"))
    frames = [pd.read_csv(REPORT / f) for f in ("test_metrics_base.csv", "test_metrics_tuned.csv")
              if (REPORT / f).exists()]
    if frames:
        pd.concat(frames).to_csv(REPORT / "test_metrics.csv", index=False)
    frames = [pd.read_csv(REPORT / f) for f in ("early_detection_base.csv", "early_detection_tuned.csv")
              if (REPORT / f).exists()]
    if frames:
        pd.concat(frames).to_csv(REPORT / "early_detection.csv", index=False)
    if a.stage in ("extra", "all"):
        epochs = {"default": ep, "tuned": cfgs.get("lite_epochs")}
        pd.DataFrame(loo(data, cfgs, epochs)).to_csv(REPORT / "leave_one_out.csv", index=False)
        ev, files = eval_sessions(data, cfgs, epochs)
        pd.DataFrame(ev).to_csv(REPORT / "eval_sessions.csv", index=False)
        (REPORT / "eval_sources.json").write_text(json.dumps(files, indent=2), encoding="utf-8")
    print("done", flush=True)


if __name__ == "__main__":
    main()
