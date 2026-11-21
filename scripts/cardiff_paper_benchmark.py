"""Paper-style benchmark on Cardiff Dataset 2 (Rhode, Burnap & Jones, 2018).

Protocol
- Test set: the published date-based ``test_set`` flag (never used for fitting or selection).
- Train pool split into train / validation (stratified 85/15, random_state=42).
- z-score fitted on train only; paper second t <-> t+1 snapshots (t = 0..19).
- Groups: ``classical`` (paper's sklearn baselines + XGBoost, refit per time step, 10-fold CV on train),
  ``deep`` (paper GRU A/B/C + max-ensemble, proposed lightweight models + ablations, hybrid CNN-SE+XGBoost).

Outputs go to artifacts/reports/cardiff_paper/.
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
from sklearn.model_selection import StratifiedShuffleSplit, StratifiedKFold, cross_val_predict
from sklearn.preprocessing import StandardScaler

from process_guard.cardiff import make_sequences

REPORT = ROOT / "artifacts/reports/cardiff_paper"
MODELS = ROOT / "artifacts/models/cardiff_paper"
MAX_STEPS = 20


def load_split(source: Path, val_size=0.15, seed=42, transform="zscore"):
    """transform: 'zscore' (paper) or 'log1p' (log1p of non-negative counters, then z-score)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        X, y, is_test, ids, metrics = make_sequences(source, seconds=MAX_STEPS)
    if transform == "log1p":
        X = np.log1p(np.clip(X, 0, None))
    pool = np.flatnonzero(~is_test)
    test = np.flatnonzero(is_test)
    sss = StratifiedShuffleSplit(n_splits=1, test_size=val_size, random_state=seed)
    tr_rel, va_rel = next(sss.split(pool, y[pool]))
    train, val = pool[tr_rel], pool[va_rel]
    scaler = StandardScaler().fit(X[train].reshape(-1, X.shape[2]))
    Xs = scaler.transform(X.reshape(-1, X.shape[2])).reshape(X.shape).astype(np.float32)
    split = {"source": str(source), "n_samples": int(len(y)), "metrics": metrics,
             "train": {"n": int(len(train)), "benign": int((y[train] == 0).sum()), "malicious": int((y[train] == 1).sum())},
             "val": {"n": int(len(val)), "benign": int((y[val] == 0).sum()), "malicious": int((y[val] == 1).sum())},
             "test": {"n": int(len(test)), "benign": int((y[test] == 0).sum()), "malicious": int((y[test] == 1).sum())},
             "overlap_ids": int(len(set(ids[train]) & set(ids[test])) + len(set(ids[val]) & set(ids[test]))
                                + len(set(ids[train]) & set(ids[val]))),
             "val_size": val_size, "split_seed": seed, "transform": transform,
             "scaler_mean": scaler.mean_.tolist(), "scaler_scale": scaler.scale_.tolist()}
    return Xs, y, train, val, test, split


def rows_for(model, seed, split_name, y, probs, extra=None):
    from process_guard.cardiff_deep import binary_metrics
    out = []
    for i, prob in enumerate(probs):
        row = {"model": model, "seed": seed, "split": split_name, "t_sec": i, "steps": i + 1}
        row.update(binary_metrics(y, prob))
        if extra:
            row.update(extra)
        out.append(row)
    return out


# -------------------------------------------------------------- classical
def classical_models(seed=42):
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, AdaBoostClassifier
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.svm import SVC
    from sklearn.naive_bayes import GaussianNB
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.neural_network import MLPClassifier
    from xgboost import XGBClassifier
    return {
        "RandomForest": RandomForestClassifier(n_estimators=200, random_state=seed, n_jobs=1),
        "DecisionTree(J48)": DecisionTreeClassifier(criterion="entropy", random_state=seed),
        "GBDT": GradientBoostingClassifier(random_state=seed),
        "SVM": SVC(kernel="rbf", C=1.0, gamma="scale", random_state=seed),
        "NaiveBayes": GaussianNB(),
        "KNN": KNeighborsClassifier(n_neighbors=5),
        "MLP": MLPClassifier(hidden_layer_sizes=(100,), max_iter=500, random_state=seed),
        "AdaBoost": AdaBoostClassifier(random_state=seed),
        "XGBoost": XGBClassifier(n_estimators=300, max_depth=4, learning_rate=0.05, subsample=0.85,
                                 colsample_bytree=0.85, tree_method="hist", random_state=seed, n_jobs=1,
                                 eval_metric="logloss"),
    }


def _score(model, X):
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]
    return 1.0 / (1.0 + np.exp(-model.decision_function(X)))


def run_classical(Xs, y, train, val, test, jobs):
    from sklearn.base import clone
    from process_guard.cardiff_deep import binary_metrics
    rows, cv_rows = [], []
    cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
    for name, proto in classical_models().items():
        probs = {"val": [], "test": []}
        started = time.perf_counter()
        for L in range(1, MAX_STEPS + 1):
            flat = Xs[:, :L].reshape(len(Xs), -1)
            m = clone(proto).fit(flat[train], y[train])
            probs["val"].append(_score(m, flat[val]))
            probs["test"].append(_score(m, flat[test]))
            pred = cross_val_predict(clone(proto), flat[train], y[train], cv=cv, n_jobs=jobs)
            r = {"model": name, "t_sec": L - 1, "steps": L}
            r.update(binary_metrics(y[train], pred.astype(float)))
            cv_rows.append(r)
        fit_s = time.perf_counter() - started
        flat6 = Xs[:, :6].reshape(len(Xs), -1)
        m6 = clone(proto).fit(flat6[train], y[train])
        t0 = time.perf_counter()
        _score(m6, flat6[test])
        infer = (time.perf_counter() - t0) / len(test) * 1000
        for split_name, idx in (("val", val), ("test", test)):
            rows += rows_for(name, 0, split_name, y[idx], probs[split_name],
                             {"family": "classical", "infer_ms": infer})
        print(f"[classical] {name}: test acc@5s={rows[-14]['accuracy']:.4f} "
              f"acc@19s={rows[-1]['accuracy']:.4f} ({fit_s:.0f}s)", flush=True)
    return rows, cv_rows


# ---------------------------------------------------------------- deep
PAPER_GRU = {  # Table 13: depth, bidirectional, hidden, epochs, dropout, weight reg
    "GRU-A (paper)": dict(layers=3, bidirectional=True, hidden=74, epochs=53, dropout=0.3, reg="l2"),
    "GRU-B (paper)": dict(layers=1, bidirectional=True, hidden=358, epochs=112, dropout=0.1, reg="l2"),
    "GRU-C (paper)": dict(layers=2, bidirectional=False, hidden=195, epochs=39, dropout=0.1, reg="l1"),
}
LITE_DEFAULT = dict(filters=32, kernel=3, reduction=4, hidden=32, heads=2, dropout=0.2)
TRAIN_DEFAULT = dict(lr=1e-3, batch=64, weight_decay=1e-5)


def build_deep(name, cfg=None):
    from process_guard import cardiff_deep as cd
    if name in PAPER_GRU:
        c = PAPER_GRU[name]
        return cd.PaperGRU(10, c["layers"], c["hidden"], c["dropout"], c["bidirectional"])
    cfg = {**LITE_DEFAULT, **(cfg or {})}
    if name.startswith("LiteSE-BiLSTM-Attn"):
        return cd.LiteSEBiLSTMAttn(10, **cfg)
    if name == "BiLSTM-only (ablation)":
        return cd.BiLSTMOnly(10, hidden=cfg["hidden"], dropout=cfg["dropout"])
    if name == "CNN-SE-only (ablation)":
        return cd.CNNSEOnly(10, filters=cfg["filters"], kernel=cfg["kernel"], reduction=cfg["reduction"],
                            dropout=cfg["dropout"])
    raise KeyError(name)


def infer_ms(model, X):
    import torch
    model.eval()
    xt = torch.as_tensor(X[:, :6], dtype=torch.float32)
    with torch.no_grad():
        model(xt)
        t0 = time.perf_counter()
        for _ in range(5):
            model(xt)
    return (time.perf_counter() - t0) / 5 / len(X) * 1000


def train_deep(name, Xs, y, train, val, seed, max_epochs, cfg=None, train_cfg=None):
    import torch
    from process_guard import cardiff_deep as cd
    torch.manual_seed(seed)
    model = build_deep(name, cfg)
    if name in PAPER_GRU:
        c = PAPER_GRU[name]
        epochs = min(c["epochs"], max_epochs)
        model, hist = cd.train_model(model, Xs[train], y[train], Xs[val], y[val], epochs=epochs, lr=1e-3,
                                     batch=64, reg=c["reg"], reg_strength=1e-6, early_stopping=False, seed=seed)
    else:
        tc = {**TRAIN_DEFAULT, **(train_cfg or {})}
        model, hist = cd.train_model(model, Xs[train], y[train], Xs[val], y[val], epochs=max_epochs,
                                     lr=tc["lr"], batch=tc["batch"], weight_decay=tc["weight_decay"],
                                     early_stopping=True, patience=15, seed=seed)
    return model, hist


def hybrid_probs(lite, Xs, y, train, val, test, seed, xgb_params=None):
    from xgboost import XGBClassifier
    from process_guard.cardiff_deep import extract_embeddings, summary_features
    params = dict(n_estimators=400, max_depth=4, learning_rate=0.05, subsample=0.85, colsample_bytree=0.85)
    params.update(xgb_params or {})
    out = {"val": [], "test": []}
    for L in range(1, MAX_STEPS + 1):
        emb = extract_embeddings(lite, Xs, L)
        feats = np.concatenate([emb, summary_features(Xs, L)], axis=1)
        m = XGBClassifier(**params, tree_method="hist", random_state=seed, n_jobs=4,
                          eval_metric="logloss", early_stopping_rounds=20)
        m.fit(feats[train], y[train], eval_set=[(feats[val], y[val])], verbose=False)
        out["val"].append(m.predict_proba(feats[val])[:, 1])
        out["test"].append(m.predict_proba(feats[test])[:, 1])
    return {k: np.stack(v) for k, v in out.items()}


DEEP_ORDER = list(PAPER_GRU) + ["LiteSE-BiLSTM-Attn", "BiLSTM-only (ablation)", "CNN-SE-only (ablation)"]


def run_deep(Xs, y, train, val, test, seeds, max_epochs, only=None):
    import torch
    from process_guard.cardiff_deep import count_params, predict_prefixes
    rows, cost = [], []
    MODELS.mkdir(parents=True, exist_ok=True)
    for seed in seeds:
        store = {}
        for name in DEEP_ORDER:
            if only and name not in only:
                continue
            model, hist = train_deep(name, Xs, y, train, val, seed, max_epochs)
            pv, pt = predict_prefixes(model, Xs[val]), predict_prefixes(model, Xs[test])
            store[name] = (model, pv, pt)
            ms = infer_ms(model, Xs[test])
            extra = {"family": "paper-rnn" if name in PAPER_GRU else "proposed", "infer_ms": ms}
            rows += rows_for(name, seed, "val", y[val], pv, extra)
            rows += rows_for(name, seed, "test", y[test], pt, extra)
            cost.append({"model": name, "seed": seed, "params": count_params(model),
                         "epochs_run": hist["epochs_run"], "train_seconds": hist["train_seconds"],
                         "best_val_loss": hist["best_val_loss"], "infer_ms": ms})
            slug = name.split(" ")[0].replace("/", "_")
            torch.save(model.state_dict(), MODELS / f"{slug}_seed{seed}.pt")
            print(f"[deep] seed={seed} {name}: params={count_params(model):,} epochs={hist['epochs_run']} "
                  f"time={hist['train_seconds']:.0f}s test acc@4s={rows[-16]['accuracy']:.4f} "
                  f"@5s={rows[-15]['accuracy']:.4f} @19s={rows[-1]['accuracy']:.4f}", flush=True)
        gru = [n for n in PAPER_GRU if n in store]
        if len(gru) == 3:
            pv = np.max([store[n][1] for n in gru], axis=0)
            pt = np.max([store[n][2] for n in gru], axis=0)
            extra = {"family": "paper-rnn", "infer_ms": sum(c["infer_ms"] for c in cost[-len(store):]
                                                            if c["model"] in gru)}
            rows += rows_for("GRU Ensemble max(A,B,C) (paper)", seed, "val", y[val], pv, extra)
            rows += rows_for("GRU Ensemble max(A,B,C) (paper)", seed, "test", y[test], pt, extra)
        if "LiteSE-BiLSTM-Attn" in store:
            lite = store["LiteSE-BiLSTM-Attn"][0]
            t0 = time.perf_counter()
            hp = hybrid_probs(lite, Xs, y, train, val, test, seed)
            secs = time.perf_counter() - t0
            extra = {"family": "proposed", "infer_ms": float("nan")}
            rows += rows_for("Hybrid CNN-SE-BiLSTM + XGBoost", seed, "val", y[val], hp["val"], extra)
            rows += rows_for("Hybrid CNN-SE-BiLSTM + XGBoost", seed, "test", y[test], hp["test"], extra)
            cost.append({"model": "Hybrid CNN-SE-BiLSTM + XGBoost", "seed": seed,
                         "params": count_params(lite), "epochs_run": np.nan,
                         "train_seconds": secs, "best_val_loss": np.nan, "infer_ms": np.nan})
            print(f"[deep] seed={seed} Hybrid: test acc@5s={rows[-15]['accuracy']:.4f} "
                  f"@19s={rows[-1]['accuracy']:.4f}", flush=True)
    return rows, cost


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", type=Path, default=ROOT / "data/raw/cardiff_data_2.csv")
    p.add_argument("--group", choices=["all", "classical", "deep"], default="all")
    p.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44])
    p.add_argument("--max-epochs", type=int, default=150)
    p.add_argument("--jobs", type=int, default=8)
    p.add_argument("--threads", type=int, default=8)
    p.add_argument("--only", nargs="*", help="subset of deep model names")
    p.add_argument("--tag", default="", help="suffix for output files (e.g. smoke)")
    a = p.parse_args()
    import torch
    torch.set_num_threads(a.threads)
    REPORT.mkdir(parents=True, exist_ok=True)
    Xs, y, train, val, test, split = load_split(a.source)
    (REPORT / f"split{a.tag}.json").write_text(json.dumps(split, indent=2), encoding="utf-8")
    print(json.dumps({k: split[k] for k in ("train", "val", "test", "overlap_ids")}), flush=True)
    if a.group in ("all", "classical"):
        rows, cv_rows = run_classical(Xs, y, train, val, test, a.jobs)
        pd.DataFrame(rows).to_csv(REPORT / f"classical_metrics{a.tag}.csv", index=False)
        pd.DataFrame(cv_rows).to_csv(REPORT / f"classical_cv10_train{a.tag}.csv", index=False)
    if a.group in ("all", "deep"):
        rows, cost = run_deep(Xs, y, train, val, test, a.seeds, a.max_epochs, a.only)
        pd.DataFrame(rows).to_csv(REPORT / f"deep_metrics{a.tag}.csv", index=False)
        pd.DataFrame(cost).to_csv(REPORT / f"deep_cost{a.tag}.csv", index=False)


if __name__ == "__main__":
    main()
