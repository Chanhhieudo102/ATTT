"""Leave-one-simulated-executable-out evaluation for PID models.

For every simulated (label 1) executable, the models are trained WITHOUT any snapshot of that
executable (and without one held-out group of benign executables) and then asked to detect it.
This estimates how well each model detects a behaviour it has never seen, which a single
train/validation/test split with few malicious executables cannot show.

Usage: python scripts/pid_leave_one_out.py --source a.csv b.csv ... [--output DIR]
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
from sklearn.ensemble import ExtraTreesClassifier, IsolationForest, RandomForestClassifier
from sklearn.model_selection import GroupKFold
from sklearn.tree import DecisionTreeClassifier

from process_guard.features import PID_MODEL_FEATURES
from process_guard.ml import ALERT_THRESHOLD, model_scores
from process_guard.pid_data import load_observations


def models():
    return {
        "Decision Tree": (DecisionTreeClassifier(max_depth=9, class_weight="balanced", random_state=42), False),
        "Random Forest": (RandomForestClassifier(n_estimators=250, min_samples_leaf=2, class_weight="balanced",
                                                 n_jobs=-1, random_state=42), False),
        "Extra Trees": (ExtraTreesClassifier(n_estimators=250, min_samples_leaf=2, class_weight="balanced",
                                             n_jobs=-1, random_state=42), False),
        "Isolation Forest": (IsolationForest(n_estimators=250, contamination="auto", random_state=42), True),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", type=Path, nargs="+", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/reports/pid_leave_one_out")
    args = parser.parse_args()
    data, _ = load_observations(args.source)
    X = data[PID_MODEL_FEATURES].astype(float)
    y = data["label"].to_numpy()
    names = data["process_path"].map(lambda value: Path(value.replace("\\", "/")).name.lower()).to_numpy()
    groups = data["group"].to_numpy()
    malicious_groups = sorted(set(groups[y == 1]))
    benign_groups = np.array(sorted(set(groups[y == 0])))
    # Each malicious executable is paired with a fold of benign executables for the FPR estimate.
    benign_folds = np.array_split(np.random.default_rng(42).permutation(benign_groups), len(malicious_groups))
    rows = []
    for held_malicious, held_benign in zip(malicious_groups, benign_folds):
        # A path can carry both labels (e.g. powershell.exe); hold out all of its rows.
        held_groups = {held_malicious, *held_benign}
        held = np.isin(groups, list(held_groups))
        fit = ~held
        target = held & (y == 1)
        benign_held = held & (y == 0)
        for name, (model, unsupervised) in models().items():
            if unsupervised:
                model.fit(X[fit & (y == 0)])
            else:
                model.fit(X[fit], y[fit])
            scores = model_scores(model, X[held], unsupervised)
            alert = scores >= ALERT_THRESHOLD
            held_y = y[held]
            rows.append({
                "held_out_executable": Path(held_malicious.replace("\\", "/")).name,
                "model": name,
                "detection_rate": float(alert[held_y == 1].mean()) if (held_y == 1).any() else float("nan"),
                "benign_false_positive_rate": float(alert[held_y == 0].mean()) if (held_y == 0).any() else float("nan"),
                "malicious_snapshots": int(target.sum()), "benign_snapshots": int(benign_held.sum()),
                "benign_executables": len(held_benign),
            })
    result = pd.DataFrame(rows)
    args.output.mkdir(parents=True, exist_ok=True)
    result.to_csv(args.output / "leave_one_out.csv", index=False)
    pivot = result.pivot(index="held_out_executable", columns="model", values="detection_rate")
    summary = result.groupby("model")[["detection_rate", "benign_false_positive_rate"]].mean()
    summary.to_csv(args.output / "leave_one_out_summary.csv")
    order = ["Decision Tree", "Random Forest", "Extra Trees", "Isolation Forest"]
    pivot = pivot[order]
    fig, ax = plt.subplots(figsize=(9, 4.6))
    image = ax.imshow(pivot.to_numpy(), cmap="Blues", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(order)), order)
    ax.set_yticks(range(len(pivot.index)), pivot.index)
    for i in range(pivot.shape[0]):
        for j in range(pivot.shape[1]):
            value = pivot.iloc[i, j]
            ax.text(j, i, f"{value:.2f}", ha="center", va="center",
                    color="white" if value > 0.6 else "#111827", fontsize=10)
    fig.colorbar(image, ax=ax, label="Tỷ lệ snapshot bị cảnh báo")
    ax.set_title("Phát hiện kỹ thuật chưa từng thấy (leave-one-executable-out)")
    fig.tight_layout()
    fig.savefig(args.output / "leave_one_out_heatmap.png", dpi=160)
    plt.close(fig)
    print(result.to_string(index=False, float_format=lambda v: f"{v:.3f}"))
    print(summary.to_string(float_format=lambda v: f"{v:.3f}"))
    (args.output / "notes.json").write_text(json.dumps({
        "threshold": ALERT_THRESHOLD,
        "note": "Each fold excludes one simulated executable and a disjoint set of benign executables from training.",
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
