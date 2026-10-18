"""Train and compare classifiers on Cardiff Dataset 2's published split."""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import (ExtraTreesClassifier, GradientBoostingClassifier,
                              IsolationForest, RandomForestClassifier)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, balanced_accuracy_score,
                             classification_report, confusion_matrix, f1_score,
                             precision_recall_curve, precision_score, recall_score,
                             roc_auc_score, roc_curve)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

try:
    from xgboost import XGBClassifier
except ImportError:
    XGBClassifier = None

try:
    from lightgbm import LGBMClassifier
except ImportError:
    LGBMClassifier = None

from process_guard.benchmark import batch_inference_ms_per_sample
from process_guard.cardiff import make_sequences
from process_guard.visualization import plot_cardiff_training_results


def _model_specs():
    """Create fresh estimators, adding modern boosters when their optional packages exist."""
    specs = [
        ("Decision Tree", "decision_tree", DecisionTreeClassifier(
            max_depth=9, class_weight="balanced", random_state=42), False),
        ("Random Forest", "random_forest", RandomForestClassifier(
            n_estimators=250, min_samples_leaf=2, class_weight="balanced", n_jobs=-1,
            random_state=42), False),
        ("Extra Trees", "extra_trees", ExtraTreesClassifier(
            n_estimators=250, min_samples_leaf=2, class_weight="balanced", n_jobs=-1,
            random_state=42), False),
        ("Gradient Boosting", "gradient_boosting", GradientBoostingClassifier(
            n_estimators=150, learning_rate=0.05, max_depth=2, random_state=42), False),
    ]
    if XGBClassifier is not None:
        specs.append(("XGBoost", "xgboost", XGBClassifier(
            objective="binary:logistic", eval_metric="logloss", n_estimators=300,
            learning_rate=0.05, max_depth=4, subsample=0.85, colsample_bytree=0.85,
            reg_lambda=1.0, tree_method="hist", n_jobs=-1, random_state=42,
            verbosity=0), False))
    if LGBMClassifier is not None:
        specs.append(("LightGBM", "lightgbm", LGBMClassifier(
            objective="binary", n_estimators=300, learning_rate=0.05, max_depth=4,
            num_leaves=15, subsample=0.85, subsample_freq=1, colsample_bytree=0.85,
            reg_lambda=1.0, n_jobs=-1, random_state=42, verbosity=-1), False))
    specs.extend([
        ("Logistic Regression", "logistic_regression", make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=3000, class_weight="balanced",
                                                 random_state=42)), False),
        ("RBF SVM", "rbf_svm", make_pipeline(
            StandardScaler(), SVC(C=1.0, kernel="rbf", class_weight="balanced",
                                  random_state=42)), False),
        ("Isolation Forest (unsupervised)", "isolation_forest", IsolationForest(
            n_estimators=250, contamination="auto", random_state=42), True),
    ])
    return specs
FEATURE_LABELS = [
    "cpu_system", "cpu_user", "memory", "swap", "total_processes", "max_pid",
    "rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
]


def _json_default(value):
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, np.ndarray):
        return value.tolist()
    return str(value)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2,
                                    default=_json_default) + "\n", encoding="utf-8")
    temporary.replace(path)


def _write_csv(frame: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    frame.to_csv(temporary, index=False)
    temporary.replace(path)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _decision_scores(model, samples, unsupervised: bool = False) -> np.ndarray | None:
    if unsupervised and hasattr(model, "decision_function"):
        return -np.asarray(model.decision_function(samples), dtype=float)
    if hasattr(model, "predict_proba"):
        probabilities = np.asarray(model.predict_proba(samples), dtype=float)
        classes = list(getattr(model, "classes_", []))
        if not classes and hasattr(model, "named_steps"):
            classes = list(getattr(model.steps[-1][1], "classes_", []))
        positive_index = classes.index(1) if 1 in classes else probabilities.shape[1] - 1
        return probabilities[:, positive_index]
    if hasattr(model, "decision_function"):
        return np.asarray(model.decision_function(samples), dtype=float).reshape(-1)
    return None


def _score_row(name: str, y_true: np.ndarray, prediction: np.ndarray,
               scores: np.ndarray | None = None) -> dict:
    benign_count = max(1, int((y_true == 0).sum()))
    row = {
        "model": name,
        "accuracy": float(accuracy_score(y_true, prediction)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, prediction)),
        "precision": float(precision_score(y_true, prediction, zero_division=0)),
        "recall": float(recall_score(y_true, prediction, zero_division=0)),
        "f1": float(f1_score(y_true, prediction, zero_division=0)),
        "false_positive_rate": float(((prediction == 1) & (y_true == 0)).sum() / benign_count),
        "roc_auc": float(roc_auc_score(y_true, scores)) if scores is not None else float("nan"),
        "average_precision": float(average_precision_score(y_true, scores)) if scores is not None else float("nan"),
    }
    return row


def _feature_importance(model, feature_order: list[str]) -> pd.DataFrame | None:
    estimator = model.steps[-1][1] if hasattr(model, "steps") else model
    if hasattr(estimator, "feature_importances_"):
        values = np.asarray(estimator.feature_importances_, dtype=float)
    elif hasattr(estimator, "coef_"):
        values = np.mean(np.abs(np.asarray(estimator.coef_, dtype=float)), axis=0)
    else:
        return None
    table = pd.DataFrame({"feature": feature_order, "importance": values})
    return table.sort_values("importance", ascending=False).reset_index(drop=True)


def _save_model_checkpoint(model, path: Path, bundle: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    joblib.dump(bundle, temporary, compress=3)
    temporary.replace(path)


def train(source: Path = ROOT / "data/raw/cardiff_data_2.csv", seconds: int = 5) -> pd.DataFrame:
    source = Path(source).resolve()
    if not source.exists():
        raise FileNotFoundError(f"Cardiff dataset not found: {source}")
    if seconds < 1 or seconds > 20:
        raise ValueError("seconds must be between 1 and 20")

    started_at = datetime.now().astimezone()
    run_started_monotonic = time.perf_counter()
    model_specs = _model_specs()
    run_id = started_at.strftime("%Y%m%d_%H%M%S_%f")
    model_root = ROOT / "artifacts/models/cardiff"
    stable_report_dir = ROOT / "artifacts/reports/cardiff"
    run_model_dir = model_root / "runs" / run_id
    run_report_dir = stable_report_dir / "runs" / run_id
    log_path = ROOT / "artifacts/logs" / f"cardiff_training_{run_id}.jsonl"
    checkpoint_path = run_model_dir / "checkpoint.json"
    model_root.mkdir(parents=True, exist_ok=True)
    run_model_dir.mkdir(parents=True, exist_ok=True)
    run_report_dir.mkdir(parents=True, exist_ok=True)
    stable_report_dir.mkdir(parents=True, exist_ok=True)

    completed: list[str] = []
    rows: list[dict] = []
    common = {
        "run_id": run_id,
        "source": str(source),
        "source_sha256": _sha256(source),
        "seconds": seconds,
        "split": "published sample-level test_set",
        "models_total": len(model_specs),
        "started_at": started_at.isoformat(timespec="seconds"),
        "checkpoint_dir": str(run_model_dir),
        "report_dir": str(run_report_dir),
        "log_file": str(log_path),
    }

    def log_event(event: str, **details) -> None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {"timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
                 "run_id": run_id, "event": event, **details}
        with log_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry, ensure_ascii=False, default=_json_default) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def update_checkpoint(status: str, current_model: str | None = None, **extra) -> None:
        state = {**common, "status": status, "current_model": current_model,
                 "completed_models": completed, "completed_count": len(completed),
                 "metrics_so_far": rows, "updated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                 **extra}
        _write_json(checkpoint_path, state)

    log_event("training_started", **common)
    optional_unavailable = []
    if XGBClassifier is None:
        optional_unavailable.append("XGBoost (install requirements-modern-ml.txt)")
    if LGBMClassifier is None:
        optional_unavailable.append("LightGBM (install requirements-modern-ml.txt)")
    for model_name in optional_unavailable:
        log_event("optional_model_unavailable", model=model_name)
        print(f"[run {run_id}] Skipping {model_name}.")
    update_checkpoint("running", current_model="loading dataset")
    print(f"[run {run_id}] Loading and preparing Cardiff Dataset 2...")
    try:
        X_seq, y, is_test, sample_ids, metrics = make_sequences(source, seconds=seconds)
        X = X_seq.reshape(len(X_seq), -1)
        train_mask, test_mask = ~is_test, is_test
        X_train, y_train = X[train_mask], y[train_mask]
        X_test, y_test = X[test_mask], y[test_mask]
        if len(X_test) == 0 or np.unique(y_train).size < 2 or np.unique(y_test).size < 2:
            raise ValueError("Published test_set must contain both labels and training data must contain both classes.")
    except Exception as exc:
        update_checkpoint("failed", current_model="loading dataset",
                          error=f"{type(exc).__name__}: {exc}")
        log_event("training_failed", completed_models=[],
                  error=f"{type(exc).__name__}: {exc}")
        raise
    feature_order = [f"t{t}_{metric}" for t in range(seconds) for metric in metrics]
    dataset_info = {
        "sample_count": int(len(y)), "train_samples": int(len(y_train)), "test_samples": int(len(y_test)),
        "train_class_counts": {str(int(label)): int(count) for label, count in
                               zip(*np.unique(y_train, return_counts=True))},
        "test_class_counts": {str(int(label)): int(count) for label, count in
                              zip(*np.unique(y_test, return_counts=True))},
        "feature_count": int(X.shape[1]), "feature_order": feature_order,
        "sample_ids_sha256": hashlib.sha256("\n".join(sample_ids.tolist()).encode("utf-8")).hexdigest(),
    }
    update_checkpoint("running", current_model="training classifiers", dataset=dataset_info)
    log_event("dataset_prepared", **dataset_info)
    feature_names = [f"t{second}_{metric}" for second in range(seconds) for metric in metrics]
    best_name, best_f1 = None, -1.0
    curve_reports: dict[str, dict] = {}

    try:
        for model_index, (name, file_stem, model, unsupervised) in enumerate(model_specs, start=1):
            print(f"[run {run_id}] Training {model_index}/{len(model_specs)}: {name}...")
            log_event("model_started", model=name, index=model_index)
            fit_started = time.perf_counter()
            fit_X, fit_y = (X_train[y_train == 0], None) if unsupervised else (X_train, y_train)
            if unsupervised:
                model.fit(fit_X)
                prediction = (model.predict(X_test) == -1).astype(int)
            else:
                model.fit(fit_X, fit_y)
                prediction = np.asarray(model.predict(X_test), dtype=int)
            fit_seconds = time.perf_counter() - fit_started
            scores = _decision_scores(model, X_test, unsupervised=unsupervised)
            metric_row = _score_row(name, y_test, prediction, scores)
            metric_row["fit_seconds"] = float(fit_seconds)
            metric_row["inference_ms_per_sample"] = float(
                batch_inference_ms_per_sample(model, X_test))
            rows.append(metric_row)

            matrix = confusion_matrix(y_test, prediction, labels=[0, 1])
            report = {
                "run_id": run_id, "model": name, "labels": ["benign", "malicious"],
                "confusion_matrix": matrix.tolist(), "metrics": metric_row,
                "classification_report": classification_report(
                    y_test, prediction, labels=[0, 1], target_names=["benign", "malicious"],
                    output_dict=True, zero_division=0),
                "source_dataset": "Cardiff Dataset 2", "seconds": seconds,
                "split": "published sample-level test_set",
                "training_data": "benign train samples only" if unsupervised else "published training samples",
            }
            _write_json(run_report_dir / f"cardiff_{file_stem}_confusion.json", report)
            if scores is not None:
                fpr, tpr, _ = roc_curve(y_test, scores)
                curve_precision, curve_recall, _ = precision_recall_curve(y_test, scores)
                curve_reports[file_stem] = {
                    "model": name, "roc_auc": metric_row["roc_auc"],
                    "average_precision": metric_row["average_precision"],
                    "fpr": fpr.tolist(), "tpr": tpr.tolist(),
                    "precision": curve_precision.tolist(), "recall": curve_recall.tolist(),
                }
            importance = _feature_importance(model, feature_names)
            if importance is not None:
                _write_csv(importance, run_report_dir / f"cardiff_{file_stem}_feature_importance.csv")

            model_bundle = {
                "model": model, "dataset": "Cardiff Dataset 2", "metrics": metrics,
                "seconds": seconds, "feature_order": feature_order,
                "split": "published sample-level test_set", "name": name,
                "source_dataset": str(source), "run_id": run_id,
                "unsupervised": unsupervised, "evaluation": metric_row,
            }
            _save_model_checkpoint(model, run_model_dir / f"cardiff_{file_stem}.joblib", model_bundle)
            completed.append(name)
            progress = pd.DataFrame(rows)
            _write_csv(progress, run_report_dir / "cardiff_training_progress.csv")
            _write_csv(progress, run_report_dir / "cardiff_model_comparison.csv")
            if metric_row["f1"] > best_f1:
                best_name, best_f1 = file_stem, metric_row["f1"]
            update_checkpoint("running", current_model=None, dataset=dataset_info,
                              best_model_by_test_f1=best_name, best_test_f1=best_f1)
            log_event("model_completed", model=name, index=model_index,
                      metrics=metric_row, checkpoint=str(run_model_dir / f"cardiff_{file_stem}.joblib"))
            print(f"[run {run_id}] {name}: F1={metric_row['f1']:.4f}, "
                  f"Recall={metric_row['recall']:.4f}, FPR={metric_row['false_positive_rate']:.4f}, "
                  f"fit={fit_seconds:.2f}s")

        # Keep the paper-style early-observation comparison for Random Forest.
        early_rows = []
        for count in range(1, seconds + 1):
            width = count * len(metrics)
            early_model = RandomForestClassifier(n_estimators=200, min_samples_leaf=2,
                                                 class_weight="balanced", n_jobs=-1,
                                                 random_state=42)
            log_event("early_window_started", seconds_observed=count)
            early_started = time.perf_counter()
            early_model.fit(X_train[:, :width], y_train)
            early_prediction = early_model.predict(X_test[:, :width])
            early_fit_seconds = time.perf_counter() - early_started
            early_row = _score_row("Random Forest", y_test, early_prediction,
                                   _decision_scores(early_model, X_test[:, :width]))
            early_row.update({"seconds_observed": count, "fit_seconds": float(early_fit_seconds),
                              "inference_ms_per_sample": float(batch_inference_ms_per_sample(
                                  early_model, X_test[:, :width]))})
            early_rows.append(early_row)
            _save_model_checkpoint(early_model, run_model_dir / f"cardiff_early_rf_{count}s.joblib", {
                "model": early_model, "dataset": "Cardiff Dataset 2", "metrics": metrics,
                "seconds": count, "feature_order": feature_order[:width],
                "split": "published sample-level test_set", "name": f"Random Forest {count}s",
                "run_id": run_id,
            })
            _write_csv(pd.DataFrame(early_rows), run_report_dir / "cardiff_early_window_metrics.csv")
            log_event("early_window_completed", seconds_observed=count,
                      metrics=early_row, fit_seconds=early_fit_seconds)

        _write_json(run_report_dir / "cardiff_curves.json", curve_reports)
        comparison = pd.DataFrame(rows)
        _write_csv(comparison, run_report_dir / "cardiff_model_comparison.csv")
        _write_csv(pd.DataFrame(early_rows), run_report_dir / "cardiff_early_window_metrics.csv")
        _write_json(run_report_dir / "cardiff_training_summary.json", {
            **common, **dataset_info, "status": "completed", "completed_models": completed,
            "best_model_by_test_f1": best_name, "best_test_f1": best_f1,
            "selection_note": "Best F1 is selected on the published test split for comparison only; it is not an independent validation estimate.",
        })

        for plot_path in plot_cardiff_training_results(run_report_dir):
            print(f"[run {run_id}] Plot saved: {plot_path}")

        total_seconds = time.perf_counter() - run_started_monotonic
        summary_path = run_report_dir / "cardiff_training_summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["elapsed_seconds"] = total_seconds
        summary["completed_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
        _write_json(summary_path, summary)

        # Publish the completed run to the stable paths used by existing project tools.
        for artifact in run_report_dir.iterdir():
            if artifact.is_file():
                shutil.copy2(artifact, stable_report_dir / artifact.name)
        for checkpoint in run_model_dir.glob("cardiff_*.joblib"):
            if "early_rf_" not in checkpoint.name:
                shutil.copy2(checkpoint, model_root / checkpoint.name)
        (model_root / "cardiff_active_model.txt").write_text(
            f"cardiff_{best_name}.joblib\n", encoding="utf-8")
        (stable_report_dir / "latest_run.txt").write_text(run_id + "\n", encoding="utf-8")

        update_checkpoint("completed", current_model=None, dataset=dataset_info,
                          best_model_by_test_f1=best_name, best_test_f1=best_f1,
                          completed_at=datetime.now().astimezone().isoformat(timespec="seconds"),
                          elapsed_seconds=total_seconds)
        log_event("training_completed", completed_models=completed, best_model_by_test_f1=best_name,
                  best_test_f1=best_f1, report_dir=str(stable_report_dir),
                  checkpoint_dir=str(run_model_dir), elapsed_seconds=total_seconds)
        comparison.attrs.update({"run_id": run_id, "run_report_dir": str(run_report_dir),
                                 "stable_report_dir": str(stable_report_dir),
                                 "checkpoint_dir": str(run_model_dir), "log_file": str(log_path)})
        print(f"[run {run_id}] Complete. Reports: {stable_report_dir}")
        print(f"[run {run_id}] Checkpoints: {run_model_dir}")
        print(f"[run {run_id}] Log: {log_path}")
        return comparison
    except KeyboardInterrupt:
        update_checkpoint("interrupted", current_model="interrupted by user", dataset=dataset_info)
        log_event("training_interrupted", completed_models=completed)
        raise
    except Exception as exc:
        update_checkpoint("failed", current_model=None, dataset=dataset_info,
                          error=f"{type(exc).__name__}: {exc}")
        log_event("training_failed", completed_models=completed,
                  error=f"{type(exc).__name__}: {exc}")
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "data/raw/cardiff_data_2.csv")
    parser.add_argument("--seconds", type=int, default=5)
    args = parser.parse_args()
    result = train(args.source, args.seconds)
    display_columns = ["model", "accuracy", "balanced_accuracy", "precision", "recall", "f1",
                       "false_positive_rate", "roc_auc", "average_precision", "fit_seconds",
                       "inference_ms_per_sample"]
    print(result[display_columns].to_string(index=False, float_format=lambda value: f"{value:.4f}"))
    print("Published sample-level test_set split used; metrics are dataset-specific.")
