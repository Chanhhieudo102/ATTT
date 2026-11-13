"""Train/infer PID models from explicitly labeled, user-collected process rows."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, IsolationForest, RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.tree import DecisionTreeClassifier

from .benchmark import batch_inference_ms_per_sample
from .features import FEATURE_COLUMNS
from .ml import ALERT_THRESHOLD, model_scores
from .pid_data import load_observations

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "artifacts/models/pid_live"
REPORT_DIR = ROOT / "artifacts/reports/pid_live"


def _metrics(y_true, predicted):
    benign_count = max(1, int((y_true == 0).sum()))
    return {
        "accuracy": float(accuracy_score(y_true, predicted)),
        "precision": float(precision_score(y_true, predicted, zero_division=0)),
        "recall": float(recall_score(y_true, predicted, zero_division=0)),
        "f1": float(f1_score(y_true, predicted, zero_division=0)),
        "false_positive_rate": float(((predicted == 1) & (y_true == 0)).sum() / benign_count),
    }


def grouped_partitions(X, y, groups):
    """Keep each executable in one partition; reserve test for final reporting."""
    outer = GroupShuffleSplit(n_splits=200, test_size=0.25, random_state=42)
    for development, test in outer.split(X, y, groups):
        if set(y[test]) != {0, 1}:
            continue
        inner = GroupShuffleSplit(n_splits=100, test_size=1 / 3, random_state=43)
        for train_local, validation_local in inner.split(X.iloc[development], y[development], groups[development]):
            train, validation = development[train_local], development[validation_local]
            if set(y[train]) == {0, 1} and set(y[validation]) == {0, 1}:
                return train, validation, test
    raise ValueError("Không tìm được train/validation/test có đủ hai lớp; cần thêm executable độc lập cho mỗi lớp.")


def train_labeled_samples(source: str | Path | list[Path] = ROOT / "data/observations/collected_samples.csv",
                          model_dir: str | Path = MODEL_DIR,
                          report_dir: str | Path = REPORT_DIR) -> pd.DataFrame:
    model_dir, report_dir = Path(model_dir), Path(report_dir)
    data, provenance = load_observations(source)
    if not set(data["label"].unique()).issuperset({0, 1}):
        raise ValueError("Cần có cả nhãn benign=0 và simulated_malicious=1.")
    groups_per_class = data.groupby("label")["group"].nunique().to_dict()
    if min(groups_per_class.get(0, 0), groups_per_class.get(1, 0)) < 3:
        raise ValueError("Cần ít nhất 3 đường dẫn executable khác nhau cho mỗi nhãn để tách train/validation/test.")

    X = data[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
    if not np.isfinite(X.to_numpy()).all():
        raise ValueError("Feature thiếu, không phải số hoặc vô hạn; hãy kiểm tra/thu thập lại thay vì tự điền 0.")
    y = data["label"].to_numpy()
    groups = data["group"].to_numpy()
    train_index, validation_index, test_index = grouped_partitions(X, y, groups)
    X_train, X_test = X.iloc[train_index], X.iloc[test_index]
    y_train, y_test = y[train_index], y[test_index]
    X_validation, y_validation = X.iloc[validation_index], y[validation_index]
    model_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    source_audit = (data.groupby(["label", "label_source"], dropna=False)
                    .agg(samples=("label", "size"), executable_count=("group", "nunique"))
                    .reset_index())
    source_audit.to_csv(report_dir / "label_source_audit.csv", index=False)
    dataset_summary = {
        "source_files": provenance,
        "label_meaning": {"0": "benign observed", "1": "simulated malicious observed"},
        "sample_count": int(len(data)),
        "class_counts": {str(int(label)): int(count) for label, count in data["label"].value_counts().items()},
        "executable_count": int(data["group"].nunique()),
        "source_count": int(data["label_source"].nunique()),
        "train_rows": int(len(train_index)),
        "validation_rows": int(len(validation_index)),
        "test_rows": int(len(test_index)),
        "train_executable_count": int(pd.Series(groups[train_index]).nunique()),
        "test_executable_count": int(pd.Series(groups[test_index]).nunique()),
        "split": "Grouped train/validation/test by normalized process_path; no path crosses partitions",
        "model_selection": "Highest validation F1 among supervised models; test is reporting only",
        "alert_threshold": ALERT_THRESHOLD,
        "score_note": "Same scores/threshold as live ML; combined rule+ML alerts require separate evaluation. Isolation score is not a probability.",
        "label_source_note": "Source text is operator-provided provenance, not an independent ground-truth attestation.",
    }
    (report_dir / "dataset_summary.json").write_text(
        json.dumps(dataset_summary, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest_columns = ["process_path", "group", "label", "label_source", "source_file", "source_row"]
    manifest_columns += [key for key in ("process_pid", "process_create_time", "sampled_at") if key in data]
    manifest = data[manifest_columns].copy()
    manifest["partition"] = ""
    for partition, indices in (("train", train_index), ("validation", validation_index), ("test", test_index)):
        manifest.loc[indices, "partition"] = partition
    manifest.to_csv(report_dir / "split_manifest.csv", index=False)
    audit_hashes = {"training_manifest_sha256": hashlib.sha256((report_dir / "split_manifest.csv").read_bytes()).hexdigest(),
                    "training_summary_sha256": hashlib.sha256((report_dir / "dataset_summary.json").read_bytes()).hexdigest()}
    classifiers = {
        "Decision Tree": DecisionTreeClassifier(max_depth=9, class_weight="balanced", random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=250, min_samples_leaf=2,
                                                class_weight="balanced", n_jobs=-1, random_state=42),
        "Extra Trees": ExtraTreesClassifier(n_estimators=250, min_samples_leaf=2,
                                            class_weight="balanced", n_jobs=-1, random_state=42),
    }
    results = []
    best_name, best_f1 = "", -1.0
    for name, model in classifiers.items():
        model.fit(X_train, y_train)
        prediction = (model_scores(model, X_test) >= ALERT_THRESHOLD).astype(int)
        validation = _metrics(y_validation, (model_scores(model, X_validation) >= ALERT_THRESHOLD).astype(int))
        row = {"model": name, **_metrics(y_test, prediction),
               "threshold": ALERT_THRESHOLD, "validation_f1": validation["f1"],
               "inference_ms_per_sample": batch_inference_ms_per_sample(model, X_test)}
        results.append(row)
        safe_name = name.lower().replace(" ", "_")
        joblib.dump({"model": model, "features": FEATURE_COLUMNS, "threshold": ALERT_THRESHOLD,
                     **audit_hashes,
                     "name": name, "source": "observed-per-process",
                     "split": dataset_summary["split"]}, model_dir / f"{safe_name}.joblib")
        report = {"labels": ["benign", "simulated_malicious"],
                  "confusion_matrix": confusion_matrix(y_test, prediction, labels=[0, 1]).tolist(),
                  "classification_report": classification_report(y_test, prediction,
                                                                   output_dict=True, zero_division=0),
                  "test_groups": sorted(set(groups[test_index])),
                  "train_group_count": int(pd.Series(groups[train_index]).nunique()),
                  "dataset_summary": dataset_summary}
        (report_dir / f"{safe_name}_confusion.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        pd.DataFrame({"feature": FEATURE_COLUMNS, "importance": model.feature_importances_}).sort_values(
            "importance", ascending=False).to_csv(report_dir / f"{safe_name}_feature_importance.csv", index=False)
        if validation["f1"] > best_f1:
            best_name, best_f1 = safe_name, validation["f1"]

    benign_train = X_train.iloc[np.where(y_train == 0)[0]]
    anomaly = IsolationForest(n_estimators=250, contamination="auto", random_state=42)
    anomaly.fit(benign_train)
    anomaly_prediction = (model_scores(anomaly, X_test, True) >= ALERT_THRESHOLD).astype(int)
    anomaly_row = {"model": "Isolation Forest (unsupervised)", **_metrics(y_test, anomaly_prediction),
                   "threshold": ALERT_THRESHOLD,
                   "validation_f1": _metrics(y_validation, (model_scores(anomaly, X_validation, True) >= ALERT_THRESHOLD).astype(int))["f1"],
                   "inference_ms_per_sample": batch_inference_ms_per_sample(anomaly, X_test)}
    results.append(anomaly_row)
    joblib.dump({"model": anomaly, "features": FEATURE_COLUMNS, "threshold": ALERT_THRESHOLD,
                 **audit_hashes,
                 "name": "Isolation Forest", "unsupervised": True,
                 "source": "observed-per-process", "split": dataset_summary["split"]},
                model_dir / "isolation_forest.joblib")
    report = {"labels": ["benign", "simulated_malicious"],
              "confusion_matrix": confusion_matrix(y_test, anomaly_prediction, labels=[0, 1]).tolist(),
              "classification_report": classification_report(y_test, anomaly_prediction,
                                                               output_dict=True, zero_division=0),
              "training_data": "benign train rows only",
              "test_groups": sorted(set(groups[test_index])),
              "dataset_summary": dataset_summary}
    (report_dir / "isolation_forest_confusion.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    comparison = pd.DataFrame(results)
    comparison.to_csv(report_dir / "model_comparison.csv", index=False)
    (model_dir / "active_model.txt").write_text(best_name + ".joblib", encoding="utf-8")
    return comparison
