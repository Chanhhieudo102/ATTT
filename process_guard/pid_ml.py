"""Train/infer PID models from explicitly labeled, user-collected process rows."""
from __future__ import annotations

import json
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


def train_labeled_samples(source: str | Path = ROOT / "data/observations/collected_samples.csv") -> pd.DataFrame:
    source = Path(source)
    if not source.exists():
        raise FileNotFoundError(f"Không thấy {source}; hãy lưu mẫu live có nhãn từ giao diện trước.")
    data = pd.read_csv(source)
    required = FEATURE_COLUMNS + ["label", "process_path", "label_source"]
    missing = [column for column in required if column not in data.columns]
    if missing:
        raise ValueError("Thiếu cột: " + ", ".join(missing) + ". Mẫu cũ có thể cần thu thập lại.")
    data = data.dropna(subset=FEATURE_COLUMNS + ["label"]).copy()
    numeric_labels = pd.to_numeric(data["label"], errors="coerce")
    if numeric_labels.isna().any() or not numeric_labels.isin([0, 1]).all():
        raise ValueError("Nhãn phải là 0 (benign) hoặc 1 (simulated_malicious).")
    data["label"] = numeric_labels.astype(int)
    data["label_source"] = data["label_source"].fillna("").astype(str).str.strip()
    if data["label_source"].eq("").any():
        raise ValueError("Có mẫu thiếu label_source; hãy ghi mã kịch bản/nguồn xác minh cho từng mẫu rồi huấn luyện lại.")
    if not set(data["label"].unique()).issuperset({0, 1}):
        raise ValueError("Cần có cả nhãn benign=0 và simulated_malicious=1.")
    data["process_path"] = data["process_path"].fillna("").astype(str)
    fallback = (data["process_name"].fillna("unknown").astype(str)
                if "process_name" in data else pd.Series("unknown", index=data.index))
    normalized_path = data["process_path"].str.replace("/", "\\", regex=False).str.casefold()
    data["group"] = normalized_path.where(normalized_path.str.len() > 0, fallback)
    groups_per_class = data.groupby("label")["group"].nunique().to_dict()
    if min(groups_per_class.get(0, 0), groups_per_class.get(1, 0)) < 2:
        raise ValueError("Cần ít nhất 2 đường dẫn executable khác nhau cho mỗi nhãn để tách train/test theo file.")

    X = data[FEATURE_COLUMNS].astype(float).replace([np.inf, -np.inf], 0).fillna(0)
    y = data["label"].to_numpy()
    groups = data["group"].to_numpy()
    split = None
    splitter = GroupShuffleSplit(n_splits=200, test_size=0.30, random_state=42)
    for train_index, test_index in splitter.split(X, y, groups):
        if set(y[train_index]) == {0, 1} and set(y[test_index]) == {0, 1}:
            split = train_index, test_index
            break
    if split is None:
        raise ValueError("Không tìm được group split có đủ hai lớp. Thu thập thêm executable riêng cho mỗi nhãn.")
    train_index, test_index = split
    X_train, X_test = X.iloc[train_index], X.iloc[test_index]
    y_train, y_test = y[train_index], y[test_index]
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    source_audit = (data.groupby(["label", "label_source"], dropna=False)
                    .agg(samples=("label", "size"), executable_count=("group", "nunique"))
                    .reset_index())
    source_audit.to_csv(REPORT_DIR / "label_source_audit.csv", index=False)
    dataset_summary = {
        "source_csv": str(source.resolve()),
        "label_meaning": {"0": "benign observed", "1": "simulated malicious observed"},
        "sample_count": int(len(data)),
        "class_counts": {str(int(label)): int(count) for label, count in data["label"].value_counts().items()},
        "executable_count": int(data["group"].nunique()),
        "source_count": int(data["label_source"].nunique()),
        "train_rows": int(len(train_index)),
        "test_rows": int(len(test_index)),
        "train_executable_count": int(pd.Series(groups[train_index]).nunique()),
        "test_executable_count": int(pd.Series(groups[test_index]).nunique()),
        "split": "GroupShuffleSplit by normalized process_path; executable paths do not cross train/test",
        "label_source_note": "Source text is operator-provided provenance, not an independent ground-truth attestation.",
    }
    (REPORT_DIR / "dataset_summary.json").write_text(
        json.dumps(dataset_summary, ensure_ascii=False, indent=2), encoding="utf-8")
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
        prediction = model.predict(X_test)
        row = {"model": name, **_metrics(y_test, prediction),
               "inference_ms_per_sample": batch_inference_ms_per_sample(model, X_test)}
        results.append(row)
        safe_name = name.lower().replace(" ", "_")
        joblib.dump({"model": model, "features": FEATURE_COLUMNS, "threshold": 0.65,
                     "name": name, "source": "observed-per-process",
                     "split": "GroupShuffleSplit by process_path"}, MODEL_DIR / f"{safe_name}.joblib")
        report = {"labels": ["benign", "simulated_malicious"],
                  "confusion_matrix": confusion_matrix(y_test, prediction, labels=[0, 1]).tolist(),
                  "classification_report": classification_report(y_test, prediction,
                                                                   output_dict=True, zero_division=0),
                  "test_groups": sorted(set(groups[test_index])),
                  "train_group_count": int(pd.Series(groups[train_index]).nunique()),
                  "dataset_summary": dataset_summary}
        (REPORT_DIR / f"{safe_name}_confusion.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        pd.DataFrame({"feature": FEATURE_COLUMNS, "importance": model.feature_importances_}).sort_values(
            "importance", ascending=False).to_csv(REPORT_DIR / f"{safe_name}_feature_importance.csv", index=False)
        if row["f1"] > best_f1:
            best_name, best_f1 = safe_name, row["f1"]

    benign_train = X_train.iloc[np.where(y_train == 0)[0]]
    anomaly = IsolationForest(n_estimators=250, contamination="auto", random_state=42)
    anomaly.fit(benign_train)
    anomaly_prediction = (anomaly.predict(X_test) == -1).astype(int)
    anomaly_row = {"model": "Isolation Forest (unsupervised)", **_metrics(y_test, anomaly_prediction),
                   "inference_ms_per_sample": batch_inference_ms_per_sample(anomaly, X_test)}
    results.append(anomaly_row)
    joblib.dump({"model": anomaly, "features": FEATURE_COLUMNS, "threshold": 0.65,
                 "name": "Isolation Forest", "unsupervised": True,
                 "source": "observed-per-process", "split": "GroupShuffleSplit by process_path"},
                MODEL_DIR / "isolation_forest.joblib")
    report = {"labels": ["benign", "simulated_malicious"],
              "confusion_matrix": confusion_matrix(y_test, anomaly_prediction, labels=[0, 1]).tolist(),
              "classification_report": classification_report(y_test, anomaly_prediction,
                                                               output_dict=True, zero_division=0),
              "training_data": "benign train rows only",
              "test_groups": sorted(set(groups[test_index])),
              "dataset_summary": dataset_summary}
    (REPORT_DIR / "isolation_forest_confusion.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    comparison = pd.DataFrame(results)
    comparison.to_csv(REPORT_DIR / "model_comparison.csv", index=False)
    (MODEL_DIR / "active_model.txt").write_text(best_name + ".joblib", encoding="utf-8")
    return comparison
