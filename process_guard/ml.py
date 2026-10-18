"""Training, comparison, and inference helpers for four scikit-learn models."""
from __future__ import annotations

from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd
from .benchmark import batch_inference_ms_per_sample
from sklearn.ensemble import IsolationForest, RandomForestClassifier, ExtraTreesClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             confusion_matrix, classification_report)
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

from .features import FEATURE_COLUMNS, extract_features

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "artifacts/models/synthetic_demo"
REPORT_DIR = ROOT / "artifacts/reports/synthetic_demo"


def train_all(dataset: str | Path = ROOT / "data/fixtures/synthetic_demo/process_samples_synthetic.csv") -> pd.DataFrame:
    data = pd.read_csv(dataset)
    if "label" not in data:
        raise ValueError("Dataset cần cột label (0=benign, 1=simulated_malicious).")
    missing = [col for col in FEATURE_COLUMNS if col not in data]
    if missing:
        raise ValueError("Thiếu cột đặc trưng: " + ", ".join(missing))
    data = data.dropna(subset=FEATURE_COLUMNS + ["label"])
    y = data["label"].astype(int)
    if y.nunique() < 2:
        raise ValueError("Cần dữ liệu của cả hai lớp 0 và 1 để huấn luyện supervised.")
    X = data[FEATURE_COLUMNS].astype(float).replace([np.inf, -np.inf], 0).fillna(0)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    models = {
        "Decision Tree": DecisionTreeClassifier(max_depth=9, class_weight="balanced", random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=180, min_samples_leaf=2,
                                                 class_weight="balanced", n_jobs=-1, random_state=42),
        "Extra Trees": ExtraTreesClassifier(n_estimators=180, min_samples_leaf=2,
                                            class_weight="balanced", n_jobs=-1, random_state=42),
    }
    results = []
    best_name, best_f1 = "", -1.0
    for name, model in models.items():
        model.fit(X_train, y_train)
        pred = model.predict(X_test)
        prob = model.predict_proba(X_test)[:, 1]
        metrics = {
            "model": name, "accuracy": accuracy_score(y_test, pred),
            "precision": precision_score(y_test, pred, zero_division=0),
            "recall": recall_score(y_test, pred, zero_division=0),
            "f1": f1_score(y_test, pred, zero_division=0),
            "false_positive_rate": float(((pred == 1) & (y_test == 0)).sum() / max(1, (y_test == 0).sum())),
            "inference_ms_per_sample": batch_inference_ms_per_sample(model, X_test),
        }
        results.append(metrics)
        joblib.dump({"model": model, "features": FEATURE_COLUMNS, "threshold": 0.65, "name": name,
                     "source": "synthetic-demo", "warning": "Synthetic teaching data; demo only."},
                    MODEL_DIR / (name.lower().replace(" ", "_") + ".joblib"))
        if metrics["f1"] > best_f1:
            best_name, best_f1 = name, metrics["f1"]
        cm = confusion_matrix(y_test, pred, labels=[0, 1]).tolist()
        (REPORT_DIR / (name.lower().replace(" ", "_") + "_confusion.json")).write_text(
            json.dumps({"labels": ["benign", "simulated_malicious"], "matrix": cm,
                        "classification_report": classification_report(y_test, pred, output_dict=True,
                                                                         zero_division=0)}, indent=2), encoding="utf-8")
        if hasattr(model, "feature_importances_"):
            pd.DataFrame({"feature": FEATURE_COLUMNS, "importance": model.feature_importances_}).sort_values(
                "importance", ascending=False).to_csv(REPORT_DIR / (name.lower().replace(" ", "_") + "_feature_importance.csv"), index=False)

    # Unsupervised model is fit only on training benign records.
    benign_train = X_train[y_train == 0]
    anomaly = IsolationForest(n_estimators=180, contamination="auto", random_state=42)
    anomaly.fit(benign_train)
    anomaly_pred = (anomaly.predict(X_test) == -1).astype(int)
    anomaly_metrics = {
        "model": "Isolation Forest (unsupervised)",
        "accuracy": accuracy_score(y_test, anomaly_pred),
        "precision": precision_score(y_test, anomaly_pred, zero_division=0),
        "recall": recall_score(y_test, anomaly_pred, zero_division=0),
        "f1": f1_score(y_test, anomaly_pred, zero_division=0),
        "false_positive_rate": float(((anomaly_pred == 1) & (y_test == 0)).sum() / max(1, (y_test == 0).sum())),
        "inference_ms_per_sample": batch_inference_ms_per_sample(anomaly, X_test),
    }
    results.append(anomaly_metrics)
    joblib.dump({"model": anomaly, "features": FEATURE_COLUMNS, "threshold": 0.65,
                 "name": "Isolation Forest", "unsupervised": True, "source": "synthetic-demo",
                 "warning": "Synthetic teaching data; demo only."}, MODEL_DIR / "isolation_forest.joblib")
    cm = confusion_matrix(y_test, anomaly_pred, labels=[0, 1]).tolist()
    (REPORT_DIR / "isolation_forest_confusion.json").write_text(
        json.dumps({"labels": ["benign", "simulated_malicious"], "matrix": cm}, indent=2), encoding="utf-8")
    result = pd.DataFrame(results)
    result.to_csv(REPORT_DIR / "model_comparison.csv", index=False)
    (MODEL_DIR / "active_model.txt").write_text(best_name.lower().replace(" ", "_") + ".joblib", encoding="utf-8")
    return result


class ModelScorer:
    def __init__(self, model_dir: str | Path = MODEL_DIR, allow_synthetic_demo: bool = False,
                 allowed_sources: set[str] | None = None):
        self.model_dir = Path(model_dir)
        self.bundle = None
        active_file = self.model_dir / "active_model.txt"
        if active_file.exists():
            candidate = self.model_dir / active_file.read_text(encoding="utf-8").strip()
            if candidate.exists():
                bundle = joblib.load(candidate)
                # Cardiff models consume machine-level sequences, not PID rows.
                # Synthetic PID models are allowed only in the explicitly labeled demo.
                accepted_sources = set(allowed_sources or ())
                if allow_synthetic_demo:
                    accepted_sources.add("synthetic-demo")
                if bundle.get("source") in accepted_sources:
                    self.bundle = bundle

    def score_many(self, records: list[dict]) -> list[tuple[float, str]]:
        if not records:
            return []
        if not self.bundle:
            return [(0.0, "Model Cardiff offline; không chấm từng PID") for _ in records]
        feature_rows = [extract_features(record) for record in records]
        X = pd.DataFrame([[row[column] for column in self.bundle["features"]]
                          for row in feature_rows], columns=self.bundle["features"])
        model = self.bundle["model"]
        if self.bundle.get("unsupervised"):
            raw = -model.decision_function(X)
            # Monotonic bounded display score; threshold is calibrated only for UI triage.
            scores = 1 / (1 + np.exp(-8 * raw))
        else:
            scores = model.predict_proba(X)[:, 1]
        name = str(self.bundle.get("name", "ML"))
        return [(float(score), name) for score in scores]

    def score(self, record: dict) -> tuple[float, str]:
        return self.score_many([record])[0]
