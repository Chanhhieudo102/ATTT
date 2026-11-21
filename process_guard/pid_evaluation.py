"""Evaluate current rules and a PID model on separately collected observations."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .features import FEATURE_COLUMNS
from .ml import ALERT_THRESHOLD, ModelScorer, model_scores
from .pid_data import load_observations, normalize_executable
from .rules import evaluate_rules


def detection_metrics(labels, predictions) -> dict:
    labels, predictions = np.asarray(labels), np.asarray(predictions)
    tn = int(((labels == 0) & (predictions == 0)).sum())
    fp = int(((labels == 0) & (predictions == 1)).sum())
    fn = int(((labels == 1) & (predictions == 0)).sum())
    tp = int(((labels == 1) & (predictions == 1)).sum())
    return {"sample_count": len(labels), "tn": tn, "fp": fp, "fn": fn, "tp": tp,
            "accuracy": (tp + tn) / len(labels) if len(labels) else None,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None,
            "confusion_matrix": [[tn, fp], [fn, tp]]}


def evaluate_observations(sources, output: Path, model_dir: Path,
                          training_report_dir: Path) -> dict:
    data, provenance = load_observations(sources)
    scorer = ModelScorer(model_dir, allowed_sources={"observed-per-process"})
    overlap = {"training_audit_available": False, "known_executable_rows": None,
               "process_identity_audit_available": False}
    bundle_hash = None
    if scorer.bundle:
        summary_path = training_report_dir / "dataset_summary.json"
        manifest_path = training_report_dir / "split_manifest.csv"
        if not summary_path.exists() or not manifest_path.exists():
            raise ValueError("Model PID cần dataset_summary.json và split_manifest.csv để kiểm tra trùng dữ liệu.")
        for key, path in (("training_summary_sha256", summary_path), ("training_manifest_sha256", manifest_path)):
            if scorer.bundle.get(key) != hashlib.sha256(path.read_bytes()).hexdigest():
                raise ValueError("Training audit không khớp model hoặc model cũ thiếu fingerprint; hãy huấn luyện lại.")
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        trained_hashes = {item["sha256"] for item in summary.get("source_files", [])}
        if not trained_hashes:
            raise ValueError("Training audit thiếu SHA-256 nguồn; hãy huấn luyện lại để có provenance.")
        if any(item["sha256"] in trained_hashes for item in provenance):
            raise ValueError("CSV đánh giá trùng nội dung với dữ liệu đã dùng trong train/validation/test.")
        manifest = pd.read_csv(manifest_path)
        known = set(manifest.process_path.map(normalize_executable))
        overlap.update(training_audit_available=True,
                       known_executable_rows=int(data.group.isin(known).sum()))
        identity_columns = ["group", "process_pid", "process_create_time"]
        if all(column in data and column in manifest for column in identity_columns):
            if data[identity_columns].isna().any().any() or manifest[identity_columns].isna().any().any():
                raise ValueError("Thiếu danh tính PID trong audit; cần thu thập/huấn luyện lại.")
            def identities(frame):
                return set(zip(frame.group, pd.to_numeric(frame.process_pid).astype(int),
                               pd.to_numeric(frame.process_create_time).round(2)))
            if identities(data) & identities(manifest):
                raise ValueError("Process instance đánh giá đã xuất hiện trong dữ liệu huấn luyện.")
            overlap["process_identity_audit_available"] = True
        model_path = Path(model_dir) / (Path(model_dir) / "active_model.txt").read_text(encoding="utf-8").strip()
        bundle_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
        if not set(scorer.bundle["features"]) <= set(FEATURE_COLUMNS):
            raise ValueError("Feature schema của model không khớp; hãy huấn luyện lại.")

    predictions = data.copy()
    rules = [evaluate_rules({}, row)[0] for row in data[FEATURE_COLUMNS].to_dict("records")]
    predictions["rule_score_current"] = rules
    score_columns = {"rules": "rule_score_current"}
    if scorer.bundle:
        predictions["ml_score_current"] = model_scores(scorer.bundle["model"], data[list(scorer.bundle["features"])],
                                                       bool(scorer.bundle.get("unsupervised")))
        predictions["combined_score_current"] = np.maximum(rules, predictions.ml_score_current)
        score_columns.update(ml="ml_score_current", combined="combined_score_current")
    else:
        predictions["combined_score_current"] = rules
        score_columns["combined_rules_only"] = "combined_score_current"
    metrics = []
    for name, column in score_columns.items():
        predictions[f"{name}_alert"] = (predictions[column] >= ALERT_THRESHOLD).astype(int)
        metrics.append({"detector": name, "unit": "snapshot",
                        **detection_metrics(data.label, predictions[f"{name}_alert"])})

    instance_keys = ["source_file", "group", "process_pid", "process_create_time"]
    instances = None
    if all(key in data for key in instance_keys) and not data[instance_keys].isna().any().any():
        group = predictions.groupby(instance_keys, dropna=False, sort=False)
        if group.label.nunique().gt(1).any():
            raise ValueError("Cùng process instance trong một nguồn có nhãn mâu thuẫn.")
        instances = group.agg(label=("label", "first"), snapshots=("label", "size"),
                              **{column: (column, "max") for column in score_columns.values()}).reset_index()
        for name, column in score_columns.items():
            metrics.append({"detector": name, "unit": "process_instance_within_source_any_alert",
                            **detection_metrics(instances.label, instances[column] >= ALERT_THRESHOLD)})
    report = {"schema_version": 1, "created_at_utc": datetime.now(timezone.utc).isoformat(),
              "sources": provenance, "threshold": ALERT_THRESHOLD,
              "ml_available": bool(scorer.bundle), "model_sha256": bundle_hash,
              "model_name": scorer.bundle.get("name") if scorer.bundle else None,
              "overlap_audit": overlap, "metrics": metrics,
              "notes": ["Labels are operator supplied; VM isolation and behavior are not independently attested.",
                        "Scores are recomputed from supplied features, not copied from recorded alert columns.",
                        "Snapshot rows are correlated. Any-alert metrics group a process instance within each CSV source.",
                        "Known executable paths may occur in new sessions; this is not unseen-executable generalization.",
                        "Identity checks cannot establish independence across VMs or missing process metadata.",
                        "Null metrics have an empty denominator; no ML metrics are emitted without a PID model."]}
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    predictions.to_csv(output / "predictions.csv", index=False)
    if instances is not None:
        instances.to_csv(output / "process_instances.csv", index=False)
    pd.DataFrame([{k: v for k, v in row.items() if k != "confusion_matrix"} for row in metrics]).to_csv(
        output / "detection_metrics.csv", index=False)
    (output / "evaluation.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report
