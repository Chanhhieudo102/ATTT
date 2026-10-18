"""Run a safe, console-only demonstration using synthetic process records."""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from process_guard.demo import demo_records
from process_guard.features import FEATURE_COLUMNS, extract_features
from process_guard.ml import ModelScorer, train_all
from process_guard.rules import evaluate_rules
from scripts.generate_demo_data import generate


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    scorer = ModelScorer(ROOT / "artifacts/models/synthetic_demo", allow_synthetic_demo=True)
    if scorer.bundle is None or scorer.bundle.get("features") != FEATURE_COLUMNS:
        print("Creating the explicitly synthetic PID demo dataset and training its demo model...")
        train_all(generate())
        scorer = ModelScorer(ROOT / "artifacts/models/synthetic_demo", allow_synthetic_demo=True)
    print("PROCESSGUARD SAFE DEMO — fixtures only; no process or payload is started")
    print(f"{'PID':>5}  {'NAME':<18} {'RULE':>7} {'ML demo':>8} {'combined':>9}  Signals")
    records = demo_records()
    model_results = scorer.score_many(records)
    for row, (ml_score, model_name) in zip(records, model_results):
        features = extract_features(row)
        rule_score, reasons = evaluate_rules(row, features)
        score = max(rule_score, ml_score)
        print(f"{row['pid']:>5}  {row['name']:<18} {rule_score:>6.1%} {ml_score:>7.1%} "
              f"{score:>8.1%}  {'; '.join(reasons) or 'no rule triggered'}")
        row["_demo_model"] = model_name
    print("\nCaution: the PID demo model is trained on generated teaching examples; its metrics are not research results.")
    print("For the paper dataset, use: python scripts/train_models.py --seconds 5")
    print("For the GUI: python main.py --demo")


if __name__ == "__main__":
    main()
