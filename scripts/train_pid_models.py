"""Train per-process classifiers on manually labeled live/lab observations."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from process_guard.pid_ml import train_labeled_samples
from process_guard.pid_visualization import plot_pid_training_results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, nargs="+", default=[ROOT / "data/observations/collected_samples.csv"],
                        help="One or more labeled observation CSV files")
    parser.add_argument("--model-dir", type=Path, default=ROOT / "artifacts/models/pid_live")
    parser.add_argument("--report-dir", type=Path, default=ROOT / "artifacts/reports/pid_live")
    parser.add_argument("--active-model", choices=["decision_tree", "random_forest", "extra_trees"],
                        help="override the CV-selected live model (e.g. when false positives matter most)")
    parser.add_argument("--override-reason", default="", help="why the override was chosen; stored in dataset_summary.json")
    args = parser.parse_args()
    try:
        result = train_labeled_samples(args.source, args.model_dir, args.report_dir)
        plot_pid_training_results(args.report_dir)
        if args.active_model:
            selected = (args.model_dir / "active_model.txt").read_text(encoding="utf-8").strip()
            (args.model_dir / "active_model.txt").write_text(args.active_model + ".joblib", encoding="utf-8")
            # Separate file: dataset_summary.json is fingerprinted by the evaluation tool.
            (args.report_dir / "active_model_override.json").write_text(json.dumps(
                {"cv_selected": selected, "active": args.active_model + ".joblib", "reason": args.override_reason},
                ensure_ascii=False, indent=2), encoding="utf-8")
    except (ValueError, OSError) as exc:
        parser.exit(1, f"Không huấn luyện được: {exc}\n")
    print(result.to_string(index=False, float_format=lambda value: f"{value:.4f}"))
    print("Per-file grouped split used. These metrics are only as reliable as the manually supplied labels.")
