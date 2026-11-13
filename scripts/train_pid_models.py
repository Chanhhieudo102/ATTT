"""Train per-process classifiers on manually labeled live/lab observations."""
from __future__ import annotations

import argparse
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
    args = parser.parse_args()
    try:
        result = train_labeled_samples(args.source, args.model_dir, args.report_dir)
        plot_pid_training_results(args.report_dir)
    except (ValueError, OSError) as exc:
        parser.exit(1, f"Không huấn luyện được: {exc}\n")
    print(result.to_string(index=False, float_format=lambda value: f"{value:.4f}"))
    print("Per-file grouped split used. These metrics are only as reliable as the manually supplied labels.")
