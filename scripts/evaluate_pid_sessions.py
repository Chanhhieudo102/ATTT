"""Recompute rules/ML/combined metrics on new, operator-labeled lab sessions."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from process_guard.pid_evaluation import evaluate_observations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, nargs="+", required=True)
    parser.add_argument("--model-dir", type=Path, default=ROOT / "artifacts/models/pid_live")
    parser.add_argument("--training-report-dir", type=Path, default=ROOT / "artifacts/reports/pid_live")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    output = args.output or ROOT / "artifacts/reports/pid_evaluation" / stamp
    try:
        report = evaluate_observations(args.source, output, args.model_dir, args.training_report_dir)
    except (ValueError, OSError) as exc:
        parser.exit(1, f"Không đánh giá được: {exc}\n")
    print(f"ML available: {report['ml_available']}; report: {output.resolve()}")


if __name__ == "__main__":
    main()
