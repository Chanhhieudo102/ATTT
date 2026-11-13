"""Export PID dataset statistics and EDA figures without running any workload."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from process_guard.pid_visualization import analyze_observations


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, nargs="+", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or ROOT / "artifacts/reports/pid_eda" / datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    try:
        summary = analyze_observations(args.source, output)
    except (ValueError, OSError) as exc:
        parser.exit(1, f"Không phân tích được: {exc}\n")
    print(f"Snapshots: {summary['snapshot_count']}; EDA: {output.resolve()}")
