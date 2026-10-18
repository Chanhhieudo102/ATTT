"""Regenerate Cardiff training plots from existing CSV/JSON reports."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from process_guard.visualization import plot_cardiff_training_results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path, default=ROOT / "artifacts/reports/cardiff")
    args = parser.parse_args()
    generated = plot_cardiff_training_results(args.report_dir)
    if not generated:
        parser.error(f"No plot inputs found in {args.report_dir}; train the Cardiff models first.")
    for path in generated:
        print(f"Saved {path}")
