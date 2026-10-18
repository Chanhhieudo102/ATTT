"""Train per-process classifiers on manually labeled live/lab observations."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from process_guard.pid_ml import train_labeled_samples


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "data/observations/collected_samples.csv")
    args = parser.parse_args()
    result = train_labeled_samples(args.source)
    print(result.to_string(index=False, float_format=lambda value: f"{value:.4f}"))
    print("Per-file grouped split used. These metrics are only as reliable as the manually supplied labels.")
