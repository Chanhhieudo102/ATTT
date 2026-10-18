"""Backward-compatible entry point for Cardiff dataset model evaluation."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.train_cardiff_models import train


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train and compare ML models on Cardiff Dataset 2.")
    parser.add_argument("--source", type=Path, default=ROOT / "data/raw/cardiff_data_2.csv")
    parser.add_argument("--seconds", type=int, default=5)
    args = parser.parse_args()
    result = train(args.source, args.seconds)
    print(result.to_string(index=False, float_format=lambda value: f"{value:.4f}"))
