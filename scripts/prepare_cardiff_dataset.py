"""Prepare the official Cardiff time-series CSV into sample-level sequences."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np
from process_guard.cardiff import make_sequences


def prepare(source: Path, output: Path = ROOT / "data/processed/cardiff_5s_sequences.npz", seconds: int = 5) -> Path:
    X, y, is_test, sample_ids, metrics = make_sequences(source, seconds=seconds)
    output.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(output, X=X, y=y, is_test=is_test, sample_ids=sample_ids,
                        metrics=np.asarray(metrics), seconds=np.asarray(seconds))
    print(f"Samples: {len(y)} | train: {(~is_test).sum()} | test: {is_test.sum()}")
    print(f"Benign: {(y == 0).sum()} | malicious: {(y == 1).sum()} | window: first {seconds} seconds")
    print(f"Saved: {output}")
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=ROOT / "data/raw/cardiff_data_2.csv")
    parser.add_argument("--output", type=Path, default=ROOT / "data/processed/cardiff_5s_sequences.npz")
    parser.add_argument("--seconds", type=int, default=5)
    args = parser.parse_args()
    prepare(args.source, args.output, args.seconds)
