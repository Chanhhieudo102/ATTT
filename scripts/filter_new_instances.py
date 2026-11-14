"""Keep only process instances (PID + create_time) that never appeared in a training manifest.

Long-running benign processes (svchost, browser...) are often sampled in both training and
evaluation sessions. ``evaluate_pid_sessions.py`` correctly refuses such overlap, so this tool
writes ``<name>_new_instances.csv`` copies that contain only unseen process instances.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True, help="split_manifest.csv of the trained model")
    parser.add_argument("--source", type=Path, nargs="+", required=True)
    args = parser.parse_args()
    manifest = pd.read_csv(args.manifest)
    seen = set(zip(manifest["process_pid"].astype(int), manifest["process_create_time"].round(2)))
    for source in args.source:
        data = pd.read_csv(source)
        keys = list(zip(data["process_pid"].astype(int), data["process_create_time"].round(2)))
        keep = [key not in seen for key in keys]
        output = source.with_name(source.stem + "_new_instances.csv")
        if output.exists():
            raise SystemExit(f"{output} đã tồn tại; không ghi đè.")
        data[keep].to_csv(output, index=False)
        print(f"{source.name}: giữ {sum(keep)}/{len(data)} snapshot, "
              f"{data[keep]['process_pid'].nunique()} process instance mới -> {output.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
