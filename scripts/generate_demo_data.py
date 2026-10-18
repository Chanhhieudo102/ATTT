"""Create clearly labeled synthetic telemetry; no malware or payload is used."""
from __future__ import annotations

import argparse
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pandas as pd

from process_guard.features import FEATURE_COLUMNS


def generate(path: str | Path = ROOT / "data/fixtures/synthetic_demo/process_samples_synthetic.csv",
             rows_per_class: int = 700, seed: int = 17) -> Path:
    rng = random.Random(seed)
    samples = []
    for label in (0, 1):
        for _ in range(rows_per_class):
            malicious = label == 1
            row = {
                "path_is_system": int(not malicious and rng.random() < .55),
                "path_is_user_writable": int(malicious or rng.random() < .3),
                "path_is_temp": int(malicious and rng.random() < .62),
                "path_is_missing": int(rng.random() < (.02 if not malicious else .08)),
                "name_similarity_risk": int(malicious and rng.random() < .18),
                "filename_entropy": rng.uniform(2.0, 3.8) if not malicious else rng.uniform(2.7, 4.6),
                "command_length": rng.randint(0, 100) if not malicious else rng.randint(20, 420),
                "unsigned_hint": int(malicious and rng.random() < .48),
                "cpu_percent": min(100, rng.expovariate(1 / (12 if not malicious else 38))),
                "memory_percent": min(40, rng.expovariate(1 / (1.8 if not malicious else 5.0))),
                "thread_count": max(1, int(rng.gauss(9 if not malicious else 18, 6))),
                "handle_count": max(1, int(rng.gauss(90 if not malicious else 180, 60))),
                "connection_count": min(35, int(rng.expovariate(1 / (1.2 if not malicious else 7)))),
                "child_count": min(20, int(rng.expovariate(1 / (1.0 if not malicious else 3.5)))),
                "file_read_rate_kbps": min(8000, rng.expovariate(1 / (45 if not malicious else 320))),
                "file_write_rate_kbps": min(8000, rng.expovariate(1 / (30 if not malicious else 420))),
                "parent_is_script_host": int(malicious and rng.random() < .22),
                "runtime_minutes": rng.uniform(0, 600),
                "label": label,
                "label_name": "benign_synthetic" if label == 0 else "simulated_malicious_synthetic",
            }
            samples.append(row)
    frame = pd.DataFrame(samples)
    # Derived teaching features mirror what the live collector/enrichment can provide.
    frame["path_is_program_files"] = (
        (frame["label"] == 0) & (frame["path_is_system"] == 0)
        & (frame["path_is_user_writable"] == 0)
    ).astype(int)
    frame["path_category_missing"] = frame["path_is_missing"].astype(int)
    frame["path_category_temp"] = (
        (frame["path_category_missing"] == 0) & (frame["path_is_temp"] == 1)
    ).astype(int)
    frame["path_category_windows"] = (
        (frame["path_category_missing"] == 0) & (frame["path_category_temp"] == 0)
        & (frame["path_is_system"] == 1)
    ).astype(int)
    frame["path_category_program_files"] = (
        (frame["path_category_missing"] == 0) & (frame["path_category_temp"] == 0)
        & (frame["path_category_windows"] == 0) & (frame["path_is_program_files"] == 1)
    ).astype(int)
    frame["path_category_other"] = 1 - frame[[
        "path_category_missing", "path_category_temp", "path_category_windows",
        "path_category_program_files",
    ]].sum(axis=1)
    frame["signature_checked"] = [int(rng.random() < 0.8) for _ in range(len(frame))]
    frame["unsigned_hint"] = frame["unsigned_hint"] * frame["signature_checked"]
    frame["signature_valid"] = frame["signature_checked"] * (1 - frame["unsigned_hint"])
    frame["registry_run_persistence"] = [
        int(label == 1 and rng.random() < 0.18) for label in frame["label"]
    ]
    frame["scheduled_task_checked"] = [int(rng.random() < 0.65) for _ in frame["label"]]
    frame["scheduled_task_persistence"] = [
        int(label == 1 and rng.random() < 0.08) for label in frame["label"]
    ]
    frame["sysmon_registry_run_hint"] = [
        int(label == 1 and rng.random() < 0.08) for label in frame["label"]
    ]
    frame["sysmon_remote_memory_access_hint"] = [
        int(label == 1 and rng.random() < 0.12) for label in frame["label"]
    ]
    frame["sysmon_remote_thread_hint"] = [
        int(label == 1 and rng.random() < 0.08) for label in frame["label"]
    ]
    frame["sysmon_process_tampering_hint"] = [
        int(label == 1 and rng.random() < 0.05) for label in frame["label"]
    ]
    frame["sysmon_file_create_events"] = [
        rng.randint(12, 40) if label == 1 and rng.random() < 0.20
        else rng.randint(0, 8) for label in frame["label"]
    ]
    frame["sysmon_dns_query_events"] = [
        rng.randint(8, 24) if label == 1 and rng.random() < 0.18
        else rng.randint(0, 7) for label in frame["label"]
    ]
    frame["cpu_avg_percent"] = frame["cpu_percent"] * 0.75
    frame["cpu_peak_percent"] = (frame["cpu_percent"] * 1.25).clip(upper=100)
    frame["memory_avg_percent"] = frame["memory_percent"] * 0.9
    frame["memory_peak_percent"] = frame["memory_percent"] * 1.1
    frame["file_read_ops_per_sec"] = frame["file_read_rate_kbps"] * 0.25
    frame["file_write_ops_per_sec"] = frame["file_write_rate_kbps"] * 0.25
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(path, index=False)
    print(f"Wrote {len(frame)} synthetic rows to {path.resolve()}")
    print("Labels are synthetic teaching examples, not observations of real malware.")
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(ROOT / "data/fixtures/synthetic_demo/process_samples_synthetic.csv"))
    parser.add_argument("--rows-per-class", type=int, default=700)
    parser.add_argument("--seed", type=int, default=17)
    args = parser.parse_args()
    generate(args.output, args.rows_per_class, args.seed)
