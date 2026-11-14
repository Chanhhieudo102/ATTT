"""Record a labeled, bounded observation session for explicitly selected PIDs."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import psutil
from process_guard.collector import ProcessCollector
from process_guard.features import FEATURE_COLUMNS, extract_features
from process_guard.ml import ALERT_THRESHOLD, ModelScorer
from process_guard.rules import evaluate_rules


def collect(pids: list[int], label: int, label_source: str, duration: float,
            interval: float, output: Path) -> dict:
    if label not in (0, 1) or not label_source.strip():
        raise ValueError("Cần label 0/1 và label_source không rỗng.")
    if not math.isfinite(duration) or not 1 <= duration <= 86400:
        raise ValueError("Duration phải trong khoảng 1..86400 giây.")
    if not math.isfinite(interval) or not 0.2 <= interval <= duration:
        raise ValueError("Interval phải từ 0.2 giây và không vượt duration.")
    if not pids or any(pid <= 0 for pid in pids):
        raise ValueError("Cần ít nhất một PID dương.")
    output = output.resolve()
    metadata = output.with_suffix(".json")
    if output.suffix.lower() != ".csv" or output.exists() or metadata.exists():
        raise ValueError("Output phải là .csv mới; không ghi đè dữ liệu hoặc metadata cũ.")
    identities = {}
    unavailable = []
    for pid in dict.fromkeys(pids):
        try:
            proc = psutil.Process(pid)
            identity = {"create_time": proc.create_time(), "exe": proc.exe(), "name": proc.name()}
        except psutil.NoSuchProcess:
            unavailable.append(pid)  # exited before the session started; never label a recycled PID
            continue
        if not identity["exe"]:
            raise ValueError(f"Không đọc được executable của PID {pid}.")
        identities[pid] = identity
    if not identities:
        raise ValueError("Không còn PID nào đang chạy để thu thập.")
    collector = ProcessCollector()
    scorer = ModelScorer(ROOT / "artifacts/models/pid_live", allowed_sources={"observed-per-process"})
    fields = FEATURE_COLUMNS + ["label", "label_name", "label_source", "process_pid",
                               "process_create_time", "process_name", "process_path", "sampled_at",
                               "rule_score", "ml_score", "combined_score", "model_name"]
    report = {"schema_version": 1, "started_at_utc": datetime.now(timezone.utc).isoformat(),
              "status": "running", "label": label, "label_source": label_source.strip(),
              "requested_duration_seconds": duration, "interval_seconds": interval,
              "process_identities": identities, "unavailable_at_start": unavailable, "sample_count": 0, "skipped_snapshots": 0,
              "ml_available": bool(scorer.bundle), "alert_threshold": ALERT_THRESHOLD,
              "ml_alert_samples": 0, "combined_alert_samples": 0,
              "label_note": "Operator-provided label; script does not independently verify behavior or VM isolation.",
              "evaluation_note": "Repeated snapshots are correlated; counts are per observation, not independent trials. Rules+ML uses max(rule, ML)."}
    output.parent.mkdir(parents=True, exist_ok=True)

    def write_metadata():
        temporary = metadata.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(metadata)

    # Exclusive creation keeps separately collected sessions from overwriting one another.
    with output.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        stream.flush()
        started = time.monotonic()
        write_metadata()
        try:
            collector.snapshot()  # warm up CPU and I/O deltas before saving any observations
            next_scan = started + interval
            while time.monotonic() - started < duration:
                time.sleep(max(0, min(next_scan, started + duration) - time.monotonic()))
                if time.monotonic() - started >= duration:
                    break
                rows = collector.snapshot()
                selected = []
                active = False
                for pid, identity in identities.items():
                    try:
                        current = psutil.Process(pid)
                        if abs(current.create_time() - identity["create_time"]) > 0.01:
                            continue  # a recycled PID must never inherit the operator's label
                        if current.exe() != identity["exe"]:
                            continue
                        active = True
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    row = next((row for row in rows if row["pid"] == pid and
                                abs(row["create_time"] - identity["create_time"]) < 0.01 and
                                row["exe"] == identity["exe"]), None)
                    if row:
                        selected.append(row)
                    else:
                        report["skipped_snapshots"] += 1
                if not active:
                    report["status"] = "targets_exited_or_unavailable"
                    break
                scores = scorer.score_many(selected) if scorer.bundle else [(None, "Rules only")] * len(selected)
                for row, (ml_score, model_name) in zip(selected, scores):
                    features = extract_features(row)
                    rule_score, _ = evaluate_rules(row, features)
                    combined = max(rule_score, ml_score) if ml_score is not None else rule_score
                    writer.writerow({**features, "label": label,
                                     "label_name": "benign_observed" if label == 0 else "simulated_malicious_observed",
                                     "label_source": label_source.strip(), "process_pid": row["pid"],
                                     "process_create_time": row["create_time"], "process_name": row["name"],
                                     "process_path": row["exe"], "sampled_at": datetime.now(timezone.utc).isoformat(),
                                     "rule_score": rule_score, "ml_score": ml_score,
                                     "combined_score": combined, "model_name": model_name})
                    report["sample_count"] += 1
                    report["ml_alert_samples"] += int(ml_score is not None and ml_score >= ALERT_THRESHOLD)
                    report["combined_alert_samples"] += int(combined >= ALERT_THRESHOLD)
                stream.flush()
                write_metadata()
                next_scan = max(next_scan + interval, time.monotonic())
            if report["status"] == "running":
                report["status"] = "completed"
        except KeyboardInterrupt:
            report["status"] = "interrupted"
        except Exception as exc:
            report["status"] = "failed"
            report["error"] = str(exc)
            raise
        finally:
            report["ended_at_utc"] = datetime.now(timezone.utc).isoformat()
            report["elapsed_seconds"] = round(time.monotonic() - started, 3)
            write_metadata()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, nargs="+", required=True)
    parser.add_argument("--label", type=int, choices=[0, 1], required=True)
    parser.add_argument("--label-source", required=True, help="VM/scenario/log reference verified by the operator")
    parser.add_argument("--duration", type=float, default=60)
    parser.add_argument("--interval", type=float, default=3)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    output = args.output or ROOT / f"data/observations/session_{stamp}.csv"
    try:
        report = collect(args.pid, args.label, args.label_source, args.duration, args.interval, output)
    except (ValueError, OSError, psutil.Error) as exc:
        parser.exit(1, f"Không thu thập được: {exc}\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"Dataset: {output.resolve()}")
    return 0 if report["sample_count"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
