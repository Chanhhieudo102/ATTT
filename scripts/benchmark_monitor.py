"""Record long-running ProcessGuard collector resource metrics to CSV/JSON."""
from __future__ import annotations

import argparse
import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import platform
import sys
import time

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from process_guard.collector import ProcessCollector


def _atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def benchmark(duration_seconds: int, interval_seconds: float, output: Path,
              target_pid: int | None = None) -> tuple[Path, Path]:
    if output.suffix.casefold() != ".csv":
        raise ValueError("Benchmark output must be a .csv path")
    output.parent.mkdir(parents=True, exist_ok=True)
    metadata_path = output.with_suffix(".json")
    if output.exists() or metadata_path.exists():
        raise FileExistsError(f"Không ghi đè benchmark cũ: {output} hoặc {metadata_path} đã tồn tại")
    monitor = psutil.Process(target_pid or os.getpid())
    monitor_identity = monitor.create_time()
    monitor_name = monitor.name()
    collector = ProcessCollector()
    host_cpu_count = psutil.cpu_count(logical=True) or 1
    started_utc = datetime.now(timezone.utc)
    started_monotonic = time.monotonic()
    metadata = {
        "schema_version": 1,
        "status": "running",
        "started_at_utc": started_utc.isoformat(timespec="seconds"),
        "ended_at_utc": None,
        "duration_requested_seconds": duration_seconds,
        "interval_seconds": interval_seconds,
        "host": platform.node(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "logical_cpu_count": host_cpu_count,
        "monitored_process": {"pid": monitor.pid, "name": monitor_name,
                              "create_time_epoch": monitor_identity},
        "csv_path": str(output.resolve()),
        "sample_count": 0,
        "errors": [],
        "note": "Collector-only benchmark; does not execute lab behavior or label processes.",
    }
    _atomic_json(metadata_path, metadata)
    monitor.cpu_percent(interval=None)
    psutil.cpu_percent(interval=None)
    sample_count = 0
    error_count = 0
    next_sample = time.monotonic()
    status = "completed"
    columns = ["sample", "timestamp_utc", "elapsed_seconds", "scan_ms", "process_count",
               "monitor_cpu_percent", "monitor_rss_mb", "host_cpu_percent",
               "host_memory_percent", "host_memory_used_mb"]
    measures = {name: {"count": 0, "sum": 0.0, "min": None, "max": None}
                for name in columns if name in {"scan_ms", "monitor_cpu_percent", "monitor_rss_mb",
                                               "host_cpu_percent", "host_memory_percent",
                                               "host_memory_used_mb"}}
    try:
        with output.open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=columns)
            writer.writeheader()
            stream.flush()
            while True:
                now = time.monotonic()
                elapsed = now - started_monotonic
                if elapsed >= duration_seconds:
                    break
                scan_started = time.perf_counter()
                try:
                    records = collector.snapshot()
                    scan_ms = (time.perf_counter() - scan_started) * 1000
                    if abs(monitor.create_time() - monitor_identity) > 0.01:
                        raise psutil.NoSuchProcess(monitor.pid)
                    monitor_cpu = monitor.cpu_percent(interval=None)
                    monitor_rss_mb = monitor.memory_info().rss / (1024 * 1024)
                    host_cpu = psutil.cpu_percent(interval=None)
                    memory = psutil.virtual_memory()
                    row = {
                        "sample": sample_count + 1,
                        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                        "elapsed_seconds": round(elapsed, 3),
                        "scan_ms": round(scan_ms, 3),
                        "process_count": len(records),
                        "monitor_cpu_percent": round(monitor_cpu, 3),
                        "monitor_rss_mb": round(monitor_rss_mb, 3),
                        "host_cpu_percent": round(host_cpu, 3),
                        "host_memory_percent": round(float(memory.percent), 3),
                        "host_memory_used_mb": round(memory.used / (1024 * 1024), 3),
                    }
                    writer.writerow(row)
                    sample_count += 1
                    for key, aggregate in measures.items():
                        value = float(row[key])
                        aggregate["count"] += 1
                        aggregate["sum"] += value
                        aggregate["min"] = value if aggregate["min"] is None else min(aggregate["min"], value)
                        aggregate["max"] = value if aggregate["max"] is None else max(aggregate["max"], value)
                    stream.flush()
                except (psutil.Error, OSError, RuntimeError, ValueError) as exc:
                    error_count += 1
                    if len(metadata["errors"]) < 100:
                        metadata["errors"].append({
                            "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                            "error": f"{type(exc).__name__}: {exc}"[:500],
                        })
                    if isinstance(exc, psutil.NoSuchProcess):
                        status = "target_exited_or_pid_reused"
                        break
                next_sample += interval_seconds
                delay = next_sample - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                else:
                    # Avoid an unbounded burst of catch-up scans if collection
                    # takes longer than the configured interval.
                    next_sample = time.monotonic()
    except KeyboardInterrupt:
        status = "interrupted"
    except Exception:
        status = "failed"
        raise
    finally:
        metadata.update({
            "status": status,
            "ended_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_actual_seconds": round(time.monotonic() - started_monotonic, 3),
            "sample_count": sample_count,
            "collection_error_count": error_count,
            "summary": {key: {
                "mean": round(values["sum"] / values["count"], 4) if values["count"] else None,
                "min": round(values["min"], 4) if values["count"] else None,
                "max": round(values["max"], 4) if values["count"] else None,
            } for key, values in measures.items()},
        })
        _atomic_json(metadata_path, metadata)
    return output, metadata_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration-hours", type=float, default=1.0,
                        help="benchmark duration in hours (0.1..168; default 1 hour)")
    parser.add_argument("--interval-seconds", type=float, default=3.0,
                        help="snapshot interval in seconds (1..60; default 3)")
    parser.add_argument("--output", type=Path, default=None,
                        help="CSV path; default artifacts/reports/live_benchmark/<timestamp>.csv")
    parser.add_argument("--target-pid", type=int, default=None,
                        help="optional PID of the already-running desktop/web monitor to measure; default measures this collector")
    args = parser.parse_args()
    if not 0.1 <= args.duration_hours <= 168:
        parser.error("--duration-hours must be between 0.1 and 168")
    if not 1 <= args.interval_seconds <= 60:
        parser.error("--interval-seconds must be between 1 and 60")
    if args.target_pid is not None and args.target_pid <= 0:
        parser.error("--target-pid must be a positive process ID")
    output = args.output
    if output is None:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        output = ROOT / "artifacts/reports/live_benchmark" / f"monitor_{stamp}.csv"
    else:
        output = output.expanduser().resolve()
    csv_path, metadata_path = benchmark(round(args.duration_hours * 3600), args.interval_seconds,
                                        output, args.target_pid)
    print(f"Benchmark complete. Samples: {json.loads(metadata_path.read_text(encoding='utf-8'))['sample_count']}")
    print(f"CSV: {csv_path}")
    print(f"Metadata: {metadata_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
