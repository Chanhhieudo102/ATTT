"""Bounded local-only workload for observing a child process in an isolated VM.

This is not malware and does not implement persistence, injection, remote access,
or external networking. It writes a capped dummy file inside a temporary folder,
uses CPU for a short bounded interval, and exchanges data over loopback only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

CHUNK = (b"PROCESSGUARD SAFE LAB DATA\n" * 2048)[:64 * 1024]


def _worker(port: int, duration: int, write_mb: int, output_dir: str) -> int:
    temp_root = os.path.normcase(os.path.abspath(tempfile.gettempdir()))
    resolved_dir = os.path.normcase(os.path.abspath(output_dir))
    try:
        inside_temp = os.path.commonpath((temp_root, resolved_dir)) == temp_root
    except ValueError:
        inside_temp = False
    if not inside_temp or not Path(resolved_dir).name.startswith("processguard_safe_lab_"):
        print("Worker output must be inside its ProcessGuard temporary directory.", file=sys.stderr)
        return 2
    destination = Path(resolved_dir) / "dummy_activity.bin"
    stop_at = time.monotonic() + duration
    byte_limit = write_mb * 1024 * 1024
    bytes_written = 0
    seed = b"ProcessGuard local lab CPU sample"
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
            connection.settimeout(1)
            with destination.open("wb") as output:
                while time.monotonic() < stop_at:
                    if bytes_written < byte_limit:
                        block = CHUNK[:min(len(CHUNK), byte_limit - bytes_written)]
                        output.write(block)
                        output.flush()
                        bytes_written += len(block)
                    # A small bounded CPU workload, not an evasion or payload routine.
                    for _ in range(1800):
                        seed = hashlib.sha256(seed).digest()
                    connection.sendall(b"PG-LAB\n")
                    if connection.recv(16) != b"ACK\n":
                        break
    except (OSError, TimeoutError) as exc:
        print(f"Lab worker stopped: {exc}", file=sys.stderr)
        return 2
    print(f"Lab worker finished; wrote {bytes_written} bytes to temporary storage.")
    return 0


def _serve(listener: socket.socket, finished: threading.Event) -> None:
    listener.settimeout(0.5)
    while not finished.is_set():
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        with connection:
            connection.settimeout(0.5)
            while not finished.is_set():
                try:
                    payload = connection.recv(64)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if not payload:
                    return
                try:
                    connection.sendall(b"ACK\n")
                except OSError:
                    return
            return


def _write_run_log(log_path: Path, report: dict) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if log_path.exists():
        raise FileExistsError(f"Refusing to overwrite existing run evidence: {log_path}")
    temporary = log_path.with_suffix(log_path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(log_path)


def run_parent(duration: int, write_mb: int, log_path: Path) -> int:
    with tempfile.TemporaryDirectory(prefix="processguard_safe_lab_") as temp_dir:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        finished = threading.Event()
        server = threading.Thread(target=_serve, args=(listener, finished), daemon=True)
        server.start()
        command = [sys.executable, str(Path(__file__).resolve()), "--worker",
                   "--port", str(port), "--duration", str(duration),
                   "--write-mb", str(write_mb), "--output-dir", temp_dir]
        started_at = datetime.now(timezone.utc)
        started_monotonic = time.monotonic()
        child = subprocess.Popen(command, close_fds=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
        print("Safe lab workload started. No payload, persistence, process injection, or external network is used.")
        print(f"Child PID: {child.pid}; duration cap: {duration}s; dummy-write cap: {write_mb} MiB.")
        print("Start ProcessGuard in another terminal and inspect this child while it runs.")
        try:
            return_code = child.wait(timeout=duration + 5)
        except subprocess.TimeoutExpired:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
            return_code = 124
        finally:
            stdout, stderr = child.communicate()
            finished.set()
            listener.close()
            server.join(timeout=1)
        print("Temporary lab files were removed when the workload ended.")
        report = {
            "schema_version": 1,
            "scenario": "bounded_cpu_dummy_file_loopback",
            "started_at_utc": started_at.isoformat(timespec="seconds"),
            "ended_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_actual_seconds": round(time.monotonic() - started_monotonic, 3),
            "duration_limit_seconds": duration,
            "dummy_write_limit_mib": write_mb,
            "child_pid": child.pid,
            "exit_code": return_code,
            "network_scope": "127.0.0.1 loopback only",
            "persistence_or_injection": False,
            "payload_or_real_malware": False,
            "temporary_data_removed": True,
            "vm_isolation_verified_by_script": False,
            "operator_note": "This script cannot verify VM isolation. Capture screenshots in the isolated VM and keep them with this log.",
            "stdout": stdout[-4000:],
            "stderr": stderr[-4000:],
        }
        _write_run_log(log_path, report)
        print(f"Run evidence log: {log_path}")
        return return_code


def main() -> int:
    parser = argparse.ArgumentParser(description="Short local-only ProcessGuard lab stimulus")
    parser.add_argument("--duration", type=int, default=10, help="seconds; allowed range 3..15")
    parser.add_argument("--write-mb", type=int, default=8, help="temporary dummy data; allowed range 1..16 MiB")
    parser.add_argument("--log-file", type=Path, default=None,
                        help="JSON run log path; default artifacts/reports/lab_runs/safe_behavior_<timestamp>.json")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--output-dir", default="", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not 3 <= args.duration <= 15:
        parser.error("--duration must be between 3 and 15 seconds")
    if not 1 <= args.write_mb <= 16:
        parser.error("--write-mb must be between 1 and 16 MiB")
    if args.worker:
        if not args.port or not args.output_dir:
            parser.error("internal worker arguments are missing")
        return _worker(args.port, args.duration, args.write_mb, args.output_dir)
    log_path = args.log_file
    if log_path is None:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        log_path = Path(__file__).resolve().parents[1] / "artifacts" / "reports" / "lab_runs" / f"safe_behavior_{stamp}.json"
    log_path = log_path.expanduser().resolve()
    if log_path.exists():
        parser.error(f"refusing to overwrite existing run log: {log_path}")
    return run_parent(args.duration, args.write_mb, log_path)


if __name__ == "__main__":
    raise SystemExit(main())
