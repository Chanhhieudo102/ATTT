"""Local, read-only web dashboard for ProcessGuard (Python standard library only)."""
from __future__ import annotations

import argparse
import json
import threading
import time
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
import psutil

from process_guard.collector import ProcessCollector
from process_guard.demo import demo_records
from process_guard.features import extract_features
from process_guard.ml import ModelScorer
from process_guard.rules import evaluate_rules

WEB_DIR = ROOT / "apps/web/static"


class DashboardData:
    """Maintain one snapshot so concurrent browser polls do not rescan processes."""

    def __init__(self, initial_mode: str = "live"):
        self.collector = ProcessCollector()
        self.monitor_process = psutil.Process()
        self.live_scorer = ModelScorer(ROOT / "artifacts/models/pid_live", allowed_sources={"observed-per-process"})
        self.demo_scorer = ModelScorer(ROOT / "artifacts/models/synthetic_demo", allow_synthetic_demo=True)
        self.mode = initial_mode
        self.initial_mode = initial_mode
        self.lock = threading.Lock()
        self.data: dict[str, dict] = {}
        self.performance_samples: deque[dict] = deque(maxlen=1200)
        self._logged_alerts: set[tuple[str, int, str]] = set()
        self._last_model_check = 0.0
        self._model_stamp = self._get_model_stamp()
        self._worker = threading.Thread(target=self._run, daemon=True, name="processguard-snapshot")
        self._worker.start()

    @staticmethod
    def _get_model_stamp() -> tuple[int, int]:
        stamps = []
        for path in (ROOT / "artifacts/models/pid_live/active_model.txt",
                     ROOT / "artifacts/models/synthetic_demo/active_model.txt"):
            try:
                stamps.append(path.stat().st_mtime_ns)
            except OSError:
                stamps.append(0)
        return tuple(stamps)

    def _reload_models_if_needed(self) -> None:
        now = time.monotonic()
        if now - self._last_model_check < 10:
            return
        self._last_model_check = now
        stamp = self._get_model_stamp()
        if stamp != self._model_stamp:
            self.live_scorer = ModelScorer(ROOT / "artifacts/models/pid_live", allowed_sources={"observed-per-process"})
            self.demo_scorer = ModelScorer(ROOT / "artifacts/models/synthetic_demo", allow_synthetic_demo=True)
            self._model_stamp = stamp

    def _run(self) -> None:
        while True:
            started = time.perf_counter()
            try:
                self._reload_models_if_needed()
                live_rows = self._score_rows(self.collector.snapshot(), demo=False)
                demo_rows = self._score_rows(demo_records(), demo=True)
                try:
                    app_cpu = self.monitor_process.cpu_percent(interval=None)
                    app_memory_mb = self.monitor_process.memory_info().rss / (1024 * 1024)
                except psutil.Error:
                    app_cpu, app_memory_mb = 0.0, 0.0
                elapsed_ms = (time.perf_counter() - started) * 1000
                try:
                    host_cpu = psutil.cpu_percent(interval=None)
                    host_memory = psutil.virtual_memory().percent
                except (psutil.Error, OSError):
                    host_cpu, host_memory = 0.0, 0.0
                snapshot = {
                    "live": self._payload("live", live_rows, host_cpu, host_memory,
                                          app_cpu, app_memory_mb, elapsed_ms),
                    "demo": self._payload("demo", demo_rows, host_cpu, host_memory,
                                          app_cpu, app_memory_mb, elapsed_ms),
                }
                with self.lock:
                    self.performance_samples.append({
                        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
                        "scan_ms": elapsed_ms,
                        "process_count": len(live_rows),
                        "app_cpu_percent": app_cpu,
                        "app_memory_mb": app_memory_mb,
                        "host_cpu_percent": host_cpu,
                        "host_memory_percent": host_memory,
                    })
                    self.data = snapshot
            except Exception as exc:  # keep the local dashboard alive after an intermittent scan error
                with self.lock:
                    self.data["error"] = str(exc)
            time.sleep(max(0.2, 3.0 - (time.perf_counter() - started)))

    def _score_rows(self, records: list[dict], demo: bool) -> list[dict]:
        rows = []
        scorer = self.demo_scorer if demo else self.live_scorer
        has_model = demo or bool(scorer.bundle)
        model_results = (scorer.score_many(records) if has_model else
                         [(0.0, "Chưa có model PID đã huấn luyện") for _ in records])
        for record, (ml_score, model_name) in zip(records, model_results):
            features = extract_features(record)
            rule_score, reasons = evaluate_rules(record, features)
            score = max(rule_score, ml_score) if has_model else rule_score
            item = {key: value for key, value in record.items() if not key.startswith("_")}
            item.update({"rule_score": rule_score, "ml_score": ml_score, "score": score,
                         "model_name": model_name, "reasons": reasons, "demo_only": demo})
            rows.append(item)
            if score >= 0.65:
                identity = ("demo" if demo else "live", int(item["pid"]),
                            "demo" if demo else str(item.get("create_time", "")))
                if identity not in self._logged_alerts:
                    self._write_alert(item)
                    self._logged_alerts.add(identity)
        active = {(("demo" if demo else "live"), int(item["pid"]),
                   "demo" if demo else str(item.get("create_time", "")))
                  for item in rows}
        mode_key = "demo" if demo else "live"
        self._logged_alerts = {entry for entry in self._logged_alerts
                               if entry[0] != mode_key or entry in active}
        return self._tree_order(rows)

    @staticmethod
    def _tree_order(rows: list[dict]) -> list[dict]:
        by_pid = {int(row["pid"]): row for row in rows}
        children: dict[int, list[int]] = {}
        for row in rows:
            children.setdefault(int(row.get("ppid", 0)), []).append(int(row["pid"]))
        roots = [int(row["pid"]) for row in rows
                 if int(row.get("ppid", 0)) not in by_pid or int(row.get("ppid", 0)) == int(row["pid"])]
        result, visited = [], set()

        def visit(pid: int, depth: int) -> None:
            if pid in visited or pid not in by_pid:
                return
            visited.add(pid)
            row = by_pid[pid]
            row["depth"] = min(depth, 12)
            result.append(row)
            for child in sorted(children.get(pid, [])):
                visit(child, depth + 1)

        for root_pid in sorted(roots):
            visit(root_pid, 0)
        for pid in sorted(by_pid):
            visit(pid, 0)
        return result

    @staticmethod
    def _payload(mode: str, rows: list[dict], host_cpu: float, host_memory: float,
                 app_cpu: float, app_memory_mb: float, elapsed_ms: float) -> dict:
        alerts = sum(row["score"] >= 0.65 for row in rows)
        return {
            "mode": mode,
            "updated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "processes": rows,
            "summary": {"process_count": len(rows), "alert_count": alerts,
                        "host_cpu": host_cpu, "host_memory": host_memory,
                        "app_cpu": app_cpu, "app_memory_mb": app_memory_mb,
                        "scan_ms": elapsed_ms},
            "model": ("Synthetic PID demo" if mode == "demo" else
                      ("PID model + rules" if rows and rows[0]["model_name"] != "Chưa có model PID đã huấn luyện"
                       else "Rules (chưa có PID model lab)")),
            "notice": ("Dữ liệu process tổng hợp; không có tiến trình hoặc payload nào được chạy."
                       if mode == "demo" else
                       "Live monitoring trên máy này. Điểm cảnh báo là tín hiệu cần kiểm tra, không phải kết luận malware."),
        }

    @staticmethod
    def _write_alert(row: dict) -> None:
        path = ROOT / "artifacts/logs/detections.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        event = {"event": "web_suspicious_process", "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
                 "pid": row.get("pid"), "name": row.get("name"), "exe": row.get("exe"),
                 "score": row.get("score"), "rule_score": row.get("rule_score"),
                 "ml_score": row.get("ml_score"), "model": row.get("model_name"),
                 "reasons": row.get("reasons", []), "demo_only": row.get("demo_only", False)}
        try:
            with path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def snapshot(self, mode: str) -> dict:
        with self.lock:
            return self.data.get(mode, {"mode": mode, "processes": [], "summary": {},
                                        "model": "Đang khởi tạo", "notice": "Đang lấy snapshot đầu tiên..."})

    def performance_snapshot(self) -> list[dict]:
        with self.lock:
            return list(self.performance_samples)


class Handler(BaseHTTPRequestHandler):
    server_version = "ProcessGuardWeb/1.0"
    sys_version = ""
    service: DashboardData

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        request = urlparse(self.path)
        route = request.path
        if route == "/api/processes":
            mode = parse_qs(request.query).get("mode", ["live"])[0]
            if mode not in {"live", "demo"}:
                self._send(400, b'{"error":"mode must be live or demo"}', "application/json; charset=utf-8")
                return
            body = json.dumps(self.service.snapshot(mode), ensure_ascii=False).encode("utf-8")
            self._send(200, body, "application/json; charset=utf-8")
            return
        if route == "/api/research":
            self._send(200, json.dumps(self._research(), ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")
            return
        if route == "/api/events":
            self._send(200, json.dumps(self._events(), ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")
            return
        if route == "/api/performance":
            body = json.dumps(self.service.performance_snapshot(), ensure_ascii=False).encode("utf-8")
            self._send(200, body, "application/json; charset=utf-8")
            return
        assets = {"/styles.css": (WEB_DIR / "styles.css", "text/css; charset=utf-8"),
                  "/app.js": (WEB_DIR / "app.js", "text/javascript; charset=utf-8")}
        if route == "/":
            try:
                page = (WEB_DIR / "index.html").read_text(encoding="utf-8")
                page = page.replace('data-default-mode="live"',
                                    f'data-default-mode="{self.service.initial_mode}"')
                self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
            except OSError:
                self._send(500, b"Web assets are missing.", "text/plain; charset=utf-8")
            return
        if route in assets:
            path, content_type = assets[route]
            try:
                self._send(200, path.read_bytes(), content_type)
            except OSError:
                self._send(500, b"Web assets are missing.", "text/plain; charset=utf-8")
            return
        self._send(404, b"Not found", "text/plain; charset=utf-8")

    def do_POST(self) -> None:
        self._send(405, b'{"error":"read-only dashboard"}', "application/json; charset=utf-8")

    def _research(self) -> dict:
        path = ROOT / "artifacts/reports/cardiff/cardiff_model_comparison.csv"
        try:
            rows = pd.read_csv(path).fillna(0).to_dict(orient="records") if path.exists() else []
        except (OSError, pd.errors.ParserError):
            rows = []
        return {"dataset": "Cardiff Dataset 2", "paper": "Rhode, Burnap & Jones (2018)",
                "dataset_doi": "10.17035/d.2018.0050524986", "paper_doi": "10.1016/j.cose.2018.05.010",
                "granularity": "Executable-level machine telemetry in sandbox; not per-PID telemetry.",
                "metrics": rows, "has_report": bool(rows)}

    def _events(self) -> list[dict]:
        path = ROOT / "artifacts/logs/detections.jsonl"
        if not path.exists():
            return []
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-100:]
            return [json.loads(line) for line in reversed(lines) if line.strip()]
        except (OSError, json.JSONDecodeError):
            return []

    def log_message(self, format: str, *args) -> None:
        print(f"[{self.log_date_time_string()}] {self.address_string()} {format % args}")


def main() -> None:
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Run the local ProcessGuard web dashboard")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--demo", action="store_true", help="Open the dashboard in safe synthetic demo mode")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    service = DashboardData(initial_mode="demo" if args.demo else "live")
    handler = type("ProcessGuardHandler", (Handler,), {"service": service})
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler)
    print(f"ProcessGuard web đang chạy: http://127.0.0.1:{args.port}")
    print("Chỉ lắng nghe trên localhost; Ctrl+C để dừng.")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nĐã dừng ProcessGuard web.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
