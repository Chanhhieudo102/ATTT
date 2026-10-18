from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
import psutil

from process_guard.collector import ProcessCollector
from process_guard.demo import demo_records
from process_guard.features import extract_features
from process_guard.ml import ModelScorer, train_all
from process_guard.pid_ml import train_labeled_samples
from process_guard.memory_inspection import inspect_private_executable_regions
from process_guard.procmon import aggregate_procmon_csv, match_live_process
from process_guard.procmon_capture import ProcMonCapture, ProcMonCaptureError, MAX_CAPTURE_SECONDS, MAX_BACKING_FILE_BYTES
from process_guard.quarantine import QuarantineError, quarantine_file, restore_file
from process_guard.rules import evaluate_rules
from process_guard.scheduled_tasks import tasks_for_executable
from process_guard.signature import authenticode_status, sha256_reputation
from process_guard.sysmon import has_remote_memory_access_rights, recent_events
from process_guard.virustotal import VirusTotalLookupError, lookup_sha256
from scripts.generate_demo_data import generate as generate_demo_data
from scripts.train_cardiff_models import train as train_cardiff_models


class ProcessGuardApp:
    REFRESH_MS = 3000

    def __init__(self, root: tk.Tk, demo: bool = False):
        self.root = root
        self.demo = demo
        self.root.title("ProcessGuard — giám sát tiến trình và nghiên cứu ML")
        self.root.geometry("1500x820")
        self.collector = ProcessCollector()
        self._self_process = psutil.Process(os.getpid())
        self.demo_scorer = ModelScorer(ROOT / "artifacts/models/synthetic_demo", allow_synthetic_demo=True)
        self.live_scorer = ModelScorer(ROOT / "artifacts/models/pid_live", allowed_sources={"observed-per-process"})
        self.rows: dict[int, dict] = {}
        self.after_id = None
        self.paused = False
        self._alerted: set[tuple[int, str]] = set()
        self._ignored: set[tuple[int, str]] = set()
        self._signature_cache: dict[str, tuple[str, str]] = {}
        self._path_enrichment_cache: dict[str, dict] = {}
        self._process_enrichment_cache: dict[tuple[int, float], dict] = {}
        self._extra_details: dict[int, str] = {}
        self._procmon_summary: dict | None = None
        self.procmon_capture = ProcMonCapture()
        self._procmon_starting = False
        self._procmon_stopping = False
        self._procmon_watch_id = None
        self._close_after_procmon = False
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.refresh()

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="ProcessGuard", font=("Segoe UI", 16, "bold")).pack(side="left")
        ttk.Label(top, text="Live: psutil + rule / PID ML tùy chọn | Demo: fixture, không chạy tiến trình")\
            .pack(side="left", padx=18)
        ttk.Button(top, text="Quét ngay", command=self.refresh).pack(side="right", padx=3)
        self.demo_btn = ttk.Button(top, text="Về giám sát thật" if self.demo else "Chạy demo an toàn",
                                   command=self.toggle_demo)
        self.demo_btn.pack(side="right", padx=3)
        self.pause_btn = ttk.Button(top, text="Tạm dừng cập nhật", command=self.toggle_pause)
        self.pause_btn.pack(side="right", padx=3)
        ttk.Button(top, text="Huấn luyện Cardiff", command=self.train_cardiff).pack(side="right", padx=3)
        ttk.Button(top, text="Huấn luyện PID từ nhãn lab", command=self.train_live_pid).pack(side="right", padx=3)
        ttk.Button(top, text="Huấn luyện PID demo", command=self.train_demo_pid).pack(side="right", padx=3)

        self.status = tk.StringVar(value="Đang khởi tạo...")
        ttk.Label(self.root, textvariable=self.status, padding=(9, 0)).pack(fill="x")
        body = ttk.Panedwindow(self.root, orient="horizontal")
        body.pack(fill="both", expand=True, padx=8, pady=8)
        left = ttk.Frame(body)
        right = ttk.Frame(body, width=390)
        body.add(left, weight=5)
        body.add(right, weight=2)

        columns = ("pid", "ppid", "cpu", "mem", "threads", "handles", "connections", "children", "risk")
        self.tree = ttk.Treeview(left, columns=columns, show=("tree", "headings"), selectmode="browse")
        self.tree.heading("#0", text="Tiến trình")
        self.tree.column("#0", width=240, anchor="w")
        labels = {"pid": "PID", "ppid": "PPID", "cpu": "CPU %", "mem": "RAM %",
                  "threads": "Threads", "handles": "Handles", "connections": "Kết nối",
                  "children": "Con", "risk": "Điểm nghi ngờ"}
        widths = {"pid": 65, "ppid": 65, "cpu": 65, "mem": 65, "threads": 70,
                  "handles": 75, "connections": 75, "children": 50, "risk": 115}
        for col in columns:
            self.tree.heading(col, text=labels[col], command=lambda c=col: self.sort_column(c, False))
            self.tree.column(col, width=widths[col], anchor="center")
        self.tree.tag_configure("high", background="#ffd9d9")
        self.tree.tag_configure("medium", background="#fff0c2")
        self.tree.tag_configure("ignored", background="#e8edf3", foreground="#64748b")
        self.tree.tag_configure("demo", foreground="#174a7e")
        ybar = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        xbar = ttk.Scrollbar(left, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ybar.grid(row=0, column=1, sticky="ns")
        xbar.grid(row=1, column=0, sticky="ew")
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", self.show_details)

        ttk.Label(right, text="Chi tiết tiến trình", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(3, 6))
        self.details = tk.Text(right, height=26, wrap="word", state="disabled")
        self.details.pack(fill="both", expand=True)
        ttk.Button(right, text="Kiểm tra chữ ký + hash + persistence", command=self.inspect_selected)\
            .pack(fill="x", pady=(8, 3))
        ttk.Button(right, text="Quét vùng nhớ executable (read-only)", command=self.inspect_memory_selected)\
            .pack(fill="x", pady=3)
        ttk.Button(right, text="Nhập thống kê ProcMon CSV…", command=self.import_procmon_csv)\
            .pack(fill="x", pady=3)
        advanced = ttk.LabelFrame(right, text="Điều tra nâng cao", padding=(6, 4))
        advanced.pack(fill="x", pady=3)
        advanced.columnconfigure((0, 1), weight=1)
        self.procmon_start_button = ttk.Button(advanced, text="Capture ProcMon 60 giây…",
                                               command=self.start_procmon_capture)
        self.procmon_start_button.grid(row=0, column=0, sticky="ew", padx=2, pady=2)
        self.procmon_stop_button = ttk.Button(advanced, text="Dừng + xuất CSV",
                                              command=self.stop_procmon_capture, state="disabled")
        self.procmon_stop_button.grid(row=0, column=1, sticky="ew", padx=2, pady=2)
        ttk.Button(advanced, text="Tra cứu VirusTotal SHA-256…",
                   command=self.lookup_selected_virustotal).grid(row=1, column=0, sticky="ew", padx=2, pady=2)
        ttk.Button(advanced, text="Cách ly executable…", command=self.quarantine_selected)\
            .grid(row=1, column=1, sticky="ew", padx=2, pady=2)
        ttk.Button(advanced, text="Khôi phục file quarantine…", command=self.restore_quarantined)\
            .grid(row=2, column=0, columnspan=2, sticky="ew", padx=2, pady=2)
        ttk.Button(right, text="Đọc sự kiện Sysmon gần đây", command=self.inspect_sysmon).pack(fill="x", pady=3)
        ttk.Button(right, text="Lưu quan sát PID: benign (0)", command=lambda: self.save_sample(0))\
            .pack(fill="x", pady=3)
        ttk.Button(right, text="Lưu quan sát PID: mô phỏng (1)", command=lambda: self.save_sample(1))\
            .pack(fill="x", pady=3)
        ttk.Button(right, text="Kết thúc tiến trình đã chọn…", command=self.terminate_selected)\
            .pack(fill="x", pady=(3, 8))
        ttk.Button(right, text="Bỏ qua cảnh báo trong phiên này", command=self.ignore_selected)\
            .pack(fill="x", pady=(0, 8))
        ttk.Label(right, text=("Live dùng rule và PID model nếu đã huấn luyện từ nhãn lab. "
                              "Model Cardiff phân loại chuỗi telemetry sandbox theo executable."),
                  wraplength=360, foreground="#765000").pack(anchor="w")

    def toggle_demo(self):
        self.demo = not self.demo
        self.demo_btn.configure(text="Về giám sát thật" if self.demo else "Chạy demo an toàn")
        self._extra_details.clear()
        self.refresh()

    def toggle_pause(self):
        self.paused = not self.paused
        self.pause_btn.configure(text="Tiếp tục cập nhật" if self.paused else "Tạm dừng cập nhật")
        if not self.paused:
            self.refresh()

    def refresh(self):
        if self.after_id:
            self.root.after_cancel(self.after_id)
            self.after_id = None
        started = time.perf_counter()
        records = demo_records() if self.demo else self.collector.snapshot()
        self.rows = {r["pid"]: r for r in records}
        live_identities = {(int(row["pid"]), float(row.get("create_time") or 0)) for row in records}
        self._process_enrichment_cache = {
            key: value for key, value in self._process_enrichment_cache.items() if key in live_identities
        }
        selected = self.tree.selection()
        keep_pid = int(selected[0]) if selected and selected[0].isdigit() else None
        for item in self.tree.get_children(""):
            self.tree.delete(item)
        if not self.demo:
            for row in records:
                row.update(self._path_enrichment_cache.get(self._path_key(row.get("exe", "")), {}))
                process_key = (int(row["pid"]), float(row.get("create_time") or 0))
                row.update(self._process_enrichment_cache.get(process_key, {}))
        scorer = self.demo_scorer if self.demo else self.live_scorer
        has_model = self.demo or bool(scorer.bundle)
        model_results = (scorer.score_many(records) if has_model else
                         [(0.0, "Chưa có dữ liệu PID có nhãn") for _ in records])
        warnings = 0
        for row, (ml_score, model_name) in zip(records, model_results):
            features = extract_features(row)
            rule_score, reasons = evaluate_rules(row, features)
            score = max(rule_score, ml_score) if has_model else rule_score
            row.update(_features=features, _rule_score=rule_score, _reasons=reasons,
                       _ml_score=ml_score, _model_name=model_name, _score=score)
            if score >= .65:
                key = (row["pid"], "demo" if self.demo else str(row["create_time"]))
                if key not in self._ignored:
                    warnings += 1
                if key not in self._alerted and key not in self._ignored:
                    self.log_event({"event": "suspicious_process", "pid": row["pid"],
                                    "name": row["name"], "exe": row.get("exe", ""),
                                    "score": score, "rule_score": rule_score, "ml_score": ml_score,
                                    "model": model_name, "reasons": reasons, "demo_only": self.demo})
                    self._alerted.add(key)
        active_keys = {(pid, "demo" if self.demo else str(row["create_time"]))
                       for pid, row in self.rows.items()}
        self._alerted.intersection_update(active_keys)
        self._ignored.intersection_update(active_keys)
        children: dict[int, list[int]] = {}
        for row in records:
            children.setdefault(int(row["ppid"]), []).append(int(row["pid"]))
        roots = [r["pid"] for r in records if r["ppid"] not in self.rows or r["ppid"] == r["pid"]]
        inserted: set[int] = set()

        def add_node(pid: int, parent_iid: str):
            if pid in inserted or pid not in self.rows:
                return
            inserted.add(pid)
            row = self.rows[pid]
            score = row["_score"]
            identity = (pid, "demo" if self.demo else str(row["create_time"]))
            tags = (("ignored",) if identity in self._ignored else
                    (("high",) if score >= .75 else (("medium",) if score >= .5 else ())))
            if self.demo:
                tags = (*tags, "demo")
            name = row["name"] + ("  [DEMO]" if self.demo else "")
            self.tree.insert(parent_iid, "end", iid=str(pid), text=name,
                             values=(pid, row["ppid"], f"{row['cpu_percent']:.1f}",
                                     f"{row['memory_percent']:.1f}", row["thread_count"],
                                     row["handle_count"], row["connection_count"],
                                     row["child_count"], f"{score:.0%}"), tags=tags, open=True)
            for child in sorted(children.get(pid, [])):
                add_node(child, str(pid))

        for pid in sorted(roots):
            add_node(pid, "")
        for pid in sorted(self.rows):
            add_node(pid, "")
        if keep_pid and str(keep_pid) in self.tree.get_children(""):
            self.tree.selection_set(str(keep_pid))
        elif keep_pid and str(keep_pid) in self.rows:
            self.tree.selection_set(str(keep_pid))
        elapsed = (time.perf_counter() - started) * 1000
        try:
            app_mem = self._self_process.memory_info().rss / (1024 * 1024)
            app_cpu = self._self_process.cpu_percent(interval=None)
        except psutil.Error:
            app_mem, app_cpu = 0.0, 0.0
        mode = ("DEMO tổng hợp" if self.demo else
                ("LIVE PID model + rules" if self.live_scorer.bundle else "LIVE rule-based"))
        self.status.set(f"{len(records)} tiến trình | {warnings} cần xem xét (65%) | {mode} | "
                        f"Quét {elapsed:.0f} ms | App {app_cpu:.1f}% CPU, {app_mem:.1f} MB | "
                        f"{datetime.now().strftime('%H:%M:%S')}")
        if not self.paused:
            self.after_id = self.root.after(self.REFRESH_MS, self.refresh)

    def sort_column(self, column, reverse):
        # Sorting is applied only among sibling rows so the process tree remains intact.
        parents = [""] + [str(pid) for pid in self.rows if self.tree.exists(str(pid))]
        for parent_iid in parents:
            items = [(self.tree.set(item, column), item) for item in self.tree.get_children(parent_iid)]
            def key(pair):
                value = pair[0]
                try:
                    return float(value.rstrip("%"))
                except ValueError:
                    return value.casefold()
            for index, (_, item) in enumerate(sorted(items, key=key, reverse=reverse)):
                self.tree.move(item, parent_iid, index)
        self.tree.heading(column, command=lambda: self.sort_column(column, not reverse))

    def selected_record(self):
        selected = self.tree.selection()
        if not selected:
            return None
        try:
            return self.rows.get(int(selected[0]))
        except ValueError:
            return None

    def show_details(self, _event=None):
        row = self.selected_record()
        if not row:
            return
        reasons = row["_reasons"] or ["Không có quy tắc heuristic nào kích hoạt."]
        text = (f"PID: {row['pid']}    PPID: {row['ppid']} ({row['parent_name'] or 'không rõ'})\n"
                f"Tên: {row['name']}\nĐường dẫn: {row['exe'] or '(không truy cập được)'}\n"
                f"Command line: {row['cmdline'] or '(không truy cập được)'}\n"
                f"User: {row['username'] or '(không rõ)'}\n"
                f"Khởi chạy: {datetime.fromtimestamp(row['create_time']).isoformat(sep=' ', timespec='seconds')}\n"
                f"CPU: {row['cpu_percent']:.1f}% | RAM: {row['memory_percent']:.2f}%\n"
                f"CPU TB/đỉnh: {row.get('cpu_avg_percent', row['cpu_percent']):.1f}%/"
                f"{row.get('cpu_peak_percent', row['cpu_percent']):.1f}% | "
                f"RAM TB/đỉnh: {row.get('memory_avg_percent', row['memory_percent']):.2f}%/"
                f"{row.get('memory_peak_percent', row['memory_percent']):.2f}% (tối đa 5 lần quét gần nhất)\n"
                f"Threads: {row['thread_count']} | Handles: {row['handle_count']}\n"
                f"Kết nối: {row['connection_count']} | Tiến trình con: {row['child_count']}\n"
                f"Đọc/ghi: {row['file_read_rate_kbps']:.1f}/{row['file_write_rate_kbps']:.1f} KB/s; "
                f"{row.get('file_read_ops_per_sec', 0):.1f}/{row.get('file_write_ops_per_sec', 0):.1f} I/O ops/s\n\n"
                f"Điểm rule: {row['_rule_score']:.0%}\n"
                f"Điểm ML PID: {row['_ml_score']:.0%} ({row['_model_name']})\n"
                f"Tín hiệu: " + "; ".join(reasons) + "\n\n")
        connections = row.get("connections", [])
        if connections:
            text = text.replace("Đọc/ghi:", "Kết nối chi tiết:\n" + "\n".join(
                f"  {conn['local']} -> {conn['remote'] or '(listen/local)'} [{conn['status']}]"
                for conn in connections[:20]) + "\n\nĐọc/ghi:")
        if self.demo:
            text += ("DEMO: bản ghi process giả lập, không phải tiến trình thật và không chạy payload. "
                     "Điểm ML từ dữ liệu tổng hợp chỉ minh họa luồng tích hợp; không phải bằng chứng phát hiện.\n\n")
        else:
            if self.live_scorer.bundle:
                text += ("Live đang dùng PID model đã train từ các quan sát gán nhãn của nhóm; "
                         "chỉ tin cậy khi nhãn và split theo executable phù hợp.\n\n")
            else:
                text += ("Live hiện dùng rule. Chưa có model PID vì Cardiff chỉ chứa chuỗi telemetry của executable "
                         "trong sandbox, không có thông tin riêng từng PID. Thu thập nhãn benign/mô phỏng trong lab "
                         "rồi dùng nút Huấn luyện PID từ nhãn lab.\n\n")
        text += (self._extra_details.get(row["pid"], "") +
                 ("Đã bỏ qua cảnh báo cho tiến trình này đến khi tiến trình kết thúc hoặc ứng dụng khởi động lại.\n"
                  if (row["pid"], "demo" if self.demo else str(row["create_time"])) in self._ignored else "") +
                 "\nĐiểm cao là tín hiệu cần điều tra, không phải kết luận malware. "
                 "Thiếu quyền đọc có thể khiến một số số liệu bằng 0.")
        if self._procmon_summary:
            procmon_stats = match_live_process(self._procmon_summary, row["pid"], row.get("name", ""))
            if procmon_stats:
                text += ("\nProcMon CSV đã nhập (khớp PID + tên ảnh; có thể là tiến trình cũ nếu PID được tái sử dụng):\n"
                         f"ReadFile: {procmon_stats['file_read_events']} | WriteFile: {procmon_stats['file_write_events']} | "
                         f"Registry Run/RunOnce: {procmon_stats['registry_sensitive_events']} | "
                         f"Tổng event: {procmon_stats['events']}\n"
                         f"Thời điểm trong trace: {procmon_stats['first_time'] or 'không có'} → "
                         f"{procmon_stats['last_time'] or 'không có'}\n")
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def inspect_selected(self):
        row = self.selected_record()
        if not row:
            messagebox.showinfo("Chọn tiến trình", "Hãy chọn một tiến trình trong bảng trước.")
            return
        if self.demo:
            messagebox.showinfo("Dữ liệu demo", "Các dòng demo không trỏ tới file thật nên không kiểm tra chữ ký/hash.")
            return
        path = row.get("exe") or ""
        if path not in self._signature_cache:
            self._signature_cache[path] = authenticode_status(path)
        status, signer = self._signature_cache[path]
        normalized_status = status.casefold()
        signature_checked = (normalized_status not in {"", "unknown", "unsupported", "notsupported", "unavailable"}
                             and "error" not in normalized_status)
        digest, reputation = sha256_reputation(path)
        autorun = self._autorun_matches(path)
        scheduled_tasks, task_status = tasks_for_executable(path, timeout=5.0)
        path_key = self._path_key(path)
        if path_key:
            self._path_enrichment_cache.setdefault(path_key, {}).update({
                "authenticode_status": status,
                "signature_checked": signature_checked,
                "signature_valid": normalized_status == "valid",
                "unsigned_hint": signature_checked and normalized_status != "valid",
                "registry_run_persistence": bool(autorun),
                "scheduled_task_checked": task_status == "OK",
                "scheduled_task_persistence": bool(scheduled_tasks),
            })
        extra = (f"Authenticode: {status}\nSigner: {signer or '(không có)'}\n"
                 f"SHA-256: {digest or '(không đọc được)'}\nBlocklist cục bộ: {reputation}\n"
                 f"Registry Run/RunOnce khớp: {', '.join(autorun) if autorun else 'không tìm thấy/không hỗ trợ'}\n"
                 f"Scheduled Task: {', '.join(task['task'] for task in scheduled_tasks) if scheduled_tasks else task_status if task_status != 'OK' else 'không tìm thấy action trùng executable'}\n"
                 "Khớp action chỉ là dấu hiệu persistence; không chứng minh task đã khởi chạy PID này.\n")
        self._extra_details[row["pid"]] = extra
        self.log_event({"event": "signature_inspected", "pid": row["pid"],
                        "authenticode": status, "sha256": digest,
                        "registry_run_persistence": bool(autorun),
                        "scheduled_task_matches": scheduled_tasks, "scheduled_task_status": task_status,
                        "demo_only": False})
        self.refresh()
        self.tree.selection_set(str(row["pid"]))
        self.show_details()

    def inspect_memory_selected(self):
        row = self.selected_record()
        if not row:
            messagebox.showinfo("Chọn tiến trình", "Hãy chọn một tiến trình trong bảng trước.")
            return
        if self.demo:
            messagebox.showinfo("Dữ liệu demo", "Không thể kiểm tra vùng nhớ từ fixture demo.")
            return
        if not messagebox.askyesno(
            "Quét metadata vùng nhớ",
            "Chỉ truy vấn các vùng nhớ executable và danh sách module đã nạp; không đọc nội dung hay sửa bộ nhớ.\n\n"
            "JIT/runtime hợp lệ cũng có thể tạo vùng executable riêng tư. Kết quả chỉ là tín hiệu triage. Tiếp tục?",
        ):
            return
        pid = int(row["pid"])
        create_time = float(row.get("create_time") or 0)
        name = str(row.get("name") or "")
        self.status.set(f"Đang truy vấn metadata vùng nhớ PID {pid}…")

        def worker():
            try:
                result = inspect_private_executable_regions(pid)
                self.root.after(0, lambda: self._memory_scan_done(pid, create_time, name, result))
            except Exception as exc:
                self.root.after(0, lambda error=str(exc), target_pid=pid:
                                self._memory_scan_failed(target_pid, error))

        threading.Thread(target=worker, daemon=True).start()

    def _memory_scan_failed(self, pid: int, error: str):
        self.status.set(f"Không truy vấn được vùng nhớ PID {pid}")
        messagebox.showerror("Không thể truy vấn vùng nhớ", error)

    def _memory_scan_done(self, pid: int, create_time: float, name: str, result: dict):
        current = self.rows.get(pid)
        if not current or abs(float(current.get("create_time") or 0) - create_time) > 0.01:
            messagebox.showinfo("Kết quả đã cũ", "Tiến trình đã kết thúc hoặc PID được tái sử dụng; bỏ kết quả quét.")
            return
        lines = ["Kiểm tra vùng nhớ executable (metadata read-only)",
                 f"Trạng thái: {result['status']}", f"Module nhận diện: {result['module_count']}",
                 f"Vùng nhớ đã quét: {result['region_count']}",
                 f"Vùng MEM_PRIVATE có quyền execute ngoài module: {result['unbacked_executable_region_count']}"]
        for item in result.get("samples", []):
            lines.append(f"  base={item['base']}, allocation={item['allocation_base']}, "
                         f"size={item['size_bytes']} bytes, protect={item['protect']}")
        lines.append("Đây không phải kết luận process injection; JIT và runtime hợp lệ có thể tạo vùng tương tự.")
        self._extra_details[pid] = (self._extra_details.get(pid, "") + "\n" + "\n".join(lines) + "\n")
        self.log_event({"event": "memory_region_inspected", "pid": pid, "name": name,
                        "status": result["status"], "module_count": result["module_count"],
                        "region_count": result["region_count"],
                        "unbacked_executable_region_count": result["unbacked_executable_region_count"],
                        "samples": result.get("samples", [])})
        self.status.set(f"Đã quét metadata vùng nhớ PID {pid}: {result['unbacked_executable_region_count']} vùng cần xem xét")
        selected = self.selected_record()
        if selected and int(selected["pid"]) == pid:
            self.show_details()

    def import_procmon_csv(self):
        if self.demo:
            messagebox.showinfo("Dữ liệu demo", "Hãy chuyển sang giám sát thật để đối chiếu ProcMon với PID đang chạy.")
            return
        path = filedialog.askopenfilename(
            title="Chọn CSV đã xuất từ Process Monitor",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*")),
        )
        if not path:
            return
        try:
            summary = aggregate_procmon_csv(path)
        except (OSError, ValueError, csv.Error) as exc:
            messagebox.showerror("Không đọc được ProcMon CSV", str(exc))
            return
        self._procmon_summary = summary
        self.log_event({"event": "procmon_csv_imported", "file": summary["file"],
                        "rows_read": summary["rows_read"], "dropped_rows": summary["dropped_rows"],
                        "process_count": len(summary["by_process"])})
        row = self.selected_record()
        matched = (match_live_process(summary, row["pid"], row.get("name", "")) if row else None)
        if row:
            self.show_details()
        message = (f"Đã đọc {summary['rows_read']:,} dòng, bỏ qua {summary['dropped_rows']:,} dòng lỗi; "
                   f"có {len(summary['by_process']):,} PID/tên tiến trình trong trace.\n\n")
        message += (f"Đang chọn PID {row['pid']}: có dữ liệu khớp PID và tên.\n" if matched else
                    (f"Đang chọn PID {row['pid']}: không có dòng khớp PID và tên trong CSV.\n" if row else
                     "Chọn một tiến trình để xem thống kê khớp trong phần chi tiết.\n"))
        message += "Đối chiếu PID + tên chỉ là gợi ý; trace cũ có thể trùng PID sau khi hệ điều hành tái sử dụng PID."
        messagebox.showinfo("Đã nhập ProcMon CSV", message)

    def start_procmon_capture(self):
        if self.demo:
            messagebox.showinfo("Dữ liệu demo", "ProcMon chỉ capture ở chế độ giám sát thật.")
            return
        if self._procmon_starting or self.procmon_capture.active or self._procmon_stopping:
            messagebox.showinfo("ProcMon đang hoạt động", "Hãy chờ phiên capture hiện tại kết thúc.")
            return
        executable = filedialog.askopenfilename(
            title="Chọn Procmon đã tải từ Microsoft Sysinternals",
            filetypes=(("ProcMon", "procmon.exe procmon64.exe procmon64a.exe"), ("Executable", "*.exe")),
        )
        if not executable:
            return
        if not messagebox.askyesno(
            "Bắt đầu ProcMon capture",
            "Capture tối đa 60 giây các sự kiện hệ thống file, Registry, process/thread; giới hạn PML 256 MiB.\n\n"
            "Trace có thể chứa đường dẫn, tên Registry và hoạt động ứng dụng. PML/CSV được lưu cục bộ trong "
            "artifacts/reports/procmon. Cần quyền quản trị/driver Sysinternals. Tiếp tục trong VM lab?",
        ):
            return
        self._procmon_starting = True
        self.procmon_start_button.configure(state="disabled")
        self.status.set("Đang khởi động ProcMon capture…")

        def worker():
            try:
                result = self.procmon_capture.start(executable)
                self.root.after(0, lambda data=result: self._procmon_capture_started(data))
            except Exception as exc:
                self.root.after(0, lambda error=str(exc): self._procmon_capture_start_failed(error))

        threading.Thread(target=worker, daemon=True).start()

    def _procmon_capture_start_failed(self, error: str):
        self._procmon_starting = False
        self.procmon_start_button.configure(state="normal")
        self.status.set("ProcMon capture chưa khởi động")
        messagebox.showerror("Không khởi động được ProcMon", error)

    def _procmon_capture_started(self, result: dict):
        self._procmon_starting = False
        self.procmon_start_button.configure(state="disabled")
        self.procmon_stop_button.configure(state="normal")
        self.log_event({"event": "procmon_capture_started", **result})
        self._watch_procmon_capture()

    def _watch_procmon_capture(self):
        if not self.procmon_capture.active:
            return
        elapsed = self.procmon_capture.elapsed_seconds
        size = self.procmon_capture.backing_file_size
        if elapsed >= MAX_CAPTURE_SECONDS or size >= MAX_BACKING_FILE_BYTES:
            self.status.set("ProcMon đạt giới hạn; đang dừng và xuất CSV…")
            self.stop_procmon_capture()
            return
        self.status.set(f"ProcMon capture: {elapsed:.0f}/{MAX_CAPTURE_SECONDS}s | {size / (1024 * 1024):.1f} MiB")
        self._procmon_watch_id = self.root.after(1000, self._watch_procmon_capture)

    def stop_procmon_capture(self):
        if self._procmon_starting:
            messagebox.showinfo("ProcMon đang khởi động", "Chờ ProcMon tạo file capture rồi hãy dừng.")
            return
        if not self.procmon_capture.active or self._procmon_stopping:
            return
        self._procmon_stopping = True
        if self._procmon_watch_id:
            self.root.after_cancel(self._procmon_watch_id)
            self._procmon_watch_id = None
        self.procmon_stop_button.configure(state="disabled")
        self.status.set("Đang dừng ProcMon và xuất CSV…")
        pml_path = str(self.procmon_capture.pml_path or "")

        def worker():
            result = None
            error = ""
            summary = None
            parse_error = ""
            try:
                result = self.procmon_capture.stop()
                try:
                    summary = aggregate_procmon_csv(result["csv_path"])
                except Exception as exc:
                    parse_error = str(exc)
            except Exception as exc:
                error = str(exc)
            self.root.after(0, lambda: self._procmon_capture_stopped(
                result, error, summary, parse_error, pml_path))

        threading.Thread(target=worker, daemon=True).start()

    def _procmon_capture_stopped(self, result: dict | None, error: str, summary: dict | None,
                                 parse_error: str, pml_path: str):
        self._procmon_stopping = False
        self.procmon_start_button.configure(state="normal")
        self.procmon_stop_button.configure(state="disabled")
        self._procmon_watch_id = None
        if result:
            self.log_event({"event": "procmon_capture_completed", **result})
            self._procmon_summary = summary
            if summary:
                self.log_event({"event": "procmon_csv_imported", "file": summary["file"],
                                "rows_read": summary["rows_read"], "dropped_rows": summary["dropped_rows"],
                                "process_count": len(summary["by_process"]), "automatic_capture": True})
            self.refresh()
            message = (f"Capture hoàn tất sau {result['elapsed_seconds']:.1f} giây.\n"
                       f"PML: {result['pml_path']}\nCSV: {result['csv_path']}\n")
            message += (f"Đã tổng hợp {summary['rows_read']:,} dòng. Chọn process để xem thống kê ProcMon."
                        if summary else f"Đã lưu CSV nhưng chưa tổng hợp được: {parse_error}")
            self.status.set("ProcMon capture đã lưu")
            if not self._close_after_procmon:
                messagebox.showinfo("ProcMon capture hoàn tất", message)
        else:
            self.log_event({"event": "procmon_capture_failed", "pml_path": pml_path, "error": error})
            self.status.set("ProcMon capture dừng nhưng export gặp lỗi")
            if not self._close_after_procmon:
                messagebox.showerror("ProcMon export lỗi", error + (f"\nPML giữ lại tại: {pml_path}" if pml_path else ""))
        if self._close_after_procmon:
            self._close_after_procmon = False
            self.root.destroy()

    def on_close(self):
        if self._procmon_starting:
            messagebox.showinfo("Đang khởi động capture", "Chờ ProcMon capture khởi động xong rồi hãy đóng ứng dụng.")
            return
        if self._procmon_stopping:
            messagebox.showinfo("Đang xuất ProcMon", "Chờ ProcMon dừng và xuất CSV xong rồi hãy đóng ứng dụng.")
            return
        if self.procmon_capture.active:
            if messagebox.askyesno("Dừng ProcMon trước khi đóng?",
                                   "Dừng capture, xuất CSV rồi đóng ứng dụng?"):
                self._close_after_procmon = True
                self.stop_procmon_capture()
            return
        if self.after_id:
            self.root.after_cancel(self.after_id)
        self.root.destroy()

    def lookup_selected_virustotal(self):
        row = self.selected_record()
        if not row:
            messagebox.showinfo("Chọn tiến trình", "Hãy chọn một tiến trình trong bảng trước.")
            return
        if self.demo:
            messagebox.showinfo("Dữ liệu demo", "Không có file thật để tra cứu hash.")
            return
        path = row.get("exe") or ""
        if not path or not Path(path).is_file():
            messagebox.showerror("Không đọc được executable", "File có thể đã kết thúc, bị khóa hoặc không truy cập được.")
            return
        if not messagebox.askyesno(
            "Tra cứu hash công khai",
            "Chỉ gửi SHA-256 tới VirusTotal; không tải nội dung file lên. Hash được truy vấn có thể được ghi vào "
            "dataset công khai của dịch vụ. Không dùng với file/hash nhạy cảm hoặc bí mật. Tiếp tục?",
        ):
            return
        api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
        if not api_key:
            api_key = simpledialog.askstring("VirusTotal API key", "Nhập API key (không được lưu vào project/log):",
                                             show="*", parent=self.root) or ""
        if not api_key:
            return
        pid = int(row["pid"])
        create_time = float(row.get("create_time") or 0)
        self.status.set(f"Đang tra cứu SHA-256 cho PID {pid}…")

        def worker():
            try:
                digest, local_status = sha256_reputation(path)
                if not digest:
                    raise VirusTotalLookupError(f"Không băm được file: {local_status}")
                report = lookup_sha256(digest, api_key)
                self.root.after(0, lambda: self._virustotal_lookup_done(pid, create_time, report))
            except Exception as exc:
                self.root.after(0, lambda error=str(exc), target_pid=pid:
                                self._virustotal_lookup_failed(target_pid, error))

        threading.Thread(target=worker, daemon=True).start()

    def _virustotal_lookup_failed(self, pid: int, error: str):
        self.status.set(f"VirusTotal lookup thất bại cho PID {pid}")
        messagebox.showerror("Tra cứu VirusTotal thất bại", error)

    def _virustotal_lookup_done(self, pid: int, create_time: float, report: dict):
        current = self.rows.get(pid)
        if not current or abs(float(current.get("create_time") or 0) - create_time) > 0.01:
            messagebox.showinfo("Kết quả đã cũ", "Process đã kết thúc/PID tái sử dụng; kết quả chỉ áp dụng cho hash đã gửi.")
        self.log_event({"event": "virustotal_hash_lookup", "pid": pid, **report})
        self.status.set(f"VirusTotal lookup xong cho PID {pid}")
        if report["status"] == "not_found":
            message = f"Không tìm thấy hash trong VirusTotal.\nSHA-256: {report['sha256']}"
        else:
            message = (f"SHA-256: {report['sha256']}\nMalicious: {report['malicious']} | "
                       f"Suspicious: {report['suspicious']} | Harmless: {report['harmless']} | "
                       f"Undetected: {report['undetected']}\nReputation: {report['reputation']}\n"
                       f"Loại: {report['type_description'] or 'không rõ'}\nTên: "
                       f"{', '.join(report['names'][:5]) or report['meaningful_name'] or 'không có'}\n\n"
                       "Đây là kết quả reputation bên ngoài; không phải kết luận an toàn/độc hại tuyệt đối.")
        messagebox.showinfo("VirusTotal hash report", message)

    def quarantine_selected(self):
        row = self.selected_record()
        if not row:
            messagebox.showinfo("Chọn tiến trình", "Hãy chọn một tiến trình trong bảng trước.")
            return
        if self.demo:
            messagebox.showinfo("Dữ liệu demo", "Không có file thật để cách ly.")
            return
        if int(row["pid"]) == os.getpid():
            messagebox.showerror("Không cho phép", "Không thể cách ly executable của chính ProcessGuard.")
            return
        path = row.get("exe") or ""
        if not path or not Path(path).is_file():
            messagebox.showerror("Không đọc được executable", "File không tồn tại hoặc không truy cập được.")
            return
        if not messagebox.askyesno(
            "Cách ly executable",
            f"Sao chép và xác minh hash, sau đó xóa file gốc:\n{path}\n\n"
            "File nằm trong thư mục Windows sẽ bị từ chối. Không tự kết thúc process; nếu file đang chạy, Windows có thể từ chối xóa. "
            "Bạn có thể khôi phục file bằng metadata trong quarantine. Tiếp tục?",
        ):
            return
        pid = int(row["pid"])
        create_time = float(row.get("create_time") or 0)
        self.status.set(f"Đang cách ly executable PID {pid}…")

        def worker():
            try:
                proc = psutil.Process(pid)
                if abs(proc.create_time() - create_time) > 0.01:
                    raise QuarantineError("PID đã kết thúc hoặc được tái sử dụng")
                current_exe = os.path.normcase(os.path.abspath(proc.exe()))
                if current_exe != os.path.normcase(os.path.abspath(path)):
                    raise QuarantineError("Đường dẫn executable hiện tại không khớp snapshot đã chọn")
                result = quarantine_file(path)
                self.root.after(0, lambda: self._quarantine_done(pid, result))
            except Exception as exc:
                self.root.after(0, lambda error=str(exc), target_pid=pid:
                                self._quarantine_failed(target_pid, error))

        threading.Thread(target=worker, daemon=True).start()

    def _quarantine_failed(self, pid: int, error: str):
        self.status.set(f"Không cách ly được executable PID {pid}")
        messagebox.showerror("Cách ly thất bại", error)

    def _quarantine_done(self, pid: int, result: dict):
        self.log_event({"event": "file_quarantined", "pid": pid, **result})
        self.status.set(f"Đã cách ly file PID {pid}")
        self.refresh()
        messagebox.showinfo("Đã cách ly", f"SHA-256: {result['sha256']}\n"
                            f"Quarantine: {result['quarantine_path']}\nMetadata khôi phục: {result['metadata_path']}")

    def restore_quarantined(self):
        quarantine_dir = ROOT / "artifacts/quarantine"
        if not quarantine_dir.is_dir():
            messagebox.showinfo("Chưa có quarantine", "Thư mục cách ly chưa có dữ liệu.")
            return
        metadata_path = filedialog.askopenfilename(
            title="Chọn metadata file cần khôi phục", initialdir=str(quarantine_dir),
            filetypes=(("Quarantine metadata", "*.json"),),
        )
        if not metadata_path:
            return
        try:
            metadata = json.loads(Path(metadata_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            messagebox.showerror("Metadata không hợp lệ", str(exc))
            return
        destination = str(metadata.get("source_path") or "(không rõ đường dẫn)")
        if not messagebox.askyesno(
            "Khôi phục file quarantine",
            f"Khôi phục file về:\n{destination}\n\n"
            "Hash sẽ được xác minh; file hiện có sẽ không bị ghi đè. Việc khôi phục không chạy file. Tiếp tục?",
        ):
            return
        self.status.set("Đang xác minh và khôi phục file…")

        def worker():
            try:
                result = restore_file(metadata_path)
                self.root.after(0, lambda: self._restore_quarantine_done(result))
            except Exception as exc:
                self.root.after(0, lambda error=str(exc): self._restore_quarantine_failed(error))

        threading.Thread(target=worker, daemon=True).start()

    def _restore_quarantine_failed(self, error: str):
        self.status.set("Khôi phục quarantine thất bại")
        messagebox.showerror("Khôi phục thất bại", error)

    def _restore_quarantine_done(self, result: dict):
        self.log_event({"event": "file_quarantine_restored", **result})
        self.status.set("Đã khôi phục file quarantine")
        message = f"Đã khôi phục: {result['restored_path']}\nSHA-256: {result['sha256']}"
        if result["status"] != "restored":
            message += f"\nBản quarantine vẫn còn; dọn dẹp lỗi: {result.get('cleanup_error', '')}"
        messagebox.showinfo("Khôi phục hoàn tất", message)

    @staticmethod
    def _path_key(path: str) -> str:
        return os.path.normcase(os.path.abspath(path)) if path else ""

    @staticmethod
    def _autorun_matches(path: str) -> list[str]:
        if os.name != "nt" or not path:
            return []
        try:
            import winreg
        except ImportError:
            return []
        matches = []
        hives = ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM"))
        keys = (r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
        views = [(0, "default")]
        if hasattr(winreg, "KEY_WOW64_32KEY") and hasattr(winreg, "KEY_WOW64_64KEY"):
            views = [(winreg.KEY_WOW64_32KEY, "32-bit"), (winreg.KEY_WOW64_64KEY, "64-bit")]
        needle = os.path.normcase(os.path.abspath(path)).replace("/", "\\")
        for hive, hive_name in hives:
            for key_path in keys:
                for view_flag, view_name in views:
                    try:
                        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view_flag) as key:
                            index = 0
                            while True:
                                try:
                                    name, value, _kind = winreg.EnumValue(key, index)
                                except OSError:
                                    break
                                index += 1
                                command = os.path.expandvars(str(value)).strip('"').replace("/", "\\")
                                if needle in os.path.normcase(command):
                                    matches.append(f"{hive_name}\\{key_path}\\{name} ({view_name})")
                    except OSError:
                        continue
        return matches

    def inspect_sysmon(self):
        row = self.selected_record()
        if not row:
            messagebox.showinfo("Chọn tiến trình", "Hãy chọn một tiến trình trong bảng trước.")
            return
        if self.demo:
            messagebox.showinfo("Dữ liệu demo", "Sysmon chỉ đối chiếu PID đang chạy thật; không áp dụng vào fixture.")
            return
        events, status = recent_events(limit=200)
        matched = [event for event in events if event["pid"] == row["pid"]]
        possible_injection = [event for event in matched if (
            event["event_id"] == 8 or
            (event["event_id"] == 10 and has_remote_memory_access_rights(event["fields"]))
        )]
        process_tampering = [event for event in matched if event["event_id"] == 25]
        run_registry_events = [event for event in matched
                               if event["event_id"] in {12, 13, 14}
                               and any(marker in str(event["fields"].get("TargetObject", "")).casefold()
                                       for marker in (r"\currentversion\run", r"\currentversion\runonce"))]
        file_create_events = [event for event in matched if event["event_id"] == 11]
        dns_query_events = [event for event in matched if event["event_id"] == 22]
        process_key = (int(row["pid"]), float(row.get("create_time") or 0))
        enrichment = self._process_enrichment_cache.setdefault(process_key, {})
        enrichment.update({
            "sysmon_remote_memory_access_hint": any(event["event_id"] == 10 for event in possible_injection),
            "sysmon_remote_thread_hint": any(event["event_id"] == 8 for event in possible_injection),
            "sysmon_process_tampering_hint": bool(process_tampering),
            "sysmon_registry_run_hint": bool(run_registry_events),
            "sysmon_file_create_events": len(file_create_events),
            "sysmon_dns_query_events": len(dns_query_events),
        })
        lines = [f"Sysmon status: {status}"]
        for event in matched[:10]:
            fields = event["fields"]
            summary_keys = ("Image", "CommandLine", "ParentImage", "DestinationIp", "DestinationPort",
                            "SourceImage", "TargetImage", "GrantedAccess", "StartAddress",
                            "StartModule", "StartFunction", "TargetObject", "TargetFilename",
                            "QueryName", "QueryStatus", "QueryResults", "Details", "Type")
            summary = ", ".join(f"{key}={fields[key]}" for key in summary_keys if fields.get(key))
            lines.append(f"Event ID {event['event_id']} @ {event['time']}: {summary or fields}")
        if not matched:
            lines.append("Không có sự kiện gần đây khớp PID này; có thể Sysmon chưa cài, chưa cấu hình hoặc log đã cũ.")
        lines.append("Event ID 8, Event ID 10 với quyền CreateThread/VM_OPERATION/VM_WRITE và Event ID 25 là tín hiệu triage; không tự chúng chứng minh injection/tampering.")
        if possible_injection:
            lines.append(f"Có {len(possible_injection)} sự kiện gần đây liên quan remote thread hoặc quyền ghi/điều khiển bộ nhớ.")
        if process_tampering:
            lines.append(f"Có {len(process_tampering)} sự kiện ProcessTampering gần đây.")
        if run_registry_events:
            lines.append(f"Có {len(run_registry_events)} thay đổi Registry event gần đây nhắm vào Run/RunOnce.")
        lines.append(f"Trong tối đa 200 sự kiện Sysmon mới nhất truy vấn được: {len(file_create_events)} Event ID 11 (FileCreate), {len(dns_query_events)} Event ID 22 (DNS query) khớp PID.")
        lines.append("Các số đếm này chỉ phản ánh cửa sổ sự kiện vừa truy vấn được; Event ID 11 không ghi nhận mọi lần đọc file.")
        self._extra_details[row["pid"]] = "\n".join(lines)
        self.refresh()
        self.tree.selection_set(str(row["pid"]))
        self.show_details()

    def save_sample(self, label):
        row = self.selected_record()
        if not row:
            messagebox.showinfo("Chọn tiến trình", "Hãy chọn một tiến trình trong bảng trước.")
            return
        if self.demo:
            messagebox.showinfo("Dữ liệu demo", "Không lưu fixture tổng hợp thành dữ liệu quan sát thật.")
            return
        if label == 1 and not messagebox.askyesno("Xác nhận nhãn lab",
                "Bạn xác nhận đây là tiến trình mô phỏng hành vi độc hại trong lab?\nKhông dùng nhãn này cho malware thật."):
            return
        if label == 0:
            prompt = ("Ghi mã VM/kịch bản hoặc log tham chiếu, ứng dụng và bối cảnh quan sát.\n"
                      "Chỉ gán benign khi đã xác minh tiến trình thuộc kịch bản bình thường.")
        else:
            prompt = ("Ghi mã kịch bản/run log đã duyệt để truy ngược nhãn simulated_malicious.\n"
                      "Không nhập thông tin nhạy cảm.")
        label_source = simpledialog.askstring("Nguồn gán nhãn", prompt, parent=self.root)
        if not label_source or not label_source.strip():
            messagebox.showinfo("Thiếu nguồn nhãn", "Mỗi mẫu cần căn cứ gán nhãn để đưa vào dataset lab.")
            return
        current = self.rows.get(int(row["pid"]))
        if (not current or abs(float(current.get("create_time") or 0)
                                - float(row.get("create_time") or 0)) > 0.01):
            messagebox.showerror("Process đã thay đổi", "PID đã kết thúc hoặc được tái sử dụng; hãy quét lại rồi chọn lại.")
            return
        sample = {**row["_features"], "label": label,
                  "label_name": "benign_observed" if label == 0 else "simulated_malicious_observed",
                  "process_name": row["name"], "process_path": row.get("exe", ""),
                  "process_pid": row["pid"], "process_create_time": row.get("create_time", 0),
                  "sampled_at": datetime.now().isoformat(timespec="seconds"),
                  "label_source": label_source.strip()[:500]}
        dest = ROOT / "data/observations/collected_samples.csv"
        dest.parent.mkdir(parents=True, exist_ok=True)
        temporary = dest.with_suffix(dest.suffix + ".tmp")
        new_sample = pd.DataFrame([sample])
        if dest.exists():
            previous = pd.read_csv(dest)
            for column in new_sample.columns:
                if column not in previous.columns:
                    previous[column] = pd.NA
            for column in previous.columns:
                if column not in new_sample.columns:
                    new_sample[column] = pd.NA
            new_sample = new_sample[previous.columns]
            pd.concat([previous, new_sample], ignore_index=True).to_csv(temporary, index=False)
        else:
            new_sample.to_csv(temporary, index=False)
        temporary.replace(dest)
        self.log_event({"event": "sample_saved", "pid": row["pid"], "label": label,
                        "label_source": label_source.strip()[:500], "file": str(dest)})
        messagebox.showinfo("Đã lưu", f"Đã thêm mẫu có nhãn {label} và nguồn gán nhãn vào {dest}.")

    def terminate_selected(self):
        row = self.selected_record()
        if not row:
            messagebox.showinfo("Chọn tiến trình", "Hãy chọn một tiến trình trong bảng trước.")
            return
        if self.demo:
            messagebox.showinfo("Dữ liệu demo", "Demo chỉ là bản ghi giả; không có tiến trình nào để kết thúc.")
            return
        if row["pid"] in (0, 1, os.getpid()):
            messagebox.showerror("Không cho phép", "Không thể kết thúc tiến trình hệ thống hoặc chính ứng dụng này.")
            return
        if not messagebox.askyesno("Xác nhận kết thúc", f"Kết thúc {row['name']} (PID {row['pid']})?\n"
                "Việc này có thể làm mất dữ liệu chưa lưu."):
            return
        try:
            proc = psutil.Process(row["pid"])
            if abs(proc.create_time() - row["create_time"]) > 0.01:
                raise psutil.NoSuchProcess(row["pid"])
            proc.terminate()
            self.log_event({"event": "user_terminate_requested", "pid": row["pid"], "name": row["name"]})
            messagebox.showinfo("Đã gửi yêu cầu", "Đã gửi yêu cầu kết thúc; hệ điều hành có thể từ chối nếu thiếu quyền.")
        except (psutil.Error, OSError) as exc:
            messagebox.showerror("Không thực hiện được", str(exc))

    def ignore_selected(self):
        row = self.selected_record()
        if not row:
            messagebox.showinfo("Chọn tiến trình", "Hãy chọn một tiến trình trong bảng trước.")
            return
        if float(row.get("_score") or 0) < .65:
            messagebox.showinfo("Không có cảnh báo", "Tiến trình này hiện chưa vượt ngưỡng cảnh báo 65%.")
            return
        identity = (int(row["pid"]), "demo" if self.demo else str(row.get("create_time") or 0))
        if identity in self._ignored:
            messagebox.showinfo("Đã bỏ qua", "Cảnh báo của tiến trình này đã được bỏ qua trong phiên hiện tại.")
            return
        self._ignored.add(identity)
        self.log_event({"event": "alert_ignored", "pid": row["pid"], "name": row["name"],
                        "exe": row.get("exe", ""), "score": row.get("_score"),
                        "demo_only": self.demo, "scope": "current_process_session"})
        self.refresh()
        self.tree.selection_set(str(row["pid"]))
        self.show_details()

    @staticmethod
    def log_event(event):
        path = ROOT / "artifacts/logs/detections.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        event["timestamp"] = datetime.now().isoformat(timespec="seconds")
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, ensure_ascii=False) + "\n")

    def train_cardiff(self):
        source = ROOT / "data/raw/cardiff_data_2.csv"
        if not source.exists():
            messagebox.showerror("Chưa có dataset", "Tải dữ liệu Cardiff trước:\npython scripts/download_cardiff_dataset.py")
            return
        self.status.set("Đang huấn luyện các mô hình Cardiff...")
        def worker():
            try:
                result = train_cardiff_models(source, seconds=5)
                self.root.after(0, lambda: self._cardiff_done(result))
            except Exception as exc:
                self.root.after(0, lambda error=str(exc): messagebox.showerror("Huấn luyện thất bại", error))
        threading.Thread(target=worker, daemon=True).start()

    def _cardiff_done(self, result):
        self.refresh()
        lines = [f"{r.model}: F1={r.f1:.3f}, Recall={r.recall:.3f}, FPR={r.false_positive_rate:.3f}"
                 for r in result.itertuples()]
        run_id = result.attrs.get("run_id", "latest")
        messagebox.showinfo("Huấn luyện Cardiff hoàn tất", "\n".join(lines) +
            "\n\nBáo cáo và biểu đồ: artifacts/reports/cardiff/\n"
            f"Run: {run_id}\n"
            f"Checkpoint: artifacts/models/cardiff/runs/{run_id}/\n"
            f"Log: artifacts/logs/cardiff_training_{run_id}.jsonl\n"
            "Cardiff là chuỗi telemetry sandbox cấp executable, "
            "không áp điểm lên PID live.")

    def train_demo_pid(self):
        self.status.set("Đang tạo/huấn luyện model PID demo tổng hợp...")
        def worker():
            try:
                data = generate_demo_data()
                result = train_all(data)
                self.demo_scorer = ModelScorer(ROOT / "artifacts/models/synthetic_demo", allow_synthetic_demo=True)
                self.root.after(0, lambda: messagebox.showinfo("Model demo sẵn sàng",
                    "\n".join(f"{r.model}: F1={r.f1:.3f}" for r in result.itertuples()) +
                    "\n\nChỉ dùng trong chế độ DEMO; dữ liệu và metric đều synthetic."))
                self.root.after(0, self.refresh)
            except Exception as exc:
                self.root.after(0, lambda error=str(exc): messagebox.showerror("Huấn luyện thất bại", error))
        threading.Thread(target=worker, daemon=True).start()

    def train_live_pid(self):
        source = ROOT / "data/observations/collected_samples.csv"
        if not source.exists():
            messagebox.showerror("Chưa có mẫu PID", "Lưu quan sát có nhãn trước.\n"
                "Thu thập nhiều executable benign và mô phỏng riêng trong VM lab; không gán nhãn tiến trình thật là malware.")
            return
        self.status.set("Đang huấn luyện các mô hình PID từ nhãn do nhóm thu thập...")
        def worker():
            try:
                result = train_labeled_samples(source)
                self.live_scorer = ModelScorer(ROOT / "artifacts/models/pid_live", allowed_sources={"observed-per-process"})
                self.root.after(0, lambda: self._pid_training_done(result))
            except Exception as exc:
                self.root.after(0, lambda error=str(exc): messagebox.showerror("Không đủ dữ liệu PID", error))
        threading.Thread(target=worker, daemon=True).start()

    def _pid_training_done(self, result):
        self.refresh()
        messagebox.showinfo("Huấn luyện PID hoàn tất",
            "\n".join(f"{r.model}: F1={r.f1:.3f}, Recall={r.recall:.3f}, FPR={r.false_positive_rate:.3f}"
                      for r in result.itertuples()) +
            "\n\nKết quả: artifacts/reports/pid_live/model_comparison.csv. Split theo process_path; "
            "chất lượng phụ thuộc nhãn và số executable nhóm đã thu thập.")


def main():
    parser = argparse.ArgumentParser(description="ProcessGuard process monitor and safe ML demonstration")
    parser.add_argument("--demo", action="store_true", help="Show simulated process records; never starts payloads")
    args = parser.parse_args()
    root = tk.Tk()
    ProcessGuardApp(root, demo=args.demo)
    root.mainloop()


if __name__ == "__main__":
    main()
