"""Draw the extra figures used in the written report (architecture, lab results, benchmark).

Usage:
    python scripts/build_report_figures.py [--eval-dir DIR] [--benchmark CSV]
Outputs PNG files to artifacts/reports/report_figures/.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
import pandas as pd

OUT = ROOT / "artifacts/reports/report_figures"
BLUE, ORANGE, GREEN, GREY, PURPLE = "#2563eb", "#ea580c", "#16a34a", "#64748b", "#7c3aed"


def _box(ax, x, y, w, h, title, body, color, title_size=11, body_size=8.6):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08",
                                linewidth=1.6, edgecolor=color, facecolor=color + "18"))
    ax.text(x + w / 2, y + h - 0.16, title, ha="center", va="top", fontsize=title_size, fontweight="bold", color=color)
    ax.text(x + w / 2, y + h - 0.5, body, ha="center", va="top", fontsize=body_size, color="#1f2937", linespacing=1.35)


def _arrow(ax, start, end, text="", color="#334155"):
    ax.add_patch(FancyArrowPatch(start, end, arrowstyle="-|>", mutation_scale=14, linewidth=1.4, color=color))
    if text:
        ax.text((start[0] + end[0]) / 2, (start[1] + end[1]) / 2 + 0.1, text, ha="center", fontsize=8, color=color)


def architecture() -> Path:
    fig, ax = plt.subplots(figsize=(13.6, 7.2))
    ax.set_xlim(0, 13.6)
    ax.set_ylim(0, 7.2)
    ax.axis("off")
    _box(ax, 0.2, 4.3, 2.6, 2.4, "Hệ điều hành", "Tiến trình đang chạy\nNtQuerySystemInformation\npsutil (exe, cmdline)\nSysmon / ProcMon\nAuthenticode, Registry,\nScheduled Tasks", GREY)
    _box(ax, 3.4, 4.3, 2.6, 2.4, "Process Monitor", "collector.py\nsnapshot mỗi 3 giây\nPID/PPID, CPU, RAM,\nthread, handle, kết nối,\nI/O, cây cha-con,\ncửa sổ trượt 5 lần quét", BLUE)
    _box(ax, 6.6, 4.3, 2.6, 2.4, "Feature Extractor", "features.py\n41 đặc trưng số:\ntĩnh (đường dẫn, tên,\nentropy, chữ ký),\nruntime, quan hệ\ncha-con, enrichment", BLUE)
    _box(ax, 9.8, 5.0, 3.0, 1.7, "Rule Engine", "rules.py\ntrọng số minh bạch\n(Temp, typosquatting,\nOffice → shell, ...)", ORANGE)
    _box(ax, 9.8, 2.75, 3.0, 1.75, "ML Classifier", "pid_ml.py / ml.py\nmodel PID tốt nhất\n(validation F1)\nngưỡng 0,65", PURPLE)
    _box(ax, 9.8, 0.4, 3.0, 1.85, "Alert / Report", "score = max(rule, ML)\nlog JSONL, đổi màu,\nkết thúc / cách ly /\nVirusTotal (có xác nhận)", GREEN)
    _box(ax, 6.6, 0.4, 2.6, 2.4, "Giao diện", "Desktop Tkinter\nWeb dashboard\n127.0.0.1:8765\nbảng/cây, chi tiết,\ncảnh báo, hiệu năng", GREEN)
    _box(ax, 3.4, 0.4, 2.6, 2.4, "Lưu trữ", "artifacts/logs\n(detections.jsonl)\nartifacts/models\nartifacts/reports\ndata/observations", GREY)
    _box(ax, 0.2, 0.4, 2.6, 3.3, "Huấn luyện offline", "Cardiff Dataset 2\n(telemetry sandbox)\n→ 11 mô hình, so sánh\n\nPID lab tự thu thập\n(nhãn + nguồn nhãn)\n→ 4 mô hình PID", GREY)
    _arrow(ax, (2.8, 5.5), (3.4, 5.5))
    _arrow(ax, (6.0, 5.5), (6.6, 5.5))
    _arrow(ax, (9.2, 5.85), (9.8, 5.85))
    _arrow(ax, (9.2, 4.9), (9.8, 3.9))
    ax.add_patch(FancyArrowPatch((12.8, 5.6), (12.8, 1.5), arrowstyle="-|>", mutation_scale=14, linewidth=1.4,
                                 color="#334155", connectionstyle="arc3,rad=-0.35"))
    _arrow(ax, (11.3, 2.75), (11.3, 2.25))
    _arrow(ax, (9.8, 1.4), (9.2, 1.4))
    _arrow(ax, (6.6, 1.4), (6.0, 1.4), "log / CSV")
    _arrow(ax, (2.8, 3.1), (9.8, 3.35), "model .joblib", PURPLE)
    _arrow(ax, (4.7, 4.3), (1.5, 3.7), "CSV quan sát có nhãn", GREY)
    ax.set_title("Kiến trúc tổng thể ProcessGuard", fontsize=14, fontweight="bold")
    path = OUT / "architecture.png"
    fig.savefig(path, dpi=170, bbox_inches="tight")
    plt.close(fig)
    return path


def lab_pipeline() -> Path:
    fig, ax = plt.subplots(figsize=(14, 1.9))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 1.6)
    ax.axis("off")
    steps = [("1. Triển khai", "5 chương trình .NET\nmô phỏng vô hại"),
             ("2. Chạy kịch bản", "mô phỏng + ứng dụng\nhợp lệ song song"),
             ("3. Thu thập", "collect_pid_samples\n2 giây/lần, có nhãn"),
             ("4. Huấn luyện", "EDA, chia tập theo\nfile thực thi"),
             ("5. Phiên mới", "evaluate_pid_sessions\nrule / ML / kết hợp"),
             ("6. Dọn dẹp", "kết thúc tiến trình,\nxóa thư mục pg_lab")]
    width = 2.0
    for index, (title, body) in enumerate(steps):
        x = 0.1 + index * 2.32
        _box(ax, x, 0.05, width, 1.45, title, body, [GREY, ORANGE, BLUE, PURPLE, GREEN, GREY][index], 10, 8.8)
        if index:
            _arrow(ax, (x - 0.3, 0.75), (x, 0.75))
    path = OUT / "lab_pipeline.png"
    fig.savefig(path, dpi=170, bbox_inches="tight")
    plt.close(fig)
    return path


def evaluation(eval_dir: Path) -> list[Path]:
    paths = []
    metrics = pd.read_csv(eval_dir / "detection_metrics.csv")
    unit = metrics[metrics["unit"] == "snapshot"] if "unit" in metrics else metrics
    fig, ax = plt.subplots(figsize=(9, 4.6))
    columns = [c for c in ["precision", "recall", "f1", "false_positive_rate"] if c in unit]
    width = 0.8 / max(1, len(unit))
    for i, (_, row) in enumerate(unit.iterrows()):
        values = [float(row[c]) if pd.notna(row[c]) else 0.0 for c in columns]
        bars = ax.bar([x + i * width for x in range(len(columns))], values, width, label=str(row.get("detector", row.iloc[0])))
        ax.bar_label(bars, fmt="%.3f", fontsize=8)
    ax.set_xticks([x + width * (len(unit) - 1) / 2 for x in range(len(columns))],
                  ["Precision", "Recall", "F1", "FPR"][:len(columns)])
    ax.set_ylim(0, 1.12)
    ax.legend(frameon=False, ncols=3, loc="upper center")
    ax.set_title("Phiên đánh giá mới: rule-based, ML và kết hợp (đơn vị snapshot)")
    ax.grid(axis="y", alpha=0.25)
    path = OUT / "evaluation_detectors.png"
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)
    paths.append(path)
    return paths


def benchmark(csv_path: Path) -> Path:
    data = pd.read_csv(csv_path, encoding="utf-8-sig")
    x = data["elapsed_seconds"] / 60
    fig, axes = plt.subplots(1, 3, figsize=(14, 4))
    axes[0].plot(x, data["host_cpu_percent"], color=GREY, linewidth=0.9, label="CPU toàn máy (%)")
    axes[0].plot(x, data["monitor_cpu_percent"], color=BLUE, linewidth=1.2, label="ProcessGuard (% một lõi)")
    axes[0].set_title("CPU")
    axes[0].legend(frameon=False, fontsize=8)
    axes[1].plot(x, data["monitor_rss_mb"], color=PURPLE, linewidth=1.2)
    axes[1].set_title("Bộ nhớ ProcessGuard (RSS, MB)")
    axes[1].set_ylim(0, max(200, data["monitor_rss_mb"].max() * 1.2))
    axes[2].plot(x, data["scan_ms"], color=ORANGE, linewidth=1.0)
    axes[2].set_yscale("log")
    axes[2].set_title("Thời gian một lần quét (ms, thang log)")
    for ax in axes:
        ax.set_xlabel("Phút")
        ax.grid(alpha=0.25)
    fig.suptitle("Tài nguyên tiêu tốn của dashboard ProcessGuard khi chạy nền 15 phút")
    fig.tight_layout()
    path = OUT / "benchmark_resources.png"
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--eval-dir", type=Path)
    parser.add_argument("--benchmark", type=Path)
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    produced = [architecture(), lab_pipeline()]
    if args.eval_dir:
        produced += evaluation(args.eval_dir)
    if args.benchmark:
        produced.append(benchmark(args.benchmark))
    print(json.dumps([str(p) for p in produced], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
