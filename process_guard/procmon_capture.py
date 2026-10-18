"""Short, bounded Process Monitor capture and CSV export wrapper for Windows."""
from __future__ import annotations

import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil

from .signature import authenticode_status

ROOT = Path(__file__).resolve().parents[1]

MAX_CAPTURE_SECONDS = 60
MAX_BACKING_FILE_BYTES = 256 * 1024 * 1024
PROC_MONITOR_NAMES = {"procmon.exe", "procmon64.exe", "procmon64a.exe"}


class ProcMonCaptureError(RuntimeError):
    pass


class ProcMonCapture:
    def __init__(self, output_dir: str | os.PathLike[str] = ROOT / "artifacts/reports/procmon"):
        self.output_dir = Path(output_dir).expanduser().resolve()
        self.procmon_exe: Path | None = None
        self.pml_path: Path | None = None
        self.csv_path: Path | None = None
        self.started_at: float | None = None

    @property
    def active(self) -> bool:
        return self.started_at is not None

    @property
    def elapsed_seconds(self) -> float:
        return max(0.0, time.monotonic() - self.started_at) if self.started_at else 0.0

    @property
    def backing_file_size(self) -> int:
        try:
            return self.pml_path.stat().st_size if self.pml_path else 0
        except OSError:
            return 0

    def start(self, executable: str | os.PathLike[str]) -> dict[str, Any]:
        if os.name != "nt":
            raise ProcMonCaptureError("ProcMon capture chỉ hỗ trợ Windows")
        if self.active:
            raise ProcMonCaptureError("Đang có một lượt ProcMon capture")
        procmon_exe = Path(executable).expanduser().resolve(strict=True)
        if not procmon_exe.is_file() or procmon_exe.name.casefold() not in PROC_MONITOR_NAMES:
            raise ProcMonCaptureError("Hãy chọn procmon.exe/procmon64.exe đã tải từ Sysinternals")
        signature_status, signer = authenticode_status(str(procmon_exe))
        if signature_status.casefold() != "valid" or "microsoft corporation" not in signer.casefold():
            raise ProcMonCaptureError(
                "Từ chối chạy ProcMon không có Authenticode hợp lệ của Microsoft Corporation")
        for process in psutil.process_iter(["name"]):
            try:
                if (process.info.get("name") or "").casefold() in PROC_MONITOR_NAMES:
                    raise ProcMonCaptureError("Một phiên ProcMon khác đang chạy; hãy đóng phiên đó trước")
            except psutil.AccessDenied:
                continue
            except psutil.NoSuchProcess:
                continue

        self.output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        base = self.output_dir / f"procmon_{stamp}_{os.getpid()}"
        pml_path = base.with_suffix(".pml")
        csv_path = base.with_suffix(".csv")
        args = [str(procmon_exe), "/AcceptEula", "/Quiet", "/Minimized",
                "/BackingFile", str(pml_path)]
        try:
            subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                             close_fds=True)
        except OSError as exc:
            raise ProcMonCaptureError(f"Không khởi chạy được ProcMon: {exc}") from exc

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if pml_path.exists():
                self.procmon_exe, self.pml_path, self.csv_path = procmon_exe, pml_path, csv_path
                self.started_at = time.monotonic()
                return {"pml_path": str(pml_path), "csv_path": str(csv_path),
                        "max_duration_seconds": MAX_CAPTURE_SECONDS,
                        "max_backing_bytes": MAX_BACKING_FILE_BYTES}
            time.sleep(0.2)
        try:
            subprocess.run([str(procmon_exe), "/Terminate"], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
        raise ProcMonCaptureError("ProcMon không tạo backing file; kiểm tra quyền quản trị và driver Sysinternals")

    def stop(self) -> dict[str, Any]:
        if not self.active or not self.procmon_exe or not self.pml_path or not self.csv_path:
            raise ProcMonCaptureError("Không có phiên capture đang chạy")
        executable, pml_path, csv_path = self.procmon_exe, self.pml_path, self.csv_path
        elapsed = self.elapsed_seconds
        try:
            terminate = subprocess.run([str(executable), "/Terminate"], stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                       timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                                       check=False)
            if terminate.returncode != 0:
                detail = (terminate.stderr or terminate.stdout or "").strip()
                raise ProcMonCaptureError(
                    f"ProcMon không dừng được capture ({terminate.returncode}): {detail[:800] or 'không có chi tiết'}")
            if not pml_path.is_file():
                raise ProcMonCaptureError("Không tìm thấy file PML sau khi dừng capture")
            if pml_path.stat().st_size > MAX_BACKING_FILE_BYTES:
                raise ProcMonCaptureError("PML vượt 256 MiB; giữ lại PML nhưng không tự export CSV lớn")
            export = subprocess.run(
                [str(executable), "/OpenLog", str(pml_path), "/SaveAs", str(csv_path), "/Quiet"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=120,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False,
            )
            if export.returncode != 0:
                detail = (export.stderr or export.stdout or "").strip()
                raise ProcMonCaptureError(
                    f"ProcMon export trả mã {export.returncode}: {detail[:800] or 'không có chi tiết'}")
            if not csv_path.is_file() or csv_path.stat().st_size == 0:
                detail = (export.stderr or export.stdout or "ProcMon không tạo CSV").strip()
                raise ProcMonCaptureError(f"Export CSV thất bại: {detail[:800]}")
            return {"pml_path": str(pml_path), "csv_path": str(csv_path),
                    "elapsed_seconds": elapsed, "pml_bytes": pml_path.stat().st_size,
                    "csv_bytes": csv_path.stat().st_size, "export_return_code": export.returncode}
        except subprocess.TimeoutExpired as exc:
            raise ProcMonCaptureError(f"ProcMon timeout khi dừng/export: {exc}") from exc
        except OSError as exc:
            raise ProcMonCaptureError(f"Lỗi hệ điều hành khi dừng/export ProcMon: {exc}") from exc
        finally:
            self.procmon_exe = self.pml_path = self.csv_path = None
            self.started_at = None
