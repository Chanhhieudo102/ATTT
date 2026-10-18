"""Shared feature schema for live process snapshots and training data."""
from __future__ import annotations

import math
import os
import re
from pathlib import Path
from typing import Any

FEATURE_COLUMNS = [
    "path_is_system", "path_is_user_writable", "path_is_temp", "path_is_missing",
    "path_is_program_files", "path_category_windows", "path_category_program_files",
    "path_category_temp", "path_category_other", "path_category_missing",
    "name_similarity_risk", "filename_entropy", "command_length", "unsigned_hint",
    "signature_checked", "signature_valid", "registry_run_persistence",
    "scheduled_task_checked", "scheduled_task_persistence",
    "sysmon_registry_run_hint",
    "sysmon_remote_memory_access_hint", "sysmon_remote_thread_hint",
    "sysmon_process_tampering_hint", "sysmon_file_create_events",
    "sysmon_dns_query_events",
    "cpu_percent", "cpu_avg_percent", "cpu_peak_percent",
    "memory_percent", "memory_avg_percent", "memory_peak_percent",
    "thread_count", "handle_count",
    "connection_count", "child_count", "file_read_rate_kbps", "file_write_rate_kbps",
    "file_read_ops_per_sec", "file_write_ops_per_sec",
    "parent_is_script_host", "runtime_minutes",
]

SYSTEM_NAMES = {
    "svchost.exe", "services.exe", "lsass.exe", "winlogon.exe", "csrss.exe",
    "smss.exe", "wininit.exe", "explorer.exe", "system", "system idle process",
}
SCRIPT_HOSTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "wscript.exe", "cscript.exe"}
SUSPICIOUS_NEAR_NAMES = ("svchost.exe", "explorer.exe", "services.exe", "lsass.exe", "chrome.exe")


def _norm_path(path: str | None) -> str:
    return os.path.normcase(os.path.abspath(path)) if path else ""


def _is_under(path: str, roots: list[str]) -> bool:
    for root in roots:
        try:
            if os.path.commonpath([path, root]) == root:
                return True
        except (ValueError, OSError):
            continue
    return False


def _trusted_roots() -> tuple[list[str], list[str], list[str]]:
    windows = os.environ.get("WINDIR", r"C:\Windows")
    program_files = [os.environ.get("ProgramFiles", r"C:\Program Files"),
                     os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")]
    if os.name != "nt":
        windows = "/usr"
        program_files = ["/opt", "/usr/local"]
    temp = [os.environ.get("TEMP", os.environ.get("TMP", "/tmp")), "/tmp"]
    return ([_norm_path(windows)], [_norm_path(p) for p in program_files if p],
            [_norm_path(p) for p in temp if p])


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(cur[-1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _name_risk(name: str) -> float:
    low = name.lower()
    if low in SYSTEM_NAMES or not low:
        return 0.0
    risk = 0.0
    for known in SUSPICIOUS_NEAR_NAMES:
        base, ext = os.path.splitext(known)
        candidate, candidate_ext = os.path.splitext(low)
        if candidate_ext == ext and candidate != base and _levenshtein(candidate, base) <= 1:
            risk = max(risk, 1.0)
    return risk


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    from collections import Counter
    n = len(value)
    return -sum((count / n) * math.log2(count / n) for count in Counter(value).values())


def extract_features(record: dict[str, Any]) -> dict[str, float]:
    """Map one process record to the stable numeric model schema.

    ``unsigned_hint`` is an optional input from an external signature scanner. It
    defaults to zero because psutil does not verify Authenticode signatures.
    """
    name = str(record.get("name") or "").lower()
    path = _norm_path(record.get("exe"))
    windows_roots, program_roots, temp_roots = _trusted_roots()
    trusted_roots = windows_roots + program_roots
    parent_name = str(record.get("parent_name") or "").lower()
    runtime = max(0.0, float(record.get("runtime_minutes") or 0))
    basename = Path(record.get("exe") or name).name.lower()
    path_is_windows = bool(path and _is_under(path, windows_roots))
    path_is_program_files = bool(path and _is_under(path, program_roots))
    path_is_temp = bool(path and _is_under(path, temp_roots))
    path_is_missing = not bool(path)
    path_is_other = bool(path and not (path_is_windows or path_is_program_files or path_is_temp))
    signature_status = str(record.get("authenticode_status") or "").casefold()
    signature_checked = bool(record.get("signature_checked", False))
    signature_valid = bool(record.get("signature_valid", signature_status == "valid"))
    cpu = max(0.0, float(record.get("cpu_percent") or 0))
    memory = max(0.0, float(record.get("memory_percent") or 0))
    return {
        "path_is_system": float(path_is_windows),
        "path_is_user_writable": float(bool(path and not _is_under(path, trusted_roots))),
        "path_is_temp": float(path_is_temp),
        "path_is_missing": float(path_is_missing),
        "path_is_program_files": float(path_is_program_files),
        "path_category_windows": float(path_is_windows),
        "path_category_program_files": float(not path_is_windows and path_is_program_files),
        "path_category_temp": float(not path_is_windows and not path_is_program_files and path_is_temp),
        "path_category_other": float(path_is_other),
        "path_category_missing": float(path_is_missing),
        "name_similarity_risk": _name_risk(name),
        "filename_entropy": _entropy(basename),
        "command_length": float(len(str(record.get("cmdline") or ""))),
        "unsigned_hint": float(bool(record.get("unsigned_hint", False))),
        "signature_checked": float(signature_checked),
        "signature_valid": float(signature_valid and signature_checked),
        "registry_run_persistence": float(bool(record.get("registry_run_persistence", False))),
        "scheduled_task_checked": float(bool(record.get("scheduled_task_checked", False))),
        "scheduled_task_persistence": float(bool(record.get("scheduled_task_persistence", False))),
        "sysmon_registry_run_hint": float(bool(record.get("sysmon_registry_run_hint", False))),
        "sysmon_remote_memory_access_hint": float(bool(record.get("sysmon_remote_memory_access_hint", False))),
        "sysmon_remote_thread_hint": float(bool(record.get("sysmon_remote_thread_hint", False))),
        "sysmon_process_tampering_hint": float(bool(record.get("sysmon_process_tampering_hint", False))),
        "sysmon_file_create_events": max(0.0, float(record.get("sysmon_file_create_events") or 0)),
        "sysmon_dns_query_events": max(0.0, float(record.get("sysmon_dns_query_events") or 0)),
        "cpu_percent": cpu,
        "cpu_avg_percent": max(0.0, float(record.get("cpu_avg_percent", cpu) or 0)),
        "cpu_peak_percent": max(0.0, float(record.get("cpu_peak_percent", cpu) or 0)),
        "memory_percent": memory,
        "memory_avg_percent": max(0.0, float(record.get("memory_avg_percent", memory) or 0)),
        "memory_peak_percent": max(0.0, float(record.get("memory_peak_percent", memory) or 0)),
        "thread_count": max(0.0, float(record.get("thread_count") or 0)),
        "handle_count": max(0.0, float(record.get("handle_count") or 0)),
        "connection_count": max(0.0, float(record.get("connection_count") or 0)),
        "child_count": max(0.0, float(record.get("child_count") or 0)),
        "file_read_rate_kbps": max(0.0, float(record.get("file_read_rate_kbps") or 0)),
        "file_write_rate_kbps": max(0.0, float(record.get("file_write_rate_kbps") or 0)),
        "file_read_ops_per_sec": max(0.0, float(record.get("file_read_ops_per_sec") or 0)),
        "file_write_ops_per_sec": max(0.0, float(record.get("file_write_ops_per_sec") or 0)),
        "parent_is_script_host": float(parent_name in SCRIPT_HOSTS),
        "runtime_minutes": runtime,
    }
