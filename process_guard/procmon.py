"""Bounded aggregation of a user-exported Microsoft Process Monitor CSV."""
from __future__ import annotations

import csv
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

MAX_CSV_BYTES = 64 * 1024 * 1024
MAX_ROWS = 1_000_000
MAX_PROCESS_GROUPS = 100_000


def _header_map(fieldnames: list[str] | None) -> dict[str, str]:
    if not fieldnames:
        raise ValueError("CSV không có hàng tiêu đề")
    return {name.strip().casefold(): name for name in fieldnames if name}


def aggregate_procmon_csv(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Aggregate read/write and sensitive Run-key operations from ProcMon CSV.

    The file is size and row bounded. Process identity in the export is only
    PID + image name, so callers must treat a match to a live PID as a hint.
    """
    csv_path = Path(path)
    size = csv_path.stat().st_size
    if size > MAX_CSV_BYTES:
        raise ValueError(f"CSV vượt giới hạn {MAX_CSV_BYTES // (1024 * 1024)} MiB")
    if size == 0:
        raise ValueError("CSV rỗng")

    with csv_path.open("rb") as raw:
        prefix = raw.read(4)
    encoding = "utf-16" if prefix.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"

    groups: dict[tuple[int, str], dict[str, Any]] = defaultdict(
        lambda: {"events": 0, "file_read_events": 0, "file_write_events": 0,
                 "registry_sensitive_events": 0, "first_time": "", "last_time": ""}
    )
    rows_read = 0
    dropped_rows = 0
    with csv_path.open("r", encoding=encoding, errors="replace", newline="") as stream:
        reader = csv.DictReader(stream)
        headers = _header_map(reader.fieldnames)
        required = {"process name", "pid", "operation", "path"}
        if not required.issubset(headers):
            missing = ", ".join(sorted(required - set(headers)))
            raise ValueError(f"Thiếu cột ProcMon: {missing}")

        def value(record: dict[str, str], key: str) -> str:
            column = headers.get(key)
            return (record.get(column, "") or "").strip() if column else ""

        for record in reader:
            rows_read += 1
            if rows_read > MAX_ROWS:
                raise ValueError(f"CSV vượt giới hạn {MAX_ROWS:,} dòng dữ liệu")
            try:
                pid = int(value(record, "pid"), 10)
            except ValueError:
                dropped_rows += 1
                continue
            process_name = Path(value(record, "process name").replace("\\", "/")).name.casefold()
            if pid <= 0 or not process_name:
                dropped_rows += 1
                continue

            operation = value(record, "operation").casefold()
            object_path = value(record, "path").replace("/", "\\").casefold()
            identity = (pid, process_name)
            if identity not in groups and len(groups) >= MAX_PROCESS_GROUPS:
                raise ValueError(f"CSV vượt giới hạn {MAX_PROCESS_GROUPS:,} nhóm PID/tên")
            stats = groups[identity]
            stats["events"] += 1
            if operation == "readfile":
                stats["file_read_events"] += 1
            elif operation == "writefile":
                stats["file_write_events"] += 1
            if operation.startswith("reg") and re.search(
                r"\\currentversion\\run(?:once)?(?:\\|$)", object_path
            ):
                stats["registry_sensitive_events"] += 1
            event_time = value(record, "time of day")
            if event_time:
                if not stats["first_time"]:
                    stats["first_time"] = event_time
                stats["last_time"] = event_time

    return {"file": str(csv_path), "file_size_bytes": size, "rows_read": rows_read,
            "dropped_rows": dropped_rows, "by_process": dict(groups)}


def match_live_process(summary: dict[str, Any], pid: int, name: str) -> dict[str, Any] | None:
    """Find an exported process row by PID and basename (not a durable identity)."""
    process_name = Path(str(name or "").replace("\\", "/")).name.casefold()
    return summary.get("by_process", {}).get((int(pid), process_name))
