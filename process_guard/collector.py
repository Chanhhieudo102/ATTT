"""Read-only process telemetry collection via psutil."""
from __future__ import annotations

import ctypes
import struct
import time
from collections import defaultdict, deque
from types import SimpleNamespace
from typing import Any

import psutil

_FILETIME_EPOCH_OFFSET = 11644473600.0  # seconds between 1601-01-01 and 1970-01-01


def _query_windows_processes() -> list[dict[str, Any]] | None:
    """Return per-process counters from ONE NtQuerySystemInformation call.

    psutil falls back to a full system process query *per process* for thread counts and
    for protected processes, which made a 320-process snapshot take ~10 s. Reading the
    SYSTEM_PROCESS_INFORMATION list once keeps a snapshot well under a second.
    Returns None when the API is unavailable so the caller can use plain psutil.
    """
    if not psutil.WINDOWS or ctypes.sizeof(ctypes.c_void_p) != 8:
        return None
    try:
        ntdll = ctypes.WinDLL("ntdll")
        size = ctypes.c_ulong(1 << 20)
        for _ in range(8):
            buffer = ctypes.create_string_buffer(size.value)
            needed = ctypes.c_ulong(0)
            status = ntdll.NtQuerySystemInformation(5, buffer, size, ctypes.byref(needed))
            if status == 0:
                break
            if status & 0xFFFFFFFF != 0xC0000004:  # STATUS_INFO_LENGTH_MISMATCH
                return None
            size = ctypes.c_ulong(max(needed.value, size.value) + (1 << 16))
        else:
            return None
        raw = buffer.raw
        records, offset = [], 0
        while True:
            next_offset, threads = struct.unpack_from("<II", raw, offset)
            create, user, kernel = struct.unpack_from("<qqq", raw, offset + 32)
            name_length, _, name_pointer = struct.unpack_from("<HHxxxxQ", raw, offset + 56)
            pid, ppid = struct.unpack_from("<QQ", raw, offset + 80)
            handles = struct.unpack_from("<I", raw, offset + 96)[0]
            working_set = struct.unpack_from("<Q", raw, offset + 144)[0]
            io = struct.unpack_from("<QQQQQQ", raw, offset + 208)
            name = ""
            if name_pointer and name_length:
                name = ctypes.wstring_at(name_pointer, name_length // 2)
            records.append({
                "pid": int(pid), "ppid": int(ppid), "name": name or ("System Idle Process" if pid == 0 else ""),
                "num_threads": int(threads), "num_handles": int(handles),
                "create_time": create / 1e7 - _FILETIME_EPOCH_OFFSET if create else 0.0,
                "cpu_seconds": (user + kernel) / 1e7, "rss": int(working_set),
                "io": SimpleNamespace(read_count=io[0], write_count=io[1], read_bytes=io[3], write_bytes=io[4]),
            })
            if not next_offset:
                return records
            offset += next_offset
    except (OSError, AttributeError, ValueError, struct.error):
        return None


class ProcessCollector:
    def __init__(self) -> None:
        self._previous_io: dict[tuple[int, float], tuple[float, int, int, int, int]] = {}
        self._cpu_warmed: set[tuple[int, float]] = set()
        self._resource_history: dict[
            tuple[int, float], deque[tuple[float, float]]
        ] = {}
        # Static per-instance fields (exe, cmdline, username) never change for a process.
        self._static_info: dict[tuple[int, float], dict[str, Any]] = {}
        self._previous_cpu: dict[tuple[int, float], tuple[float, float]] = {}
        probe = psutil.Process()
        self._handle_attr = "num_handles" if hasattr(probe, "num_handles") else "num_fds"

    def _static(self, pid: int, create_time: float, name: str) -> dict[str, Any]:
        identity = (pid, create_time)
        cached = self._static_info.get(identity)
        if cached is None:
            cached = {"exe": None, "cmdline": None, "username": None}
            if pid > 4:
                try:
                    proc = psutil.Process(pid)
                    with proc.oneshot():
                        for field in cached:
                            try:
                                cached[field] = getattr(proc, field)()
                            except (psutil.Error, OSError):
                                pass
                except (psutil.Error, OSError):
                    pass
            self._static_info[identity] = cached
        return cached

    def _windows_infos(self, records: list[dict[str, Any]], now: float) -> list[dict[str, Any]]:
        infos = []
        for record in records:
            pid, create_time = record["pid"], record["create_time"]
            identity = (pid, create_time)
            previous = self._previous_cpu.get(identity)
            cpu = 0.0
            if previous and now > previous[0]:
                # psutil semantics: 100 means one fully used logical CPU.
                cpu = max(0.0, (record["cpu_seconds"] - previous[1]) / (now - previous[0]) * 100)
            self._previous_cpu[identity] = (now, record["cpu_seconds"])
            static = self._static(pid, create_time, record["name"])
            infos.append({
                "pid": pid, "name": record["name"], "exe": static["exe"], "cmdline": static["cmdline"],
                "create_time": create_time, "memory_info": SimpleNamespace(rss=record["rss"]),
                "num_threads": record["num_threads"], "username": static["username"],
                "cpu_percent": 0.0 if pid == 0 else cpu, "io_counters": record["io"],
                self._handle_attr: record["num_handles"], "_resolved_ppid": record["ppid"],
            })
        return infos

    def snapshot(self) -> list[dict[str, Any]]:
        now = time.monotonic()
        wall_now = time.time()
        attrs = ["pid", "name", "exe", "cmdline", "create_time", "memory_info",
                 "num_threads", "username", "cpu_percent", "io_counters", self._handle_attr]
        parent_map: dict[int, int] = {}
        fast_records = _query_windows_processes()
        if fast_records is not None:
            procs = [SimpleNamespace(info=info) for info in self._windows_infos(fast_records, now)]
            parent_map = {info.info["pid"]: info.info["_resolved_ppid"] for info in procs}
        elif psutil.WINDOWS:
            # psutil's Windows Process.ppid() rebuilds the full parent map per
            # process; get that map once for a much faster process-tree snapshot.
            try:
                parent_map = psutil._psplatform.ppid_map()
            except (AttributeError, psutil.Error, OSError):
                attrs.append("ppid")
        else:
            attrs.append("ppid")
        if fast_records is None:
            procs = list(psutil.process_iter(attrs=attrs, ad_value=None))
        children: dict[int, int] = defaultdict(int)
        parent_names: dict[int, str] = {}
        process_info: list[tuple[psutil.Process, dict[str, Any]]] = []
        live_identities: set[tuple[int, float]] = set()
        for proc in procs:
            info = proc.info
            pid = info.get("pid")
            if pid is None:
                continue
            process_info.append((proc, info))
            parent_names[int(pid)] = str(info.get("name") or "")
            create_time = float(info.get("create_time") or wall_now)
            identity = (int(pid), create_time)
            live_identities.add(identity)
            ppid = parent_map.get(int(pid), 0) if parent_map else info.get("ppid")
            info["_resolved_ppid"] = int(ppid or 0)
            if ppid:
                children[int(ppid)] += 1

        connections_by_pid: dict[int, list[dict[str, str]]] = defaultdict(list)
        try:
            # A single system query avoids the cost of querying sockets per PID.
            for conn in psutil.net_connections(kind="inet"):
                if conn.pid is None:
                    continue
                connections_by_pid[int(conn.pid)].append({
                    "local": str(conn.laddr) if conn.laddr else "",
                    "remote": str(conn.raddr) if conn.raddr else "",
                    "status": str(conn.status or ""),
                })
        except (psutil.AccessDenied, psutil.Error, OSError, RuntimeError):
            # Windows may raise a native RuntimeError when TCP table access is
            # restricted. Keep the process snapshot available without sockets.
            pass

        try:
            memory_total = float(psutil.virtual_memory().total) or 1.0
        except (psutil.Error, OSError):
            memory_total = 1.0
        rows = []
        for proc, info in process_info:
            try:
                pid = int(info["pid"])
                create_time = float(info.get("create_time") or wall_now)
                cpu = float(info.get("cpu_percent") or 0.0)
                identity = (pid, create_time)
                if identity not in self._cpu_warmed:
                    cpu = 0.0
                    self._cpu_warmed.add(identity)
                connections = connections_by_pid.get(pid, [])
                counters = info.get("io_counters")
                read_rate = write_rate = read_ops_rate = write_ops_rate = 0.0
                if counters is not None:
                    identity = (pid, create_time)
                    previous = self._previous_io.get(identity)
                    if previous and now > previous[0]:
                        elapsed = now - previous[0]
                        read_rate = max(0, counters.read_bytes - previous[1]) / 1024 / elapsed
                        write_rate = max(0, counters.write_bytes - previous[2]) / 1024 / elapsed
                        read_ops_rate = max(0, counters.read_count - previous[3]) / elapsed
                        write_ops_rate = max(0, counters.write_count - previous[4]) / elapsed
                    self._previous_io[identity] = (
                        now, int(counters.read_bytes), int(counters.write_bytes),
                        int(counters.read_count), int(counters.write_count),
                    )
                memory_info = info.get("memory_info")
                memory_percent = float(memory_info.rss / memory_total * 100) if memory_info else 0.0
                identity = (pid, create_time)
                history = self._resource_history.setdefault(identity, deque(maxlen=5))
                history.append((cpu, memory_percent))
                cpu_values = [sample[0] for sample in history]
                memory_values = [sample[1] for sample in history]
                rows.append({
                    "pid": pid, "name": info.get("name") or "?", "ppid": int(info.get("_resolved_ppid") or 0),
                    "exe": info.get("exe") or "", "cmdline": " ".join(info.get("cmdline") or []),
                    "create_time": create_time, "runtime_minutes": max(0.0, (wall_now - create_time) / 60),
                    "cpu_percent": cpu,
                    "memory_percent": memory_percent,
                    "cpu_avg_percent": sum(cpu_values) / len(cpu_values),
                    "cpu_peak_percent": max(cpu_values, default=cpu),
                    "memory_avg_percent": sum(memory_values) / len(memory_values),
                    "memory_peak_percent": max(memory_values, default=memory_percent),
                    "thread_count": int(info.get("num_threads") or 0),
                    "handle_count": int(info.get(self._handle_attr) or 0),
                    "connection_count": len(connections), "connections": connections,
                    "child_count": int(children.get(pid, 0)),
                    "parent_name": parent_names.get(int(info.get("_resolved_ppid") or 0), ""),
                    "file_read_rate_kbps": read_rate, "file_write_rate_kbps": write_rate,
                    "file_read_ops_per_sec": read_ops_rate,
                    "file_write_ops_per_sec": write_ops_rate,
                    "username": info.get("username") or "",
                })
            except (psutil.Error, OSError, KeyError, TypeError, ValueError):
                continue
        self._previous_io = {identity: value for identity, value in self._previous_io.items()
                             if identity in live_identities}
        self._resource_history = {identity: value for identity, value in self._resource_history.items()
                                  if identity in live_identities}
        self._cpu_warmed.intersection_update(live_identities)
        self._static_info = {identity: value for identity, value in self._static_info.items()
                             if identity in live_identities}
        self._previous_cpu = {identity: value for identity, value in self._previous_cpu.items()
                              if identity in live_identities}
        return rows
