"""Read-only process telemetry collection via psutil."""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any

import psutil


class ProcessCollector:
    def __init__(self) -> None:
        self._previous_io: dict[tuple[int, float], tuple[float, int, int, int, int]] = {}
        self._cpu_warmed: set[tuple[int, float]] = set()
        self._resource_history: dict[
            tuple[int, float], deque[tuple[float, float]]
        ] = {}
        probe = psutil.Process()
        self._handle_attr = "num_handles" if hasattr(probe, "num_handles") else "num_fds"

    def snapshot(self) -> list[dict[str, Any]]:
        now = time.monotonic()
        wall_now = time.time()
        attrs = ["pid", "name", "exe", "cmdline", "create_time", "memory_info",
                 "num_threads", "username", "cpu_percent", "io_counters", self._handle_attr]
        parent_map: dict[int, int] = {}
        if psutil.WINDOWS:
            # psutil's Windows Process.ppid() rebuilds the full parent map per
            # process; get that map once for a much faster process-tree snapshot.
            try:
                parent_map = psutil._psplatform.ppid_map()
            except (AttributeError, psutil.Error, OSError):
                attrs.append("ppid")
        else:
            attrs.append("ppid")
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
        except (psutil.AccessDenied, psutil.Error, OSError):
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
        return rows
