"""Safe process-shaped fixtures for demonstrations; no process is started."""
from __future__ import annotations

from datetime import datetime
import os


def demo_records() -> list[dict]:
    now = datetime.now().timestamp()
    demo_temp = os.environ.get("TEMP", r"C:\Users\Demo\AppData\Local\Temp")
    rows = [
        {"pid": 4100, "name": "explorer.exe", "ppid": 1,
         "exe": r"C:\Windows\explorer.exe", "cmdline": r"C:\Windows\explorer.exe",
         "parent_name": "winlogon.exe", "cpu_percent": 2.2, "memory_percent": 1.4,
         "thread_count": 48, "handle_count": 980, "connection_count": 0, "child_count": 3,
         "file_read_rate_kbps": 0.0, "file_write_rate_kbps": 4.0, "username": "demo",
         "create_time": now - 3600, "runtime_minutes": 60, "_demo_only": True},
        {"pid": 4101, "name": "chrome.exe", "ppid": 4100,
         "exe": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
         "cmdline": 'chrome.exe --profile-directory=Default', "parent_name": "explorer.exe",
         "cpu_percent": 10.0, "memory_percent": 4.0, "thread_count": 32, "handle_count": 470,
         "connection_count": 4, "child_count": 0, "file_read_rate_kbps": 64.0,
         "file_write_rate_kbps": 12.0, "username": "demo", "create_time": now - 900,
         "runtime_minutes": 15, "_demo_only": True},
        {"pid": 4102, "name": "WINWORD.EXE", "ppid": 4100,
         "exe": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
         "cmdline": 'WINWORD.EXE /safe', "parent_name": "explorer.exe",
         "cpu_percent": 3.0, "memory_percent": 2.3, "thread_count": 18, "handle_count": 350,
         "connection_count": 0, "child_count": 1, "file_read_rate_kbps": 2.0,
         "file_write_rate_kbps": 3.0, "username": "demo", "create_time": now - 1200,
         "runtime_minutes": 20, "_demo_only": True},
        {"pid": 4103, "name": "svch0st.exe", "ppid": 4102,
         "exe": os.path.join(demo_temp, "svch0st.exe"),
         "cmdline": os.path.join(demo_temp, "svch0st.exe") + " --connect demo.invalid",
         "parent_name": "WINWORD.EXE", "cpu_percent": 93.0, "memory_percent": 8.5,
         "thread_count": 38, "handle_count": 210, "connection_count": 16, "child_count": 2,
         "file_read_rate_kbps": 900.0, "file_write_rate_kbps": 4800.0, "username": "demo",
         "create_time": now - 35, "runtime_minutes": 0.58, "_demo_only": True},
        {"pid": 4104, "name": "powershell.exe", "ppid": 4103,
         "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "cmdline": "powershell.exe -NoProfile (demo record only)", "parent_name": "svch0st.exe",
         "cpu_percent": 1.0, "memory_percent": 0.8, "thread_count": 7, "handle_count": 65,
         "connection_count": 0, "child_count": 0, "file_read_rate_kbps": 0.0,
         "file_write_rate_kbps": 0.0, "username": "demo", "create_time": now - 8,
         "runtime_minutes": 0.13, "_demo_only": True},
    ]
    for row in rows:
        row.setdefault("unsigned_hint", 0)
    return rows
