"""Optional, read-only parsing of recent Sysmon operational events."""
from __future__ import annotations

import os
import subprocess
import xml.etree.ElementTree as ET

CHANNEL = "Microsoft-Windows-Sysmon/Operational"
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def has_remote_memory_access_rights(fields: dict[str, str]) -> bool:
    """Flag Sysmon ProcessAccess rights commonly needed by injection tools.

    This is a triage hint only: legitimate debuggers, endpoint security, and
    accessibility tools can request the same rights.
    """
    raw = str(fields.get("GrantedAccess") or "").strip()
    if not raw:
        return False
    try:
        mask = int(raw, 0)
    except ValueError:
        try:
            mask = int(raw, 16)
        except ValueError:
            return False
    # PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
    required_for_remote_write = 0x0002 | 0x0008 | 0x0020
    return bool(mask & required_for_remote_write)


def recent_events(limit: int = 80) -> tuple[list[dict], str]:
    if os.name != "nt":
        return [], "Sysmon chỉ có trên Windows"
    query = "*[System[(EventID=1 or EventID=3 or EventID=8 or EventID=10 or EventID=11 or EventID=12 or EventID=13 or EventID=14 or EventID=22 or EventID=25)]]"
    try:
        result = subprocess.run(["wevtutil.exe", "qe", CHANNEL, "/q:" + query,
                                 "/rd:true", "/c:" + str(max(1, min(limit, 200))), "/f:xml"],
                                capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], str(exc)
    if result.returncode != 0:
        detail = (result.stderr or "Không truy vấn được Sysmon").strip()
        return [], detail
    try:
        root = ET.fromstring("<Events>" + result.stdout + "</Events>")
    except ET.ParseError as exc:
        return [], f"XML Sysmon không hợp lệ: {exc}"
    events = []
    for event in root.findall("e:Event", _NS):
        system = event.find("e:System", _NS)
        event_id_node = system.find("e:EventID", _NS) if system is not None else None
        time_node = system.find("e:TimeCreated", _NS) if system is not None else None
        fields = {node.attrib.get("Name", ""): node.text or ""
                  for node in event.findall("e:EventData/e:Data", _NS)}
        try:
            event_id = int(event_id_node.text) if event_id_node is not None else -1
        except (ValueError, TypeError):
            event_id = -1
        pid_value = fields.get("ProcessId") or fields.get("SourceProcessId") or "0"
        try:
            pid = int(pid_value, 0)
        except ValueError:
            try:
                pid = int(pid_value)
            except ValueError:
                pid = 0
        events.append({"event_id": event_id, "pid": pid,
                       "time": time_node.attrib.get("SystemTime", "") if time_node is not None else "",
                       "fields": fields})
    return events, "OK"
