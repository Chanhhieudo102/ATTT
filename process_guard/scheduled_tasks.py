"""Read-only Scheduled Task action inspection for Windows persistence triage."""
from __future__ import annotations

import json
import os
import shutil
import subprocess


def _resolved_path(value: str) -> str:
    value = os.path.expandvars(os.path.expanduser(str(value or "").strip().strip('"')))
    if not value:
        return ""
    candidate = value if os.path.isabs(value) else (shutil.which(value) or "")
    if not candidate:
        return ""
    return os.path.normcase(os.path.abspath(candidate))


def tasks_for_executable(executable: str, timeout: float = 15.0) -> tuple[list[dict], str]:
    """Return task actions whose executable path exactly matches ``executable``.

    This checks configured task actions only. A match does not prove that a task
    launched the currently selected process.
    """
    if os.name != "nt":
        return [], "Scheduled Tasks chỉ được hỗ trợ trên Windows"
    target = _resolved_path(executable)
    if not target:
        return [], "Không có đường dẫn executable để đối chiếu"

    script = r"""
$ErrorActionPreference = 'Stop'
$rows = @(Get-ScheduledTask | ForEach-Object {
  $task = $_
  foreach ($action in @($task.Actions)) {
    if ($null -ne $action -and $action.Execute) {
      [PSCustomObject]@{
        TaskPath = [string]$task.TaskPath
        TaskName = [string]$task.TaskName
        Execute = [string]$action.Execute
        Arguments = [string]$action.Arguments
      }
    }
  }
})
ConvertTo-Json -InputObject $rows -Compress -Depth 3
"""
    kwargs = {}
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False, **kwargs,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], str(exc)
    if result.returncode != 0:
        return [], (result.stderr or "Không truy vấn được Scheduled Tasks").strip()
    try:
        payload = json.loads(result.stdout.strip() or "[]")
    except json.JSONDecodeError as exc:
        return [], f"JSON Scheduled Tasks không hợp lệ: {exc}"
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list):
        return [], "Dữ liệu Scheduled Tasks không đúng định dạng"

    matches = []
    for action in payload:
        if not isinstance(action, dict) or _resolved_path(action.get("Execute", "")) != target:
            continue
        matches.append({
            "task": f"{action.get('TaskPath', '')}{action.get('TaskName', '')}",
            "execute": action.get("Execute", ""),
            "arguments": action.get("Arguments", ""),
        })
    return matches, "OK"
