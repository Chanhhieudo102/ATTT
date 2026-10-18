"""On-demand Windows Authenticode and local SHA-256 reputation checks."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def authenticode_status(path: str, timeout: int = 8) -> tuple[str, str]:
    if os.name != "nt":
        return "unsupported", "Authenticode chỉ hỗ trợ trên Windows"
    if not path or not Path(path).is_file():
        return "unavailable", "Không đọc được file thực thi"
    escaped = path.replace("'", "''")
    script = ("$s=Get-AuthenticodeSignature -LiteralPath '" + escaped + "'; "
              "Write-Output ($s.Status.ToString() + '|' + $s.SignerCertificate.Subject)")
    try:
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                                capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "error", str(exc)
    if result.returncode != 0:
        return "error", (result.stderr or "PowerShell returned an error").strip()
    output = result.stdout.strip().split("|", 1)
    return (output[0] if output else "unknown", output[1] if len(output) > 1 else "")


def sha256_reputation(path: str, blocklist: str | Path = ROOT / "data/reference/hash_blocklist.json") -> tuple[str, str]:
    file_path = Path(path)
    if not path or not file_path.is_file():
        return "", "Không đọc được file thực thi"
    digest = hashlib.sha256()
    try:
        with file_path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        return "", str(exc)
    sha = digest.hexdigest()
    try:
        entries = json.loads(Path(blocklist).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        entries = {}
    label = entries.get(sha, "Không có trong blocklist cục bộ") if isinstance(entries, dict) else "Blocklist sai định dạng"
    return sha, str(label)
