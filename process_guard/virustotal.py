"""VirusTotal public API hash lookup. File contents are never uploaded."""
from __future__ import annotations

import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

API_BASE = "https://www.virustotal.com/api/v3/files/"


class VirusTotalLookupError(RuntimeError):
    pass


def lookup_sha256(sha256: str, api_key: str, timeout: float = 12.0) -> dict:
    digest = str(sha256 or "").strip().lower()
    key = str(api_key or "").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("SHA-256 phải gồm đúng 64 ký tự hex")
    if not key:
        raise ValueError("Cần VirusTotal API key")

    request = Request(API_BASE + digest, headers={
        "accept": "application/json", "x-apikey": key,
        "user-agent": "ProcessGuard/1.0 (hash lookup only)",
    })
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))
    except HTTPError as exc:
        if exc.code == 404:
            return {"status": "not_found", "sha256": digest}
        if exc.code in (401, 403):
            raise VirusTotalLookupError("API key không hợp lệ hoặc không có quyền truy vấn") from exc
        if exc.code == 429:
            raise VirusTotalLookupError("VirusTotal từ chối do vượt quota/rate limit") from exc
        raise VirusTotalLookupError(f"VirusTotal trả HTTP {exc.code}") from exc
    except URLError as exc:
        raise VirusTotalLookupError(f"Không kết nối được VirusTotal: {exc.reason}") from exc
    except (TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VirusTotalLookupError(f"Phản hồi VirusTotal không hợp lệ: {exc}") from exc

    attributes = payload.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {}) or {}
    return {
        "status": "found",
        "sha256": digest,
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "harmless": int(stats.get("harmless", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
        "reputation": int(attributes.get("reputation", 0) or 0),
        "meaningful_name": str(attributes.get("meaningful_name", "") or ""),
        "names": [str(name) for name in (attributes.get("names", []) or [])[:8]],
        "type_description": str(attributes.get("type_description", "") or ""),
        "last_analysis_date": attributes.get("last_analysis_date"),
    }
