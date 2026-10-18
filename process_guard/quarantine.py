"""Reversible, hash-verified quarantine for a user-selected executable."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


class QuarantineError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_within(path: Path, directory: Path) -> bool:
    try:
        normalized_path = os.path.normcase(os.path.abspath(path))
        normalized_directory = os.path.normcase(os.path.abspath(directory))
        return os.path.commonpath((normalized_path, normalized_directory)) == normalized_directory
    except ValueError:
        return False


def _quarantine_root(path: str | os.PathLike[str]) -> Path:
    root = Path(path).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def quarantine_file(source: str | os.PathLike[str], quarantine_dir: str | os.PathLike[str]
                    = ROOT / "artifacts/quarantine") -> dict[str, Any]:
    source_path = Path(source).expanduser()
    if source_path.is_symlink() or not source_path.is_file():
        raise QuarantineError("Chỉ cách ly file thường; không chấp nhận symlink hoặc đường dẫn không phải file")
    try:
        source_path = source_path.resolve(strict=True)
    except OSError as exc:
        raise QuarantineError(f"Không phân giải được file nguồn: {exc}") from exc
    quarantine_root = _quarantine_root(quarantine_dir)
    if _is_within(source_path, quarantine_root):
        raise QuarantineError("File đã nằm trong thư mục cách ly")

    windows_root = Path(os.environ.get("WINDIR", r"C:\Windows")).resolve()
    if _is_within(source_path, windows_root):
        raise QuarantineError("Từ chối cách ly file nằm trong thư mục Windows")

    stage_path = stored_path = metadata_tmp = metadata_path = None
    try:
        source_digest = _sha256(source_path)
        token = uuid.uuid4().hex
        safe_stem = re.sub(r"[^\w.-]+", "_", source_path.stem)[:80].strip(" .") or "file"
        # Deliberately discard the executable extension while quarantined so
        # accidental double-clicking does not launch the stored sample.
        stored_name = f"{source_digest[:16]}_{token[:12]}_{safe_stem}.quarantined"
        stored_path = quarantine_root / stored_name
        stage_path = quarantine_root / f".{token}.partial"
        metadata_path = quarantine_root / f"{stored_name}.json"
        metadata_tmp = quarantine_root / f".{token}.json.partial"
        shutil.copy2(source_path, stage_path)
        if _sha256(stage_path) != source_digest or _sha256(source_path) != source_digest:
            raise QuarantineError("Hash file thay đổi trong lúc sao chép; hủy cách ly")
        stage_path.rename(stored_path)
        metadata = {
            "schema_version": 1,
            "quarantined_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source_path": str(source_path),
            "stored_name": stored_name,
            "sha256": source_digest,
            "size_bytes": stored_path.stat().st_size,
        }
        metadata_tmp.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
        metadata_tmp.rename(metadata_path)
        if _sha256(source_path) != source_digest:
            raise QuarantineError("Hash file nguồn đổi trước khi xóa bản gốc; hủy thao tác")
        source_path.unlink()
        return {**metadata, "quarantine_path": str(stored_path), "metadata_path": str(metadata_path)}
    except Exception as exc:
        for leftover in (stage_path, stored_path, metadata_tmp, metadata_path):
            if leftover is not None:
                try:
                    leftover.unlink(missing_ok=True)
                except OSError:
                    pass
        if isinstance(exc, QuarantineError):
            raise
        raise QuarantineError(f"Không cách ly được file: {exc}") from exc


def restore_file(metadata_file: str | os.PathLike[str], quarantine_dir: str | os.PathLike[str]
                 = ROOT / "artifacts/quarantine") -> dict[str, Any]:
    quarantine_root = Path(quarantine_dir).expanduser().resolve()
    metadata_path = Path(metadata_file).expanduser().resolve(strict=True)
    if not _is_within(metadata_path, quarantine_root) or metadata_path.suffix.casefold() != ".json":
        raise QuarantineError("Hãy chọn file metadata .json nằm trong thư mục quarantine của ứng dụng")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QuarantineError(f"Metadata quarantine lỗi: {exc}") from exc
    stored_name = str(metadata.get("stored_name") or "")
    digest = str(metadata.get("sha256") or "").lower()
    source_value = str(metadata.get("source_path") or "")
    if (not stored_name or Path(stored_name).name != stored_name
            or not re.fullmatch(r"[0-9a-f]{64}", digest) or not source_value):
        raise QuarantineError("Metadata quarantine thiếu hoặc sai thông tin")
    stored_candidate = quarantine_root / stored_name
    if stored_candidate.is_symlink():
        raise QuarantineError("File cách ly không hợp lệ")
    stored_path = stored_candidate.resolve(strict=True)
    if not _is_within(stored_path, quarantine_root) or not stored_path.is_file():
        raise QuarantineError("File cách ly không hợp lệ")
    if _sha256(stored_path) != digest:
        raise QuarantineError("Hash file cách ly không khớp metadata; không khôi phục")
    destination = Path(source_value)
    if not destination.is_absolute() or not destination.parent.is_dir():
        raise QuarantineError("Thư mục gốc không còn tồn tại hoặc đường dẫn đích không hợp lệ")
    destination = destination.parent.resolve() / destination.name
    if _is_within(destination, quarantine_root):
        raise QuarantineError("Đích khôi phục không được nằm trong quarantine")
    if destination.exists():
        raise QuarantineError("Đã có file ở đường dẫn gốc; không ghi đè. Hãy xử lý bản hiện tại trước")

    stage_path = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.restore"
    try:
        shutil.copy2(stored_path, stage_path)
        if _sha256(stage_path) != digest:
            raise QuarantineError("Hash bản khôi phục không khớp")
        # Hard-link creation is atomic and refuses to overwrite a file created
        # after the earlier existence check. Both paths are on the same volume.
        os.link(stage_path, destination)
    except Exception as exc:
        try:
            stage_path.unlink(missing_ok=True)
        except OSError:
            pass
        if isinstance(exc, QuarantineError):
            raise
        raise QuarantineError(f"Không khôi phục được file: {exc}") from exc

    try:
        stage_path.unlink()
    except OSError as exc:
        return {"status": "restored_with_quarantine_copy", "restored_path": str(destination),
                "sha256": digest, "cleanup_error": f"Temporary hard link cleanup failed: {exc}"}

    try:
        stored_path.unlink()
        metadata_path.unlink()
    except OSError as exc:
        return {"status": "restored_with_quarantine_copy", "restored_path": str(destination),
                "sha256": digest, "cleanup_error": str(exc)}
    return {"status": "restored", "restored_path": str(destination), "sha256": digest}
