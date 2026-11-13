"""Validate labeled process observations without silently dropping bad rows."""
from __future__ import annotations

import hashlib
import ntpath
from pathlib import Path

import numpy as np
import pandas as pd

from .features import FEATURE_COLUMNS


def normalize_executable(value: str) -> str:
    return ntpath.normpath(value.strip()).casefold()


def load_observations(sources) -> tuple[pd.DataFrame, list[dict]]:
    paths = [Path(p) for p in sources] if isinstance(sources, (list, tuple)) else [Path(sources)]
    if not paths:
        raise ValueError("Cần ít nhất một file CSV quan sát.")
    if len({p.resolve() for p in paths}) != len(paths):
        raise ValueError("Danh sách source chứa file trùng lặp.")
    frames, provenance = [], []
    required = FEATURE_COLUMNS + ["label", "process_path", "label_source"]
    for path in paths:
        data = pd.read_csv(path)
        missing = [column for column in required if column not in data]
        if missing:
            raise ValueError(f"{path.name}: thiếu cột: {', '.join(missing)}. Mẫu cũ có thể cần thu thập lại.")
        if data.empty:
            raise ValueError(f"{path.name}: không có quan sát.")
        labels = pd.to_numeric(data["label"], errors="coerce")
        if labels.isna().any() or not labels.isin([0, 1]).all():
            raise ValueError(f"{path.name}: nhãn phải là 0 (benign) hoặc 1 (simulated_malicious).")
        data["label"] = labels.astype(int)
        for column in ("process_path", "label_source"):
            data[column] = data[column].fillna("").astype(str).str.strip()
            if data[column].eq("").any():
                raise ValueError(f"{path.name}: có mẫu thiếu {column}.")
        numeric = data[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
        if not np.isfinite(numeric.to_numpy(dtype=float)).all():
            raise ValueError(f"{path.name}: feature thiếu, không phải số hoặc vô hạn; hãy kiểm tra/thu thập lại.")
        data[FEATURE_COLUMNS] = numeric
        data["group"] = data["process_path"].map(normalize_executable)
        data["source_file"] = str(path.resolve())
        data["source_row"] = np.arange(len(data)) + 2  # header is CSV row 1
        frames.append(data)
        provenance.append({"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                           "rows": len(data)})
    return pd.concat(frames, ignore_index=True), provenance
