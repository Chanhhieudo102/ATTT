"""Import and prepare Cardiff's published per-sample runtime time series."""
from __future__ import annotations

from pathlib import Path
import re
import warnings

import numpy as np
import pandas as pd

METRICS = [
    "cpu_system", "cpu_user", "memory", "swap", "total_processes", "max_pid",
    "rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
]
ALIASES = {
    "cpu_system": ("cpu_system", "cpu_sysem", "cpu_sys"),
    "cpu_user": ("cpu_user",), "memory": ("memory",), "swap": ("swap",),
    "total_processes": ("total_pro", "total_processes"), "max_pid": ("max_pid",),
    "rx_bytes": ("rx_bytes",), "tx_bytes": ("tx_bytes",),
    "rx_packets": ("rx_packets",), "tx_packets": ("tx_packets",),
}


def load_cardiff_csv(path: str | Path) -> pd.DataFrame:
    data = pd.read_csv(path, low_memory=False)
    data.columns = [re.sub(r"[^a-z0-9]+", "_", str(column).strip().lower()).strip("_") for column in data.columns]
    aliases = {}
    for target, options in ALIASES.items():
        found = next((name for name in options if name in data.columns), None)
        if found is None:
            raise ValueError(f"Cardiff CSV is missing required feature {target}; columns={list(data.columns)}")
        aliases[found] = target
    data = data.rename(columns=aliases)
    for required in ("sample_id", "vector", "malware"):
        if required not in data.columns:
            raise ValueError(f"Cardiff CSV is missing required column {required}.")
    data["vector"] = pd.to_numeric(data["vector"], errors="coerce")
    data["malware"] = pd.to_numeric(data["malware"], errors="coerce")
    for column in METRICS:
        data[column] = pd.to_numeric(data[column], errors="coerce")
    data = data.dropna(subset=["sample_id", "vector", "malware"] + METRICS)
    data["malware"] = data["malware"].astype(int)
    data = data[data["malware"].isin([0, 1])]
    return data.sort_values(["sample_id", "vector"]).reset_index(drop=True)


def get_test_flag(group: pd.DataFrame) -> bool:
    column = "test_set" if "test_set" in group.columns else "test_set"
    if column not in group:
        raise ValueError("The Cardiff file has no test_set field; refusing a row-wise random split.")
    values = group[column].dropna().astype(str).str.strip().str.lower().unique()
    if len(values) != 1:
        raise ValueError("test_set must be constant for every sample_id.")
    return values[0] in {"true", "1", "yes", "test"}


def remove_ambiguous_sample_ids(data: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Drop IDs whose rows disagree on label or published train/test membership."""
    keep = []
    for sample_id, group in data.groupby("sample_id", sort=False):
        if group["malware"].nunique() == 1 and group["test_set"].nunique(dropna=True) == 1:
            keep.append(sample_id)
    filtered = data[data["sample_id"].isin(keep)].copy()
    return filtered, int(data["sample_id"].nunique() - len(keep))


def make_sequences(path: str | Path, seconds: int = 5) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, list[str]]:
    """Build one [time, metric] sequence per executable sample.

    The first `seconds` observations are used, matching the paper's early
    prediction experiment. Short traces are padded with their last observation.
    `test_set` is retained at sample level to avoid temporal and group leakage.
    """
    if seconds < 1 or seconds > 20:
        raise ValueError("seconds must be between 1 and 20")
    data = load_cardiff_csv(path)
    if "test_set" not in data.columns:
        raise ValueError("Cardiff CSV is missing test_set, needed for its published split.")
    data, ambiguous_count = remove_ambiguous_sample_ids(data)
    if ambiguous_count:
        warnings.warn(f"Excluded {ambiguous_count} sample_id values with conflicting labels or test_set flags.",
                      RuntimeWarning)
    sequences, labels, ids, test_flags = [], [], [], []
    for sample_id, group in data.groupby("sample_id", sort=False):
        if group["malware"].nunique() != 1:
            raise ValueError(f"Conflicting labels in sample_id={sample_id}")
        window = group.loc[group["vector"] < seconds].groupby("vector")[METRICS].mean()
        if window.empty:
            continue
        # Keep the time coordinate: fill any missing second with the latest
        # available observation (and backfill only if the trace starts late).
        rows = window.reindex(range(seconds)).ffill().bfill().to_numpy(dtype=np.float32)
        sequences.append(rows)
        labels.append(int(group["malware"].iloc[0]))
        ids.append(str(sample_id))
        test_flags.append(get_test_flag(group))
    if not sequences:
        raise ValueError("No per-sample sequences were built from Cardiff CSV.")
    return (np.stack(sequences), np.asarray(labels, dtype=np.int64), np.asarray(test_flags, dtype=bool),
            np.asarray(ids, dtype=str), METRICS.copy())
