"""Per-process snapshot windows for sequence models on the self-collected PID data.

Every snapshot becomes one sample: the window of the last ``k`` snapshots of the *same*
process instance (oldest -> newest, front-padded with the first snapshot). The label and the
alert threshold stay per snapshot, so results are comparable with the flat tree models.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .features import PID_MODEL_FEATURES

INSTANCE_KEYS = ["source_file", "group", "process_pid", "process_create_time"]


def order_snapshots(data: pd.DataFrame) -> pd.DataFrame:
    """Stable chronological order inside each process instance, plus 1-based position."""
    data = data.copy()
    data["_t"] = pd.to_datetime(data["sampled_at"], errors="coerce", utc=True)
    data["_row"] = np.arange(len(data))
    data = data.sort_values(INSTANCE_KEYS + ["_t", "_row"], kind="mergesort")
    data["position"] = data.groupby(INSTANCE_KEYS, sort=False).cumcount() + 1
    return data


def transform(values: np.ndarray) -> np.ndarray:
    """log1p of non-negative counters/rates (all PID features are >= 0)."""
    return np.log1p(np.clip(values.astype(np.float64), 0, None))


def build_windows(data: pd.DataFrame, k: int = 8, mean=None, std=None):
    """Return (windows[n, k, F] float32, ordered frame). ``data`` must come from order_snapshots."""
    values = transform(data[PID_MODEL_FEATURES].to_numpy())
    if mean is not None:
        values = (values - mean) / std
    out = np.empty((len(data), k, values.shape[1]), dtype=np.float32)
    starts = data.groupby(INSTANCE_KEYS, sort=False).cumcount().to_numpy()
    for i in range(len(data)):
        first = i - starts[i]
        idx = np.arange(i - k + 1, i + 1)
        idx = np.maximum(idx, first)
        out[i] = values[idx]
    return out


def fit_scaler(data: pd.DataFrame):
    values = transform(data[PID_MODEL_FEATURES].to_numpy())
    mean, std = values.mean(0), values.std(0)
    std[std < 1e-8] = 1.0
    return mean, std
