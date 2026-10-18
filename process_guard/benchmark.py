"""Small, repeatable single-row inference timing for model comparison reports."""
from __future__ import annotations

import time
from typing import Any


def batch_inference_ms_per_sample(model: Any, samples: Any, repeats: int = 10,
                                  max_batch_size: int = 128) -> float:
    """Return warmed-up estimator predict latency amortized across a batch.

    This measures the estimator call only. Collector, feature extraction, disk,
    and rendering costs are reported separately by the live monitor. The batch
    size approximates scoring a full process snapshot in the live application.
    """
    if hasattr(samples, "iloc"):
        batch = samples.iloc[:max(1, max_batch_size)]
    else:
        batch = samples[:max(1, max_batch_size)]
    row_count = max(1, len(batch))
    model.predict(batch)
    started = time.perf_counter()
    for _ in range(max(1, repeats)):
        model.predict(batch)
    return (time.perf_counter() - started) * 1000 / (max(1, repeats) * row_count)
