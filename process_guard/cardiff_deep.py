"""Sequence models for the Cardiff early-prediction benchmark (Rhode et al., 2018).

All models consume a z-scored tensor ``[batch, time, 10]``. Training samples a
random prefix length per batch (as the paper randomises "time into execution"),
so a single network can be queried at any time step 1..20.
PyTorch is imported lazily by callers through :func:`require_torch`.
"""
from __future__ import annotations

import copy
import time

import numpy as np
from sklearn.metrics import (accuracy_score, f1_score, precision_score, recall_score,
                             roc_auc_score, confusion_matrix)

VAL_PREFIXES = (1, 2, 3, 5, 10, 20)


def require_torch():
    try:
        import torch  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("Cần PyTorch: pip install torch --index-url https://download.pytorch.org/whl/cpu") from exc
    return torch


torch = require_torch()
nn = torch.nn


# --------------------------------------------------------------------- models
class PaperGRU(nn.Module):
    """GRU configuration from Table 2/13 of the paper."""

    def __init__(self, n_in=10, layers=3, hidden=74, dropout=0.3, bidirectional=True):
        super().__init__()
        self.gru = nn.GRU(n_in, hidden, num_layers=layers, batch_first=True,
                          bidirectional=bidirectional, dropout=dropout if layers > 1 else 0.0)
        self.bidirectional = bidirectional
        self.drop = nn.Dropout(dropout)
        self.out = nn.Linear(hidden * (2 if bidirectional else 1), 1)

    def forward(self, x):
        _, h = self.gru(x)
        rep = torch.cat((h[-2], h[-1]), 1) if self.bidirectional else h[-1]
        return self.out(self.drop(rep)).squeeze(1)


class SEBlock(nn.Module):
    """Squeeze-and-Excitation over channels of a [B, C, T] feature map."""

    def __init__(self, channels, reduction=4):
        super().__init__()
        mid = max(2, channels // reduction)
        self.fc = nn.Sequential(nn.Linear(channels, mid), nn.ReLU(), nn.Linear(mid, channels), nn.Sigmoid())

    def forward(self, x):
        w = self.fc(x.mean(dim=2))
        return x * w.unsqueeze(2)


class ConvSE(nn.Module):
    def __init__(self, n_in, filters, kernel, reduction):
        super().__init__()
        self.conv = nn.Conv1d(n_in, filters, kernel, padding=kernel // 2)
        self.bn = nn.BatchNorm1d(filters)
        self.se = SEBlock(filters, reduction)

    def forward(self, x):  # x [B,T,C]
        T = x.shape[1]
        z = torch.relu(self.bn(self.conv(x.transpose(1, 2))))[:, :, :T]
        return self.se(z)  # [B,F,T]


class AttnPool(nn.Module):
    """Multi-head attention pooling with a learned query over time steps."""

    def __init__(self, dim, heads):
        super().__init__()
        self.query = nn.Parameter(torch.randn(1, 1, dim) * 0.1)
        self.mha = nn.MultiheadAttention(dim, heads, batch_first=True)
        self.last_weights = None

    def forward(self, seq):
        q = self.query.expand(seq.shape[0], -1, -1)
        out, w = self.mha(q, seq, seq, need_weights=True)
        self.last_weights = w.detach()
        return out.squeeze(1)


class LiteSEBiLSTMAttn(nn.Module):
    """Conv1d + SE -> BiLSTM -> multi-head attention pooling -> logit."""

    def __init__(self, n_in=10, filters=32, kernel=3, reduction=4, hidden=32, heads=2, dropout=0.2):
        super().__init__()
        self.convse = ConvSE(n_in, filters, kernel, reduction)
        self.lstm = nn.LSTM(filters, hidden, batch_first=True, bidirectional=True)
        dim = 2 * hidden
        if dim % heads:
            heads = 1
        self.pool = AttnPool(dim, heads)
        self.drop = nn.Dropout(dropout)
        self.out = nn.Linear(dim, 1)

    def embed(self, x):
        z = self.convse(x).transpose(1, 2)
        seq, _ = self.lstm(z)
        return self.pool(seq)

    def forward(self, x):
        return self.out(self.drop(self.embed(x))).squeeze(1)


class BiLSTMOnly(nn.Module):
    def __init__(self, n_in=10, hidden=32, dropout=0.2, **_):
        super().__init__()
        self.lstm = nn.LSTM(n_in, hidden, batch_first=True, bidirectional=True)
        self.drop = nn.Dropout(dropout)
        self.out = nn.Linear(2 * hidden, 1)

    def forward(self, x):
        _, (h, _) = self.lstm(x)
        return self.out(self.drop(torch.cat((h[-2], h[-1]), 1))).squeeze(1)


class CNNSEOnly(nn.Module):
    def __init__(self, n_in=10, filters=32, kernel=3, reduction=4, dropout=0.2, **_):
        super().__init__()
        self.convse = ConvSE(n_in, filters, kernel, reduction)
        self.drop = nn.Dropout(dropout)
        self.out = nn.Linear(2 * filters, 1)

    def forward(self, x):
        z = self.convse(x)
        rep = torch.cat((z.mean(2), z.amax(2)), 1)
        return self.out(self.drop(rep)).squeeze(1)


def count_params(model) -> int:
    return int(sum(p.numel() for p in model.parameters() if p.requires_grad))


# ------------------------------------------------------------------- training
def _penalty(model, kind, strength):
    if not kind or strength <= 0:
        return 0.0
    weights = [p for n, p in model.named_parameters() if "weight" in n]
    if kind == "l1":
        return strength * sum(p.abs().sum() for p in weights)
    return strength * sum((p ** 2).sum() for p in weights)


def predict_prefixes(model, X, lengths=range(1, 21), batch=1024):
    """Return probabilities with shape [len(lengths), n]."""
    model.eval()
    xt = torch.as_tensor(X, dtype=torch.float32)
    out = []
    with torch.no_grad():
        for L in lengths:
            parts = [torch.sigmoid(model(xt[i:i + batch, :L])) for i in range(0, len(xt), batch)]
            out.append(torch.cat(parts).numpy())
    return np.stack(out)


def val_loss(model, X, y, prefixes=VAL_PREFIXES):
    model.eval()
    xt = torch.as_tensor(X, dtype=torch.float32)
    yt = torch.as_tensor(y, dtype=torch.float32)
    fn = nn.BCEWithLogitsLoss()
    with torch.no_grad():
        return float(np.mean([fn(model(xt[:, :L]), yt).item() for L in prefixes]))


def train_model(model, X_tr, y_tr, X_val, y_val, *, epochs=150, lr=1e-3, batch=64, weight_decay=0.0,
                reg=None, reg_strength=0.0, early_stopping=True, patience=15, seed=42, max_len=20,
                verbose=False, pos_weight=None, val_prefixes=VAL_PREFIXES, random_prefix=True):
    """Train with random-prefix batches; optional early stopping on mean val BCE.

    Returns (model with best weights, history dict).
    """
    rng = np.random.default_rng(seed)
    torch.manual_seed(seed)
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=weight_decay)
    sched = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, factor=0.5, patience=5) if early_stopping else None
    fn = nn.BCEWithLogitsLoss(pos_weight=None if pos_weight is None else torch.tensor(float(pos_weight)))
    xt = torch.as_tensor(X_tr, dtype=torch.float32)
    yt = torch.as_tensor(y_tr, dtype=torch.float32)
    n = len(xt)
    best, best_state, bad, history = np.inf, None, 0, []
    started = time.perf_counter()
    for epoch in range(1, epochs + 1):
        model.train()
        order = rng.permutation(n)
        total = 0.0
        for i in range(0, n, batch):
            idx = order[i:i + batch]
            if len(idx) < 2:
                continue
            L = int(rng.integers(1, max_len + 1)) if random_prefix else xt.shape[1]
            opt.zero_grad(set_to_none=True)
            loss = fn(model(xt[idx, :L]), yt[idx])
            loss = loss + _penalty(model, reg, reg_strength)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            total += loss.item() * len(idx)
        vl = val_loss(model, X_val, y_val, val_prefixes)
        history.append({"epoch": epoch, "train_loss": total / n, "val_loss": vl})
        if verbose:
            print(f"  epoch {epoch:3d} train={total / n:.4f} val={vl:.4f}", flush=True)
        if vl < best - 1e-4:
            best, best_state, bad = vl, copy.deepcopy(model.state_dict()), 0
        else:
            bad += 1
        if sched is not None:
            sched.step(vl)
        if early_stopping and bad >= patience:
            break
    if early_stopping and best_state is not None:
        model.load_state_dict(best_state)
    return model, {"epochs_run": len(history), "best_val_loss": best if early_stopping else history[-1]["val_loss"],
                   "train_seconds": time.perf_counter() - started, "history": history}


# ------------------------------------------------------------ hybrid helpers
def extract_embeddings(model, X, L, batch=1024):
    model.eval()
    xt = torch.as_tensor(X, dtype=torch.float32)
    with torch.no_grad():
        return torch.cat([model.embed(xt[i:i + batch, :L]) for i in range(0, len(xt), batch)]).numpy()


def summary_features(X, L):
    """Per-metric last, mean, max and slope over the first L steps -> [n, 40]."""
    w = X[:, :L]
    slope = (w[:, -1] - w[:, 0]) / max(L - 1, 1)
    return np.concatenate([w[:, -1], w.mean(1), w.max(1), slope], axis=1)


# ------------------------------------------------------------------- metrics
def binary_metrics(y, prob, threshold=0.5):
    pred = (prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    try:
        auc = roc_auc_score(y, prob)
    except ValueError:
        auc = float("nan")
    return {"accuracy": accuracy_score(y, pred), "precision": precision_score(y, pred, zero_division=0),
            "recall": recall_score(y, pred, zero_division=0), "f1": f1_score(y, pred, zero_division=0),
            "fpr": fp / max(fp + tn, 1), "fnr": fn / max(fn + tp, 1), "auc": auc,
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
