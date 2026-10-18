"""Train a small three-GRU ensemble inspired by Rhode et al. (2018).

PyTorch is optional; install requirements-rnn.txt to run this script. It consumes
only the published benign/malicious time series and never executes sample files.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import json
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, classification_report)
from sklearn.preprocessing import StandardScaler

from process_guard.cardiff import make_sequences


CONFIGS = ((3, 74, 53, 0.3, True, "l2"),
           (1, 358, 112, 0.1, True, "l2"),
           (2, 195, 39, 0.1, False, "l1"))


def train(source: Path, seconds: int = 5, seed: int = 42):
    try:
        import torch
        from torch import nn
        from torch.utils.data import DataLoader, TensorDataset
    except ImportError as exc:
        raise SystemExit("PyTorch is optional. Install with: python -m pip install -r requirements-rnn.txt") from exc
    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed)
    X, y, is_test, sample_ids, metrics = make_sequences(source, seconds=seconds)
    train_mask, test_mask = ~is_test, is_test
    if np.unique(y[train_mask]).size < 2 or np.unique(y[test_mask]).size < 2:
        raise ValueError("Published train/test split must include both classes.")
    # Fit normalization on training observations only, as in the paper.
    scaler = StandardScaler().fit(X[train_mask].reshape(-1, len(metrics)))
    X_scaled = scaler.transform(X.reshape(-1, len(metrics))).reshape(X.shape).astype(np.float32)
    x_train = torch.tensor(X_scaled[train_mask], dtype=torch.float32)
    y_train = torch.tensor(y[train_mask].astype(np.float32), dtype=torch.float32)
    x_test = torch.tensor(X_scaled[test_mask], dtype=torch.float32)
    y_test = y[test_mask]
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    members = []

    class GRUClassifier(nn.Module):
        def __init__(self, layers: int, hidden: int, dropout: float, bidirectional: bool):
            super().__init__()
            self.gru = nn.GRU(input_size=len(metrics), hidden_size=hidden, num_layers=layers,
                              batch_first=True, bidirectional=bidirectional,
                              dropout=dropout if layers > 1 else 0.0)
            self.dropout = nn.Dropout(dropout)
            self.bidirectional = bidirectional
            self.output = nn.Linear(hidden * (2 if bidirectional else 1), 1)

        def forward(self, values):
            _, hidden = self.gru(values)
            representation = (torch.cat((hidden[-2], hidden[-1]), dim=1)
                              if self.bidirectional else hidden[-1])
            return self.output(self.dropout(representation)).squeeze(1)

    for index, (layers, hidden_size, epochs, dropout, bidirectional, regularization) in enumerate(CONFIGS):
        model = GRUClassifier(layers, hidden_size, dropout, bidirectional).to(device)
        optimizer = torch.optim.Adam(model.parameters(), lr=1e-3,
                                     weight_decay=1e-5 if regularization == "l2" else 0.0)
        loss_fn = nn.BCEWithLogitsLoss()
        loader = DataLoader(TensorDataset(x_train, y_train), batch_size=64, shuffle=True)
        model.train()
        for _epoch in range(epochs):
            for batch_x, batch_y in loader:
                batch_x, batch_y = batch_x.to(device), batch_y.to(device)
                optimizer.zero_grad(set_to_none=True)
                loss = loss_fn(model(batch_x), batch_y)
                if regularization == "l1":
                    loss = loss + 1e-5 * sum(parameter.abs().sum() for parameter in model.parameters())
                loss.backward()
                nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                optimizer.step()
        model.eval()
        with torch.no_grad():
            logits = model(x_test.to(device)).cpu().numpy()
        members.append((model, torch.sigmoid(torch.tensor(logits)).numpy()))
        print(f"Trained GRU member {index + 1}: layers={layers}, hidden={hidden_size}, epochs={epochs}, "
              f"bidirectional={bidirectional}, regularization={regularization}")

    # Paper's ensemble favors malware: max of member probabilities, threshold 0.5.
    ensemble_probability = np.max(np.stack([prob for _, prob in members]), axis=0)
    prediction = (ensemble_probability >= 0.5).astype(int)
    results = []
    for seconds_seen in range(1, seconds + 1):
        prefix_probs = []
        with torch.no_grad():
            prefix = x_test[:, :seconds_seen].to(device)
            for model, _ in members:
                model.eval()
                prefix_probs.append(torch.sigmoid(model(prefix)).cpu().numpy())
        prefix_prediction = (np.max(np.stack(prefix_probs), axis=0) >= 0.5).astype(int)
        results.append({"seconds_observed": seconds_seen,
                        "accuracy": accuracy_score(y_test, prefix_prediction),
                        "precision": precision_score(y_test, prefix_prediction, zero_division=0),
                        "recall": recall_score(y_test, prefix_prediction, zero_division=0),
                        "f1": f1_score(y_test, prefix_prediction, zero_division=0)})
    report_dir, model_dir = ROOT / "artifacts/reports/cardiff", ROOT / "artifacts/models/cardiff"
    report_dir.mkdir(parents=True, exist_ok=True); model_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(results).to_csv(report_dir / "cardiff_gru_early_window_metrics.csv", index=False)
    report = {"source_dataset": "Cardiff Dataset 2", "paper": "Rhode et al. (2018)",
              "seconds": seconds, "ensemble": "max probability of three GRUs (A/B bidirectional, C unidirectional), threshold 0.5",
              "confusion_matrix": confusion_matrix(y_test, prediction, labels=[0, 1]).tolist(),
              "classification_report": classification_report(y_test, prediction, output_dict=True, zero_division=0),
              "device": str(device), "split": "published test_set"}
    (report_dir / "cardiff_gru_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    torch.save({"members": [model.cpu().state_dict() for model, _ in members],
                "configs": CONFIGS, "metrics": metrics, "seconds": seconds,
                "scaler_mean": scaler.mean_, "scaler_scale": scaler.scale_}, model_dir / "cardiff_gru_ensemble.pt")
    print(f"Ensemble at {seconds}s: accuracy={accuracy_score(y_test, prediction):.4f}, "
          f"precision={precision_score(y_test, prediction, zero_division=0):.4f}, "
          f"recall={recall_score(y_test, prediction, zero_division=0):.4f}, "
          f"F1={f1_score(y_test, prediction, zero_division=0):.4f}")
    print("Paper result is a reference, not a target or guaranteed outcome.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=ROOT / "data/raw/cardiff_data_2.csv")
    parser.add_argument("--seconds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    train(args.source, args.seconds, args.seed)
