"""Plot evaluation outputs saved by the Cardiff training pipeline."""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


CLASSIFICATION_METRICS = ["accuracy", "precision", "recall", "f1"]
DETECTION_METRICS = ["balanced_accuracy", "roc_auc", "average_precision", "false_positive_rate"]
METRIC_LABELS = {
    "accuracy": "Accuracy",
    "balanced_accuracy": "Balanced accuracy",
    "precision": "Precision",
    "recall": "Recall",
    "f1": "F1",
    "false_positive_rate": "False-positive rate",
    "roc_auc": "ROC AUC",
    "average_precision": "Average precision (PR AUC)",
}
MODEL_FILES = {
    "Decision Tree": "decision_tree",
    "Random Forest": "random_forest",
    "Extra Trees": "extra_trees",
    "Gradient Boosting": "gradient_boosting",
    "XGBoost": "xgboost",
    "LightGBM": "lightgbm",
    "Logistic Regression": "logistic_regression",
    "RBF SVM": "rbf_svm",
    "Isolation Forest (unsupervised)": "isolation_forest",
}


def _comparison_plot(comparison: pd.DataFrame, report_dir: Path, metrics: list[str],
                     filename: str, title: str) -> Path | None:
    metrics = [metric for metric in metrics if metric in comparison.columns]
    if not metrics:
        return None
    fig, ax = plt.subplots(figsize=(12, 6))
    x = np.arange(len(comparison))
    width = 0.8 / len(metrics)
    for index, metric in enumerate(metrics):
        offset = (index - (len(metrics) - 1) / 2) * width
        ax.bar(x + offset, comparison[metric], width=width * 0.94,
               label=METRIC_LABELS[metric])
    ax.set(title=title, ylabel="Score", xlabel="Model", ylim=(0, 1.05))
    ax.set_xticks(x, comparison["model"], rotation=12, ha="right")
    ax.grid(axis="y", alpha=0.25)
    ax.legend(ncols=2, loc="upper center", bbox_to_anchor=(0.5, -0.2), frameon=False)
    fig.tight_layout()
    output = report_dir / filename
    fig.savefig(output, dpi=160, bbox_inches="tight")
    plt.close(fig)
    return output


def plot_cardiff_training_results(report_dir: str | Path) -> list[Path]:
    """Create PNG summaries from existing Cardiff CSV/JSON evaluation reports."""
    report_dir = Path(report_dir)
    comparison = pd.read_csv(report_dir / "cardiff_model_comparison.csv")
    early_path = report_dir / "cardiff_early_window_metrics.csv"
    early = pd.read_csv(early_path) if early_path.exists() else pd.DataFrame()
    outputs: list[Path] = []

    for metrics, filename, title in (
        (CLASSIFICATION_METRICS, "cardiff_model_comparison.png",
         "Cardiff Dataset 2 — classification metrics"),
        (DETECTION_METRICS, "cardiff_detection_metrics.png",
         "Cardiff Dataset 2 — balanced and threshold-independent metrics"),
    ):
        output = _comparison_plot(comparison, report_dir, metrics, filename, title)
        if output:
            outputs.append(output)

    if "inference_ms_per_sample" in comparison.columns:
        fig, ax = plt.subplots(figsize=(9, 5))
        values = comparison["inference_ms_per_sample"].clip(lower=1e-6)
        bars = ax.barh(comparison["model"], values, color="#4c78a8")
        ax.set_xscale("log")
        ax.set(title="Cardiff Dataset 2 — inference latency",
               xlabel="Milliseconds per sample (log scale)")
        ax.grid(axis="x", which="both", alpha=0.25)
        for bar, value in zip(bars, comparison["inference_ms_per_sample"]):
            ax.annotate(f"{value:.4g} ms",
                        (bar.get_width(), bar.get_y() + bar.get_height() / 2),
                        xytext=(5, 0), textcoords="offset points", va="center", fontsize=8)
        fig.tight_layout()
        output = report_dir / "cardiff_inference_latency.png"
        fig.savefig(output, dpi=160, bbox_inches="tight")
        plt.close(fig)
        outputs.append(output)

    if "fit_seconds" in comparison.columns:
        fig, ax = plt.subplots(figsize=(9, 5))
        bars = ax.barh(comparison["model"], comparison["fit_seconds"], color="#f28e2b")
        ax.set(title="Cardiff Dataset 2 — model fit time", xlabel="Seconds")
        ax.grid(axis="x", alpha=0.25)
        for bar, value in zip(bars, comparison["fit_seconds"]):
            ax.annotate(f"{value:.2f}s",
                        (bar.get_width(), bar.get_y() + bar.get_height() / 2),
                        xytext=(5, 0), textcoords="offset points", va="center", fontsize=8)
        fig.tight_layout()
        output = report_dir / "cardiff_training_time.png"
        fig.savefig(output, dpi=160, bbox_inches="tight")
        plt.close(fig)
        outputs.append(output)

    early_metrics = [metric for metric in CLASSIFICATION_METRICS if metric in early.columns]
    if "seconds_observed" in early.columns and early_metrics:
        fig, ax = plt.subplots(figsize=(9, 5.5))
        for metric in early_metrics:
            ax.plot(early["seconds_observed"], early[metric], marker="o",
                    linewidth=2, label=METRIC_LABELS[metric])
        ax.set(title="Random Forest — early-window performance",
               xlabel="Telemetry observed (seconds)", ylabel="Score", ylim=(0, 1.05))
        ax.set_xticks(early["seconds_observed"])
        ax.grid(alpha=0.25)
        ax.legend(ncols=2, loc="upper center", bbox_to_anchor=(0.5, -0.18), frameon=False)
        fig.tight_layout()
        output = report_dir / "cardiff_early_window_metrics.png"
        fig.savefig(output, dpi=160, bbox_inches="tight")
        plt.close(fig)
        outputs.append(output)

    matrices: list[tuple[str, np.ndarray]] = []
    for model_name, file_stem in MODEL_FILES.items():
        path = report_dir / f"cardiff_{file_stem}_confusion.json"
        if path.exists():
            report = json.loads(path.read_text(encoding="utf-8"))
            matrices.append((model_name, np.asarray(report["confusion_matrix"], dtype=int)))
    if matrices:
        columns = min(4, len(matrices))
        row_count = int(np.ceil(len(matrices) / columns))
        fig, axes = plt.subplots(row_count, columns,
                                 figsize=(4.3 * columns, 4 * row_count), squeeze=False)
        max_count = max(int(matrix.max()) for _, matrix in matrices)
        for ax, (model_name, matrix) in zip(axes.flat, matrices):
            image = ax.imshow(matrix, cmap="Blues", vmin=0, vmax=max_count)
            ax.set(title=model_name, xlabel="Predicted label", ylabel="True label",
                   xticks=[0, 1], yticks=[0, 1], xticklabels=["Benign", "Malicious"],
                   yticklabels=["Benign", "Malicious"])
            threshold = matrix.max() / 2 if matrix.size else 0
            for row in range(matrix.shape[0]):
                for column in range(matrix.shape[1]):
                    ax.text(column, row, f"{matrix[row, column]:,}", ha="center", va="center",
                            color="white" if matrix[row, column] > threshold else "black")
        for ax in axes.flat[len(matrices):]:
            ax.set_visible(False)
        fig.subplots_adjust(left=0.06, right=0.92, bottom=0.08, top=0.9,
                            wspace=0.5, hspace=0.42)
        colorbar_axis = fig.add_axes([0.94, 0.18, 0.015, 0.64])
        fig.colorbar(image, cax=colorbar_axis)
        fig.suptitle("Cardiff Dataset 2 — confusion matrices (published test split)", y=0.97)
        output = report_dir / "cardiff_confusion_matrices.png"
        fig.savefig(output, dpi=160, bbox_inches="tight")
        plt.close(fig)
        outputs.append(output)

    curves_path = report_dir / "cardiff_curves.json"
    if curves_path.exists():
        curves = json.loads(curves_path.read_text(encoding="utf-8"))
        if curves:
            fig, ax = plt.subplots(figsize=(8.5, 6))
            for curve in curves.values():
                ax.plot(curve["fpr"], curve["tpr"], linewidth=2,
                        label=f"{curve['model']} (AUC {curve['roc_auc']:.3f})")
            ax.plot([0, 1], [0, 1], "k--", linewidth=1, label="Chance")
            ax.set(title="Cardiff Dataset 2 — ROC curves", xlabel="False-positive rate",
                   ylabel="True-positive rate", xlim=(0, 1), ylim=(0, 1.02))
            ax.grid(alpha=0.25)
            ax.legend(loc="lower right", fontsize=8, frameon=False)
            fig.tight_layout()
            output = report_dir / "cardiff_roc_curves.png"
            fig.savefig(output, dpi=160, bbox_inches="tight")
            plt.close(fig)
            outputs.append(output)

            fig, ax = plt.subplots(figsize=(8.5, 6))
            for curve in curves.values():
                ax.plot(curve["recall"], curve["precision"], linewidth=2,
                        label=f"{curve['model']} (AP {curve['average_precision']:.3f})")
            ax.set(title="Cardiff Dataset 2 — precision-recall curves",
                   xlabel="Recall", ylabel="Precision", xlim=(0, 1), ylim=(0, 1.02))
            ax.grid(alpha=0.25)
            ax.legend(loc="lower left", fontsize=8, frameon=False)
            fig.tight_layout()
            output = report_dir / "cardiff_precision_recall_curves.png"
            fig.savefig(output, dpi=160, bbox_inches="tight")
            plt.close(fig)
            outputs.append(output)

    for model_name, file_stem in MODEL_FILES.items():
        path = report_dir / f"cardiff_{file_stem}_feature_importance.csv"
        if not path.exists():
            continue
        importance = pd.read_csv(path).nlargest(15, "importance").sort_values("importance")
        if importance.empty:
            continue
        fig, ax = plt.subplots(figsize=(9, max(4, 0.32 * len(importance))))
        ax.barh(importance["feature"], importance["importance"], color="#59a14f")
        x_label = ("Absolute standardized coefficient" if model_name == "Logistic Regression"
                   else "Feature importance")
        ax.set(title=f"{model_name} — top feature importance",
               xlabel=x_label, ylabel="Feature")
        ax.grid(axis="x", alpha=0.25)
        fig.tight_layout()
        output = report_dir / f"cardiff_{file_stem}_feature_importance.png"
        fig.savefig(output, dpi=160, bbox_inches="tight")
        plt.close(fig)
        outputs.append(output)

    return outputs
