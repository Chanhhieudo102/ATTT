"""Regression checks for PID evaluation integrity and runtime score parity."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import joblib
import numpy as np
import pandas as pd

from process_guard.features import FEATURE_COLUMNS, extract_features
from process_guard.ml import ALERT_THRESHOLD, ModelScorer, model_scores
from process_guard.pid_ml import grouped_partitions, train_labeled_samples
from scripts.collect_pid_samples import collect


class PIDPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "observations.csv"
        self.models = self.root / "models"
        self.reports = self.root / "reports"
        rows = []
        for label in (0, 1):
            for executable in range(6):
                record = {"exe": f"C:/lab/class{label}/app{executable}.exe",
                          "name": f"app{executable}.exe", "cpu_percent": label * 80 + executable,
                          "thread_count": 2 + label * 60}
                for snapshot in range(3):
                    rows.append({**extract_features(record), "label": label,
                                 "process_path": record["exe"], "label_source": f"fixture/{label}/{executable}",
                                 "process_name": record["name"]})
        self.data = pd.DataFrame(rows)
        self.data.to_csv(self.source, index=False)

    def train(self):
        return train_labeled_samples(self.source, self.models, self.reports)

    def test_partitions_keep_executables_separate_and_both_labels(self):
        X = self.data[FEATURE_COLUMNS]
        y = self.data.label.to_numpy()
        groups = self.data.process_path.to_numpy()
        partitions = grouped_partitions(X, y, groups)
        for indices in partitions:
            self.assertEqual(set(y[indices]), {0, 1})
        for i, first in enumerate(partitions):
            for second in partitions[i + 1:]:
                self.assertFalse(set(groups[first]) & set(groups[second]))
        self.assertEqual(sum(map(len, partitions)), len(X))

    def test_four_models_match_runtime_scores_and_reported_confusion(self):
        comparison = self.train()
        self.assertEqual(len(comparison), 4)
        manifest = pd.read_csv(self.reports / "split_manifest.csv")
        test = self.data.loc[manifest.partition.eq("test"), FEATURE_COLUMNS]
        labels = self.data.loc[manifest.partition.eq("test"), "label"].to_numpy()
        for name in ("decision_tree", "random_forest", "extra_trees", "isolation_forest"):
            bundle = joblib.load(self.models / f"{name}.joblib")
            scores = model_scores(bundle["model"], test[bundle["features"]], bundle.get("unsupervised", False))
            prediction = scores >= ALERT_THRESHOLD
            expected = [[int(((labels == actual) & (prediction == predicted)).sum())
                         for predicted in (0, 1)] for actual in (0, 1)]
            report = json.loads((self.reports / f"{name}_confusion.json").read_text())
            self.assertEqual(report["confusion_matrix"], expected)
            # Execute the actual live feature extraction and score path for every model.
            scorer = ModelScorer(self.models, allowed_sources={"observed-per-process"})
            scorer.bundle = bundle
            record = {"exe": "C:/lab/test.exe", "cpu_percent": 85, "thread_count": 62}
            features = pd.DataFrame([extract_features(record)])[bundle["features"]]
            self.assertAlmostEqual(scorer.score(record)[0], model_scores(bundle["model"], features,
                                   bundle.get("unsupervised", False))[0])
        best = comparison.iloc[comparison.iloc[:3].cv_f1.argmax()]["model"].lower().replace(" ", "_")
        self.assertEqual((self.models / "active_model.txt").read_text().strip(), best + ".joblib")

    def test_invalid_samples_are_rejected_before_writing_models(self):
        for column, value in (("label", 2), ("label_source", " "), ("process_path", ""),
                              (FEATURE_COLUMNS[0], float("inf")), (FEATURE_COLUMNS[1], "bad"),
                              (FEATURE_COLUMNS[2], float("nan"))):
            with self.subTest(column=column, value=value):
                data = self.data.copy()
                data[column] = data[column].astype(object)
                data.loc[0, column] = value
                data.to_csv(self.source, index=False)
                with self.assertRaises(ValueError):
                    self.train()
                self.assertFalse(self.models.exists())

    def test_insufficient_groups_rejected(self):
        self.data.iloc[:3].to_csv(self.source, index=False)
        with self.assertRaises(ValueError):
            self.train()

    def test_duplicate_source_rejected(self):
        with self.assertRaises(ValueError):
            train_labeled_samples([self.source, self.source], self.models, self.reports)

    def test_socket_table_failure_preserves_process_snapshot(self):
        from process_guard.collector import ProcessCollector
        with patch("process_guard.collector.psutil.net_connections", side_effect=RuntimeError("GetExtendedTcpTable failed")):
            rows = ProcessCollector().snapshot()
        self.assertTrue(rows)
        self.assertTrue(all(row["connection_count"] == 0 for row in rows))

    def test_collection_rejects_invalid_bounds_without_touching_processes(self):
        for duration, interval in ((float("nan"), 1), (10, 0), (1, 2)):
            with self.assertRaises(ValueError):
                collect([123], 0, "test", duration, interval, self.root / "session.csv")

    @patch("scripts.collect_pid_samples.ModelScorer")
    @patch("scripts.collect_pid_samples.ProcessCollector")
    @patch("scripts.collect_pid_samples.psutil.Process")
    def test_collection_writes_features_and_final_metadata(self, process, collector, scorer):
        process.return_value.create_time.return_value = 100
        process.return_value.exe.return_value = "C:/lab/app.exe"
        process.return_value.name.return_value = "app.exe"
        collector.return_value.snapshot.return_value = [{"pid": 123, "create_time": 100,
            "exe": "C:/lab/app.exe", "name": "app.exe", "cpu_percent": 5}]
        scorer.return_value.bundle = None
        output = self.root / "session.csv"
        report = collect([123], 0, "fixture only", 1, 0.2, output)
        rows = pd.read_csv(output)
        self.assertGreater(len(rows), 0)
        self.assertEqual(report["sample_count"], len(rows))
        self.assertEqual(report["status"], "completed")
        self.assertFalse(report["ml_available"])
        self.assertTrue(rows.ml_score.isna().all())
        self.assertTrue(rows.process_pid.eq(123).all())
        self.assertTrue(rows.process_create_time.eq(100).all())
        self.assertTrue(rows.label_source.eq("fixture only").all())
        self.assertTrue(set(FEATURE_COLUMNS).issubset(rows.columns))

    @patch("scripts.collect_pid_samples.ModelScorer")
    @patch("scripts.collect_pid_samples.ProcessCollector")
    @patch("scripts.collect_pid_samples.psutil.Process")
    def test_recycled_pid_is_never_recorded(self, process, collector, scorer):
        process.return_value.create_time.side_effect = [100, 200]
        process.return_value.exe.return_value = "C:/lab/app.exe"
        process.return_value.name.return_value = "app.exe"
        collector.return_value.snapshot.return_value = []
        scorer.return_value.bundle = None
        output = self.root / "session.csv"
        report = collect([123], 0, "fixture only", 1, 0.2, output)
        self.assertEqual(report["sample_count"], 0)
        self.assertEqual(report["status"], "targets_exited_or_unavailable")
        self.assertTrue(pd.read_csv(output).empty)
        self.assertEqual(json.loads(output.with_suffix(".json").read_text())["sample_count"], 0)
        with self.assertRaises(ValueError):
            collect([123], 0, "fixture only", 1, 0.2, output)


if __name__ == "__main__":
    unittest.main()
