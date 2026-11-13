"""Held-out evaluation, provenance, report and EDA regression tests."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import pandas as pd

from process_guard.features import FEATURE_COLUMNS, extract_features
from process_guard.pid_evaluation import detection_metrics, evaluate_observations
from process_guard.pid_ml import train_labeled_samples
from process_guard.pid_visualization import analyze_observations, plot_pid_training_results
from scripts.build_project_report import build_report


class EvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        cls.root = Path(cls.workspace.name)
        cls.models, cls.reports = cls.root / "models", cls.root / "reports"
        rows = []
        for label in (0, 1):
            for app in range(6):
                record = {"exe": f"C:/fixture/{label}/app{app}.exe", "name": f"app{app}.exe",
                          "cpu_percent": 80 * label + app, "thread_count": 3 + 50 * label}
                rows.append({**extract_features(record), "label": label, "process_path": record["exe"],
                             "label_source": "software-test-fixture", "process_pid": 100 + 10 * label + app,
                             "process_create_time": 1000 + app})
        cls.training = pd.DataFrame(rows)
        cls.source = cls.root / "train.csv"
        cls.training.to_csv(cls.source, index=False)
        train_labeled_samples(cls.source, cls.models, cls.reports)

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.source = self.work / "heldout.csv"
        self.observed = self.training.copy()
        self.observed["process_create_time"] += 10000
        self.observed.to_csv(self.source, index=False)

    def evaluate(self, model_dir=None, source=None):
        return evaluate_observations([source or self.source], self.work / "evaluation",
                                     model_dir or self.models, self.reports)

    def test_metrics_counts_and_undefined_denominators(self):
        result = detection_metrics([0, 0, 1, 1], [0, 1, 0, 1])
        self.assertEqual(result["confusion_matrix"], [[1, 1], [1, 1]])
        self.assertEqual(result["recall"], 0.5)
        benign = detection_metrics([0, 0], [0, 0])
        self.assertIsNone(benign["recall"])
        self.assertIsNone(benign["precision"])
        self.assertEqual(benign["false_positive_rate"], 0)

    def test_current_scores_ignore_recorded_scores_and_known_paths_are_reported(self):
        self.observed["ml_score"] = 999  # historical columns must not determine predictions
        self.observed.to_csv(self.source, index=False)
        report = self.evaluate()
        self.assertTrue(report["ml_available"])
        self.assertEqual(report["overlap_audit"]["known_executable_rows"], len(self.observed))
        self.assertTrue(report["overlap_audit"]["process_identity_audit_available"])
        self.assertEqual(len(report["metrics"]), 6)
        predictions = pd.read_csv(self.work / "evaluation/predictions.csv")
        self.assertTrue(predictions.ml_score_current.between(0, 1).all())
        self.assertTrue((predictions.combined_score_current >= predictions.rule_score_current).all())

    def test_no_model_emits_rules_only_and_no_ml_metrics(self):
        report = self.evaluate(model_dir=self.work / "missing-model")
        self.assertFalse(report["ml_available"])
        self.assertEqual({row["detector"] for row in report["metrics"]}, {"rules", "combined_rules_only"})

    def test_training_file_content_cannot_be_evaluation_even_under_another_name(self):
        shutil.copyfile(self.__class__.source, self.source)
        with self.assertRaisesRegex(ValueError, "trùng nội dung"):
            self.evaluate()
        self.assertFalse((self.work / "evaluation").exists())

    def test_process_instance_overlap_rejected_even_after_csv_changes(self):
        self.observed["process_create_time"] = self.training.process_create_time
        self.observed["label_source"] = "another CSV of the same process"
        self.observed.to_csv(self.source, index=False)
        with self.assertRaisesRegex(ValueError, "Process instance"):
            self.evaluate()

    def test_wrong_audit_for_model_rejected(self):
        copied_reports = self.work / "reports"
        shutil.copytree(self.reports, copied_reports)
        summary = copied_reports / "dataset_summary.json"
        summary.write_text(summary.read_text() + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "không khớp model"):
            evaluate_observations([self.source], self.work / "evaluation", self.models, copied_reports)

    def test_same_instance_has_one_any_alert_prediction_per_source(self):
        row = self.observed.iloc[0].copy()
        row["name_similarity_risk"] = 1
        row["path_is_temp"] = 1
        row["parent_is_script_host"] = 1
        data = pd.concat([self.observed.iloc[[0]], pd.DataFrame([row])], ignore_index=True)
        data.to_csv(self.source, index=False)
        report = self.evaluate(model_dir=self.work / "no-model")
        snapshot = next(item for item in report["metrics"] if item["unit"] == "snapshot" and item["detector"] == "rules")
        instance = next(item for item in report["metrics"] if item["unit"].startswith("process_instance") and item["detector"] == "rules")
        self.assertEqual(snapshot["sample_count"], 2)
        self.assertEqual(snapshot["fp"], 1)
        self.assertEqual(instance["sample_count"], 1)
        self.assertEqual(instance["fp"], 1)

    def test_conflicting_instance_labels_rejected(self):
        row = self.observed.iloc[0].copy()
        row["label"] = 1
        pd.concat([self.observed.iloc[[0]], pd.DataFrame([row])], ignore_index=True).to_csv(self.source, index=False)
        with self.assertRaisesRegex(ValueError, "nhãn mâu thuẫn"):
            self.evaluate(model_dir=self.work / "no-model")

    def test_no_silent_schema_fill_between_csv_files(self):
        bad_source = self.work / "missing-column.csv"
        self.observed.drop(columns=FEATURE_COLUMNS[0]).to_csv(bad_source, index=False)
        with self.assertRaisesRegex(ValueError, "thiếu cột"):
            evaluate_observations([self.source, bad_source], self.work / "evaluation", self.models, self.reports)

    def test_report_directory_not_overwritten(self):
        self.evaluate()
        with self.assertRaises(FileExistsError):
            self.evaluate()

    def test_eda_and_training_plots(self):
        summary = analyze_observations([self.source], self.work / "eda")
        self.assertEqual(summary["snapshot_count"], len(self.observed))
        self.assertTrue((self.work / "eda/runtime_features.png").stat().st_size > 1000)
        figures = plot_pid_training_results(self.reports)
        self.assertEqual(len(figures), 5)
        self.assertTrue(all(path.stat().st_size > 1000 for path in figures))

    def test_report_missing_artifacts_and_manual_edits(self):
        output = self.work / "report.md"
        build_report(self.work, output)
        text = output.read_text(encoding="utf-8")
        self.assertIn("Chưa có artifact", text)
        self.assertIn("**0 CSV**", text)
        build_report(self.work, output)  # generated report can be refreshed
        output.write_text("My manually written report", encoding="utf-8")
        with self.assertRaises(ValueError):
            build_report(self.work, output)


if __name__ == "__main__":
    unittest.main()
