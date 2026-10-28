#!/usr/bin/env python3
"""
test_evaluate_detection.py — Unit tests for scripts/evaluate_detection.py (Part A).

Tests:
- Ground truth loading and parsing (6 rows, required columns)
- All six sample records present
- Expected behavior and technique matching
- Hit/miss/uncertain classification
- Noise classification
- Missing / malformed input handling
- Processing time parsing (including ANSI strip)
- Unavailable processing time
- Deterministic output
- JSON and CSV consistency
"""

import csv
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

# Allow importing from scripts/
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

# Import the module under test
import evaluate_detection as ed


GROUND_TRUTH_SAMPLE = """\
filename,expected_behavior,expected_technique_ids,source_note
sample_a.evtx,Credential dump via lsass,T1003.001,Based on filename
sample_b.evtx,Scheduled task persistence,T1053.005,Based on filename
"""

REAL_OUTPUT_SAMPLE = [
    {"RuleTitle": "LSASS Process Memory Dump", "Level": "high",
     "Computer": "PC04.example.corp", "EventID": "11",
     "Details": "TgtProc: lsass.exe dump file created", "RecordID": "1"},
    {"RuleTitle": "Scheduled Task Created", "Level": "medium",
     "Computer": "WIN-TEST", "EventID": "4698",
     "Details": "schtasks /create task persistence", "RecordID": "2"},
    {"RuleTitle": "Benign Event", "Level": "informational",
     "Computer": "PC04.example.corp", "EventID": "7036",
     "Details": "Service started", "RecordID": "3"},
]


class TestGroundTruthLoading(unittest.TestCase):

    def test_load_six_samples(self):
        """The project ground truth must have exactly 6 rows."""
        gt_path = ROOT / "data" / "ground_truth.csv"
        self.assertTrue(gt_path.exists(), "data/ground_truth.csv does not exist")
        rows = ed.load_ground_truth(gt_path)
        self.assertEqual(len(rows), 6, f"Expected 6 rows, got {len(rows)}")

    def test_required_columns_present(self):
        """Ground truth must have all four required columns."""
        gt_path = ROOT / "data" / "ground_truth.csv"
        rows = ed.load_ground_truth(gt_path)
        required = {"filename", "expected_behavior", "expected_technique_ids", "source_note"}
        actual = set(rows[0].keys())
        self.assertTrue(required.issubset(actual), f"Missing columns: {required - actual}")

    def test_all_six_evtx_samples_present(self):
        """All six EVTX filenames must appear in the ground truth."""
        expected_files = {
            "babyshark_mimikatz_powershell.evtx",
            "CA_sysmon_hashdump_cmd_meterpreter.evtx",
            "Exec_sysmon_meterpreter_reversetcp_msipackage.evtx",
            "sysmon_10_11_lsass_memdump.evtx",
            "sysmon_local_account_creation_and_added_admingroup_12_13.evtx",
            "temp_scheduled_task_4698_4699.evtx",
        }
        gt_path = ROOT / "data" / "ground_truth.csv"
        rows = ed.load_ground_truth(gt_path)
        found = {r["filename"].strip() for r in rows}
        self.assertEqual(found, expected_files, f"Missing: {expected_files - found}")

    def test_each_row_has_source_note(self):
        """Every row must have a non-empty source_note."""
        gt_path = ROOT / "data" / "ground_truth.csv"
        rows = ed.load_ground_truth(gt_path)
        for row in rows:
            self.assertTrue(
                row.get("source_note", "").strip(),
                f"Empty source_note for {row.get('filename')}",
            )

    def test_file_not_found_raises(self):
        """load_ground_truth raises FileNotFoundError for missing file."""
        with self.assertRaises(FileNotFoundError):
            ed.load_ground_truth(Path("/nonexistent/path/ground_truth.csv"))

    def test_empty_file_raises(self):
        """load_ground_truth raises ValueError for a file with only a header."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("filename,expected_behavior,expected_technique_ids,source_note\n")
            tmp = Path(f.name)
        try:
            with self.assertRaises(ValueError):
                ed.load_ground_truth(tmp)
        finally:
            tmp.unlink(missing_ok=True)


class TestAlertRelevance(unittest.TestCase):

    def _make_alert(self, rule_title, details="", level="high", computer="TEST", eid="10"):
        return {"RuleTitle": rule_title, "Details": details,
                "Level": level, "Computer": computer, "EventID": eid}

    def test_relevant_lsass_alert_matched(self):
        """A LSASS dump alert should be relevant to T1003.001."""
        alerts = [self._make_alert("LSASS Process Memory Dump Files", "lsass.exe dump")]
        relevant, noise = ed.alerts_relevant_to_techniques(alerts, "T1003.001")
        self.assertEqual(len(relevant), 1)
        self.assertEqual(len(noise), 0)

    def test_benign_alert_classified_as_noise(self):
        """An unrelated alert should be classified as noise, not relevant."""
        alerts = [self._make_alert("DLL Loaded", "some dll loaded")]
        relevant, noise = ed.alerts_relevant_to_techniques(alerts, "T1053.005")
        self.assertEqual(len(relevant), 0)
        self.assertEqual(len(noise), 1)

    def test_empty_technique_ids_all_noise(self):
        """If expected_technique_ids is empty, all alerts are noise."""
        alerts = [self._make_alert("Anything", "details")]
        relevant, noise = ed.alerts_relevant_to_techniques(alerts, "")
        self.assertEqual(len(relevant), 0)
        self.assertEqual(len(noise), 1)

    def test_scheduled_task_alert_matched(self):
        """A scheduled task alert should match T1053.005."""
        alerts = [self._make_alert("Scheduled Task Created", "schtask created", eid="4698")]
        relevant, noise = ed.alerts_relevant_to_techniques(alerts, "T1053.005")
        self.assertEqual(len(relevant), 1)

    def test_powershell_alert_matched(self):
        """A PowerShell alert should match T1059.001."""
        alerts = [self._make_alert("Non Interactive PowerShell Process Spawned", "powershell.exe")]
        relevant, noise = ed.alerts_relevant_to_techniques(alerts, "T1059.001")
        self.assertEqual(len(relevant), 1)


class TestSampleEvaluation(unittest.TestCase):

    def test_evaluation_uses_six_real_samples(self):
        """evaluate_samples must process exactly 6 rows from the real ground truth."""
        gt_path = ROOT / "data" / "ground_truth.csv"
        real_csv = ROOT / "outputs" / "raw" / "hayabusa_real_output.csv"
        if not real_csv.exists():
            self.skipTest("hayabusa_real_output.csv not available")
        ground_truth = ed.load_ground_truth(gt_path)
        all_alerts = ed.load_real_output(real_csv)
        results = ed.evaluate_samples(ground_truth, all_alerts, [], [])
        self.assertEqual(len(results), 6)

    def test_each_result_has_required_keys(self):
        """Each result dict must have the required output keys."""
        gt_path = ROOT / "data" / "ground_truth.csv"
        real_csv = ROOT / "outputs" / "raw" / "hayabusa_real_output.csv"
        if not real_csv.exists():
            self.skipTest("hayabusa_real_output.csv not available")
        ground_truth = ed.load_ground_truth(gt_path)
        all_alerts = ed.load_real_output(real_csv)
        results = ed.evaluate_samples(ground_truth, all_alerts, [], [])
        required = {"filename", "status", "matching_alert_titles",
                    "possible_noise_alert_count", "attribution_note"}
        for r in results:
            self.assertTrue(required.issubset(r.keys()), f"Missing keys in: {r}")

    def test_status_values_are_valid(self):
        """All evaluation statuses must be one of: hit, miss, uncertain."""
        gt_path = ROOT / "data" / "ground_truth.csv"
        real_csv = ROOT / "outputs" / "raw" / "hayabusa_real_output.csv"
        if not real_csv.exists():
            self.skipTest("hayabusa_real_output.csv not available")
        ground_truth = ed.load_ground_truth(gt_path)
        all_alerts = ed.load_real_output(real_csv)
        results = ed.evaluate_samples(ground_truth, all_alerts, [], [])
        valid_statuses = {"hit", "miss", "uncertain"}
        for r in results:
            self.assertIn(r["status"], valid_statuses,
                          f"{r['filename']} has invalid status: {r['status']}")

    def test_deterministic_output(self):
        """Running evaluation twice on the same inputs must produce identical results."""
        gt_path = ROOT / "data" / "ground_truth.csv"
        real_csv = ROOT / "outputs" / "raw" / "hayabusa_real_output.csv"
        if not real_csv.exists():
            self.skipTest("hayabusa_real_output.csv not available")
        ground_truth = ed.load_ground_truth(gt_path)
        all_alerts = ed.load_real_output(real_csv)
        r1 = ed.evaluate_samples(ground_truth, all_alerts, [], [])
        r2 = ed.evaluate_samples(ground_truth, all_alerts, [], [])
        self.assertEqual(
            [(r["filename"], r["status"]) for r in r1],
            [(r["filename"], r["status"]) for r in r2],
        )


class TestProcessingTime(unittest.TestCase):

    def test_parse_processing_time_from_real_log(self):
        """Processing time must be parseable from the real run log."""
        log_path = ROOT / "outputs" / "raw" / "hayabusa_run_log.txt"
        if not log_path.exists():
            self.skipTest("Run log not available")
        seconds, raw = ed.parse_processing_time(log_path)
        self.assertIsNotNone(seconds, f"Could not parse processing time: {raw}")
        self.assertGreater(seconds, 0)
        self.assertAlmostEqual(seconds, 5.404, places=2)

    def test_missing_log_returns_unavailable(self):
        """Missing run log must return (None, 'unavailable: ...')."""
        seconds, raw = ed.parse_processing_time(Path("/nonexistent/log.txt"))
        self.assertIsNone(seconds)
        self.assertIn("unavailable", raw.lower())

    def test_log_without_elapsed_returns_unavailable(self):
        """A log file without an elapsed time line returns unavailable."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("No elapsed time here.\n")
            tmp = Path(f.name)
        try:
            seconds, raw = ed.parse_processing_time(tmp)
            self.assertIsNone(seconds)
            self.assertIn("unavailable", raw.lower())
        finally:
            tmp.unlink(missing_ok=True)

    def test_ansi_escape_codes_stripped(self):
        """ANSI escape codes in the log file must not prevent time parsing."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("\x1b[0mElapsed time: \x1b[0m00:00:07.123\n")
            tmp = Path(f.name)
        try:
            seconds, raw = ed.parse_processing_time(tmp)
            self.assertIsNotNone(seconds)
            self.assertAlmostEqual(seconds, 7.123, places=2)
        finally:
            tmp.unlink(missing_ok=True)


class TestOutputConsistency(unittest.TestCase):

    def test_evaluation_json_exists_and_valid(self):
        """outputs/evaluation.json must exist and be valid JSON with required keys."""
        json_path = ROOT / "outputs" / "evaluation.json"
        self.assertTrue(json_path.exists(), "evaluation.json does not exist (run evaluate_detection.py)")
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("metadata", data)
        self.assertIn("samples", data)
        self.assertIn("limitations", data)

    def test_evaluation_csv_exists_and_has_rows(self):
        """outputs/evaluation.csv must exist and have at least 6 data rows."""
        csv_path = ROOT / "outputs" / "evaluation.csv"
        self.assertTrue(csv_path.exists(), "evaluation.csv does not exist")
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        self.assertGreaterEqual(len(rows), 6)

    def test_json_and_csv_sample_count_match(self):
        """The number of samples in JSON and CSV must match."""
        json_path = ROOT / "outputs" / "evaluation.json"
        csv_path = ROOT / "outputs" / "evaluation.csv"
        if not json_path.exists() or not csv_path.exists():
            self.skipTest("Evaluation outputs not generated yet")
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            csv_rows = list(reader)
        self.assertEqual(len(data["samples"]), len(csv_rows))

    def test_evaluation_json_has_limitations(self):
        """evaluation.json must include a non-empty limitations list."""
        json_path = ROOT / "outputs" / "evaluation.json"
        if not json_path.exists():
            self.skipTest("evaluation.json not generated yet")
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertIsInstance(data["limitations"], list)
        self.assertGreater(len(data["limitations"]), 0)

    def test_evaluation_json_processing_time_present(self):
        """evaluation.json must document processing time or explicitly state unavailability."""
        json_path = ROOT / "outputs" / "evaluation.json"
        if not json_path.exists():
            self.skipTest("evaluation.json not generated yet")
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        meta = data.get("metadata", {})
        # Must have the key regardless of value
        self.assertIn("processing_time_seconds", meta)
        self.assertIn("processing_time_source", meta)


if __name__ == "__main__":
    unittest.main()

