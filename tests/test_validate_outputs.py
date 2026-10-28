#!/usr/bin/env python3
"""
test_validate_outputs.py — Unit tests for scripts/validate_outputs.py (Part A).

Tests the validation functions and checks that all contract CSV headers are intact.
"""

import csv
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestContractCsvHeaders(unittest.TestCase):
    """Verify that all four contract CSVs have their frozen headers."""

    FINDINGS_HEADERS = [
        "finding_id", "timestamp", "timezone", "alert_name", "severity", "status",
        "confidence", "host", "event_id", "channel", "record_id", "rule_id",
        "evidence_reference", "details", "interpretation", "benign_explanation",
        "limitation", "next_step", "techniques",
    ]
    SHORTLIST_HEADERS = [
        "finding_id", "timestamp", "timezone", "alert_name", "severity",
        "rule_id", "source_file", "event_reference", "analyst_note",
    ]
    TIMELINE_HEADERS = [
        "timestamp", "timezone", "finding_id", "event_id", "channel",
        "host_label", "level", "summary", "evidence_reference",
    ]
    ATTACK_HEADERS = [
        "finding_id", "tactic", "technique_id", "technique_name",
        "mapping_rationale", "evidence_reference", "confidence",
        "mapping_status", "limitation",
    ]

    def _read_headers(self, path):
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return list(reader.fieldnames or [])

    def test_findings_csv_headers(self):
        path = ROOT / "outputs" / "findings.csv"
        self.assertTrue(path.exists(), "findings.csv missing")
        actual = self._read_headers(path)
        self.assertEqual(actual, self.FINDINGS_HEADERS)

    def test_shortlist_csv_headers(self):
        path = ROOT / "outputs" / "shortlist.csv"
        self.assertTrue(path.exists(), "shortlist.csv missing")
        actual = self._read_headers(path)
        self.assertEqual(actual, self.SHORTLIST_HEADERS)

    def test_timeline_csv_headers(self):
        path = ROOT / "outputs" / "timeline.csv"
        self.assertTrue(path.exists(), "timeline.csv missing")
        actual = self._read_headers(path)
        self.assertEqual(actual, self.TIMELINE_HEADERS)

    def test_attack_mapping_headers(self):
        path = ROOT / "outputs" / "attack_mapping.csv"
        self.assertTrue(path.exists(), "attack_mapping.csv missing")
        actual = self._read_headers(path)
        self.assertEqual(actual, self.ATTACK_HEADERS)


class TestImmutableFiles(unittest.TestCase):
    """Verify that the immutable raw files remain unchanged."""

    def test_hayabusa_raw_output_line_count(self):
        """hayabusa_raw_output.csv must have exactly 11 lines (1 header + 10 data)."""
        path = ROOT / "outputs" / "raw" / "hayabusa_raw_output.csv"
        self.assertTrue(path.exists(), "hayabusa_raw_output.csv missing")
        lines = path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 11, f"Expected 11 lines, got {len(lines)}")

    def test_hayabusa_run_log_exists(self):
        """hayabusa_run_log.txt must exist."""
        path = ROOT / "outputs" / "raw" / "hayabusa_run_log.txt"
        self.assertTrue(path.exists(), "hayabusa_run_log.txt missing")

    def test_hayabusa_run_log_has_content(self):
        """hayabusa_run_log.txt must have substantive content (> 1KB)."""
        path = ROOT / "outputs" / "raw" / "hayabusa_run_log.txt"
        if not path.exists():
            self.skipTest("hayabusa_run_log.txt missing")
        size = path.stat().st_size
        self.assertGreater(size, 1024, f"Run log is too small: {size} bytes")


class TestFindingsDataIntegrity(unittest.TestCase):
    """Verify findings data quality without modifying source files."""

    def _load_findings(self):
        path = ROOT / "outputs" / "findings.csv"
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return list(reader)

    def test_at_least_one_finding(self):
        rows = self._load_findings()
        self.assertGreater(len(rows), 0)

    def test_all_finding_ids_format(self):
        """All finding IDs must match F-NN format."""
        import re
        pattern = re.compile(r"^F-\d{2,}$")
        rows = self._load_findings()
        for row in rows:
            fid = row.get("finding_id", "")
            self.assertTrue(pattern.match(fid), f"Invalid finding_id: {fid!r}")

    def test_valid_status_values(self):
        """All status values must be from the allowed set."""
        valid = {"candidate", "validated_observation", "inconclusive"}
        rows = self._load_findings()
        for row in rows:
            self.assertIn(row.get("status", ""), valid,
                          f"Invalid status: {row.get('status')} in {row.get('finding_id')}")

    def test_valid_severity_values(self):
        """All severity values must be from the allowed set."""
        valid = {"critical", "high", "medium", "low", "informational"}
        rows = self._load_findings()
        for row in rows:
            self.assertIn(row.get("severity", ""), valid,
                          f"Invalid severity: {row.get('severity')} in {row.get('finding_id')}")

    def test_all_timestamps_non_empty(self):
        """All findings must have non-empty timestamps."""
        rows = self._load_findings()
        for row in rows:
            self.assertTrue(row.get("timestamp", "").strip(),
                            f"Empty timestamp in {row.get('finding_id')}")

    def test_attack_mapping_finding_ids_in_findings(self):
        """attack_mapping.csv finding_ids must all exist in findings.csv."""
        findings_path = ROOT / "outputs" / "findings.csv"
        mapping_path = ROOT / "outputs" / "attack_mapping.csv"
        with open(findings_path, newline="", encoding="utf-8") as f:
            findings_ids = {row["finding_id"] for row in csv.DictReader(f)}
        with open(mapping_path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                fid = row.get("finding_id", "")
                self.assertIn(fid, findings_ids,
                              f"attack_mapping finding_id {fid!r} not in findings.csv")


class TestProcessedDataJson(unittest.TestCase):
    """Verify processed_data.json structure."""

    def _load_json(self):
        path = ROOT / "outputs" / "processed_data.json"
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def test_exists(self):
        self.assertTrue((ROOT / "outputs" / "processed_data.json").exists())

    def test_has_metadata(self):
        data = self._load_json()
        self.assertIn("metadata", data)

    def test_has_findings(self):
        data = self._load_json()
        self.assertIn("findings", data)
        self.assertIsInstance(data["findings"], list)

    def test_has_attack_mapping(self):
        data = self._load_json()
        self.assertIn("attack_mapping", data)

    def test_has_timeline(self):
        data = self._load_json()
        self.assertIn("timeline", data)

    def test_metadata_has_evtx_files(self):
        data = self._load_json()
        evtx = data["metadata"].get("evtx_files", [])
        self.assertEqual(len(evtx), 6, f"Expected 6 EVTX files, got {len(evtx)}")


class TestGroundTruthCsv(unittest.TestCase):
    """Tests for data/ground_truth.csv."""

    REQUIRED_COLUMNS = {"filename", "expected_behavior", "expected_technique_ids", "source_note"}
    EXPECTED_SAMPLES = {
        "babyshark_mimikatz_powershell.evtx",
        "CA_sysmon_hashdump_cmd_meterpreter.evtx",
        "Exec_sysmon_meterpreter_reversetcp_msipackage.evtx",
        "sysmon_10_11_lsass_memdump.evtx",
        "sysmon_local_account_creation_and_added_admingroup_12_13.evtx",
        "temp_scheduled_task_4698_4699.evtx",
    }

    def _load_gt(self):
        path = ROOT / "data" / "ground_truth.csv"
        self.assertTrue(path.exists(), "data/ground_truth.csv missing")
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return list(reader), set(reader.fieldnames or [])

    def test_exactly_six_rows(self):
        rows, _ = self._load_gt()
        self.assertEqual(len(rows), 6)

    def test_required_columns_present(self):
        rows, fieldnames = self._load_gt()
        self.assertTrue(self.REQUIRED_COLUMNS.issubset(fieldnames),
                        f"Missing: {self.REQUIRED_COLUMNS - fieldnames}")

    def test_all_six_samples_present(self):
        rows, _ = self._load_gt()
        found = {r["filename"].strip() for r in rows}
        self.assertEqual(found, self.EXPECTED_SAMPLES)

    def test_each_row_has_source_note(self):
        rows, _ = self._load_gt()
        for row in rows:
            self.assertTrue(row.get("source_note", "").strip(),
                            f"Empty source_note for {row.get('filename')}")

    def test_expected_technique_ids_format(self):
        """Expected technique IDs should use semicolon separation."""
        rows, _ = self._load_gt()
        import re
        tid_pattern = re.compile(r"^T\d{4}(?:\.\d{3})?$")
        for row in rows:
            tids_str = row.get("expected_technique_ids", "")
            if not tids_str.strip():
                continue
            tids = [t.strip() for t in tids_str.split(";") if t.strip()]
            for tid in tids:
                # Each ID should match T####[.###] pattern OR be "UNCERTAIN"
                if not tid.upper().startswith("UNCERTAIN"):
                    self.assertTrue(tid_pattern.match(tid),
                                    f"Invalid technique ID: {tid!r} in {row.get('filename')}")


if __name__ == "__main__":
    unittest.main()

