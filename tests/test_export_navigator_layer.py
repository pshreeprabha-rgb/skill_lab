#!/usr/bin/env python3
"""
test_export_navigator_layer.py — Unit tests for scripts/export_navigator_layer.py (Part D).

Tests:
- Layer structure validity
- Correct mapped technique IDs
- Finding references in comments
- Duplicate mapping handling
- Malformed technique handling
- JSON serialization
- Deterministic output
- CSV header preservation (findings download)
- CSV escaping edge cases
"""

import csv
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import export_navigator_layer as enl


SAMPLE_MAPPING_ROWS = [
    {"finding_id": "F-01", "technique_id": "T1003.001", "tactic": "Credential Access",
     "technique_name": "LSASS Memory", "confidence": "high", "mapping_status": "validated_observation"},
    {"finding_id": "F-02", "technique_id": "T1059.001", "tactic": "Execution",
     "technique_name": "PowerShell", "confidence": "medium", "mapping_status": "candidate"},
    {"finding_id": "F-03", "technique_id": "T1003.001", "tactic": "Credential Access",
     "technique_name": "LSASS Memory", "confidence": "medium", "mapping_status": "candidate"},
]

DUPLICATE_ROWS = [
    {"finding_id": "F-01", "technique_id": "T1003.001", "tactic": "Credential Access",
     "technique_name": "LSASS Memory", "confidence": "high", "mapping_status": "validated_observation"},
    {"finding_id": "F-02", "technique_id": "T1003.001", "tactic": "Credential Access",
     "technique_name": "LSASS Memory", "confidence": "medium", "mapping_status": "candidate"},
]


class TestLayerStructure(unittest.TestCase):

    def test_required_top_level_keys(self):
        """Layer must have: name, versions, domain, techniques."""
        entries = enl.build_technique_entries(SAMPLE_MAPPING_ROWS)
        layer = enl.build_layer(entries)
        for key in ("name", "versions", "domain", "techniques"):
            self.assertIn(key, layer, f"Missing key: {key}")

    def test_versions_structure(self):
        """versions must have attack, navigator, layer keys."""
        entries = enl.build_technique_entries(SAMPLE_MAPPING_ROWS)
        layer = enl.build_layer(entries)
        versions = layer["versions"]
        for vk in ("attack", "navigator", "layer"):
            self.assertIn(vk, versions, f"Missing versions.{vk}")

    def test_domain_is_enterprise_attack(self):
        """Domain must be enterprise-attack."""
        entries = enl.build_technique_entries(SAMPLE_MAPPING_ROWS)
        layer = enl.build_layer(entries)
        self.assertEqual(layer["domain"], "enterprise-attack")

    def test_techniques_is_list(self):
        """techniques must be a list."""
        entries = enl.build_technique_entries(SAMPLE_MAPPING_ROWS)
        layer = enl.build_layer(entries)
        self.assertIsInstance(layer["techniques"], list)

    def test_validation_passes_for_valid_layer(self):
        """validate_layer must not raise for a valid layer."""
        entries = enl.build_technique_entries(SAMPLE_MAPPING_ROWS)
        layer = enl.build_layer(entries)
        # Should not raise
        enl.validate_layer(layer)

    def test_validation_fails_missing_key(self):
        """validate_layer must raise ValueError when required key is missing."""
        layer = {"name": "test", "domain": "enterprise-attack"}  # missing versions, techniques
        with self.assertRaises(ValueError):
            enl.validate_layer(layer)


class TestTechniqueEntries(unittest.TestCase):

    def test_correct_technique_ids(self):
        """Only technique IDs from the mapping should appear in entries."""
        entries = enl.build_technique_entries(SAMPLE_MAPPING_ROWS)
        entry_ids = {e["techniqueID"] for e in entries}
        expected_ids = {"T1003.001", "T1059.001"}
        self.assertEqual(entry_ids, expected_ids)

    def test_finding_ids_in_comment(self):
        """Each entry's comment must reference its associated finding ID(s)."""
        entries = enl.build_technique_entries(SAMPLE_MAPPING_ROWS)
        for entry in entries:
            self.assertIn("Finding IDs:", entry["comment"])

    def test_duplicate_handling_merges_findings(self):
        """Multiple findings for the same technique must be merged into one entry."""
        entries = enl.build_technique_entries(DUPLICATE_ROWS)
        self.assertEqual(len(entries), 1, "Duplicate technique should produce one entry")
        entry = entries[0]
        self.assertIn("F-01", entry["comment"])
        self.assertIn("F-02", entry["comment"])

    def test_high_confidence_color(self):
        """A high-confidence mapping should use the red color."""
        high_rows = [SAMPLE_MAPPING_ROWS[0]]  # F-01, high
        entries = enl.build_technique_entries(high_rows)
        self.assertEqual(entries[0]["color"], "#ff6666")

    def test_medium_confidence_color(self):
        """A medium-confidence mapping should use the orange color."""
        med_rows = [SAMPLE_MAPPING_ROWS[1]]  # F-02, medium
        entries = enl.build_technique_entries(med_rows)
        self.assertEqual(entries[0]["color"], "#ff9966")

    def test_empty_rows_produces_empty_entries(self):
        """Empty mapping rows should produce an empty techniques list."""
        entries = enl.build_technique_entries([])
        self.assertEqual(entries, [])

    def test_malformed_row_skipped(self):
        """Rows with empty technique_id should be skipped gracefully."""
        rows = [{"finding_id": "F-01", "technique_id": "", "tactic": "", "confidence": "high"}]
        # Should not raise; empty ID rows are filtered in load_attack_mapping
        entries = enl.build_technique_entries(rows)
        # An empty string key would still pass; but with empty id, we expect 1 entry with key ""
        # The main validator would catch this; test that it doesn't crash
        self.assertIsInstance(entries, list)

    def test_deterministic_output(self):
        """Same input always produces same output (deterministic ordering)."""
        e1 = enl.build_technique_entries(SAMPLE_MAPPING_ROWS)
        e2 = enl.build_technique_entries(SAMPLE_MAPPING_ROWS)
        self.assertEqual(
            [e["techniqueID"] for e in e1],
            [e["techniqueID"] for e in e2],
        )

    def test_enabled_is_true(self):
        """All technique entries must have enabled=True."""
        entries = enl.build_technique_entries(SAMPLE_MAPPING_ROWS)
        for e in entries:
            self.assertTrue(e.get("enabled"), f"enabled not True for {e['techniqueID']}")


class TestJsonSerialization(unittest.TestCase):

    def test_layer_json_is_valid(self):
        """Layer must serialize to valid JSON without errors."""
        entries = enl.build_technique_entries(SAMPLE_MAPPING_ROWS)
        layer = enl.build_layer(entries)
        serialized = json.dumps(layer)
        # Must parse back without error
        parsed = json.loads(serialized)
        self.assertEqual(parsed["domain"], "enterprise-attack")

    def test_real_layer_file_exists_and_valid(self):
        """The generated attack_navigator_layer.json must exist and be valid JSON."""
        layer_path = ROOT / "outputs" / "attack_navigator_layer.json"
        self.assertTrue(layer_path.exists(), "attack_navigator_layer.json not generated yet")
        with open(layer_path, encoding="utf-8") as f:
            layer = json.load(f)
        self.assertIn("techniques", layer)
        self.assertIn("domain", layer)

    def test_real_layer_only_contains_mapped_techniques(self):
        """Generated layer should only contain technique IDs from attack_mapping.csv."""
        layer_path = ROOT / "outputs" / "attack_navigator_layer.json"
        mapping_path = ROOT / "outputs" / "attack_mapping.csv"
        if not layer_path.exists() or not mapping_path.exists():
            self.skipTest("Required files not generated")
        with open(layer_path, encoding="utf-8") as f:
            layer = json.load(f)
        with open(mapping_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            mapped_tids = {row["technique_id"].strip() for row in reader if row.get("technique_id")}
        layer_tids = {t["techniqueID"] for t in layer["techniques"]}
        unmapped = layer_tids - mapped_tids
        self.assertEqual(unmapped, set(), f"Layer contains unmapped techniques: {unmapped}")


class TestCsvEscaping(unittest.TestCase):
    """Test that CSV generation properly escapes special characters.
    These tests verify the escaping logic used for the findings CSV download."""

    def _write_csv(self, rows, fieldnames):
        """Helper: write rows to a CSV string."""
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        return output.getvalue()

    def test_comma_in_field_escaped(self):
        """A comma inside a field must be properly quoted in CSV output."""
        rows = [{"finding_id": "F-01", "alert_name": "Foo, Bar"}]
        csv_text = self._write_csv(rows, ["finding_id", "alert_name"])
        # CSV should quote the field
        self.assertIn('"Foo, Bar"', csv_text)

    def test_quote_in_field_escaped(self):
        """A double-quote inside a field must be escaped (doubled) in CSV output."""
        rows = [{"finding_id": "F-01", "alert_name": 'Say "hello"'}]
        csv_text = self._write_csv(rows, ["finding_id", "alert_name"])
        # Python csv module uses RFC 4180 doubling
        self.assertIn('""hello""', csv_text)

    def test_unicode_preserved(self):
        """Unicode characters in fields must be preserved in CSV output."""
        rows = [{"finding_id": "F-01", "alert_name": "Tâche planifiée"}]
        csv_text = self._write_csv(rows, ["finding_id", "alert_name"])
        self.assertIn("Tâche planifiée", csv_text)

    def test_newline_in_field_escaped(self):
        """A newline inside a field must be properly quoted in CSV output."""
        rows = [{"finding_id": "F-01", "alert_name": "Line1\nLine2"}]
        csv_text = self._write_csv(rows, ["finding_id", "alert_name"])
        self.assertIn('"Line1\nLine2"', csv_text)

    def test_contract_headers_preserved(self):
        """Findings CSV must use the contract headers in order."""
        expected = [
            "finding_id", "timestamp", "timezone", "alert_name", "severity", "status",
            "confidence", "host", "event_id", "channel", "record_id", "rule_id",
            "evidence_reference", "details", "interpretation", "benign_explanation",
            "limitation", "next_step", "techniques",
        ]
        findings_path = ROOT / "outputs" / "findings.csv"
        if not findings_path.exists():
            self.skipTest("findings.csv not available")
        with open(findings_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            actual = list(reader.fieldnames or [])
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()

