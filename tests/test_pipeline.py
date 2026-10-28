#!/usr/bin/env python3
"""
tests/test_pipeline.py — Comprehensive 18-Check QA Test Suite
Validates the end-to-end Windows Threat Hunting pipeline against all acceptance criteria:
  Check 01: Dataset provenance recorded
  Check 02: Selected EVTX files exist & readable
  Check 03: SHA-256 integrity match between disk and dataset_inventory.csv
  Check 04: Hayabusa version recorded and verified (v4.2.0)
  Check 05: Hayabusa dfir-timeline command execution log verified
  Check 06: Raw CSV output exists, parseable, and has 85 alert rows
  Check 07: Raw alert counts match run log metrics (85 detections)
  Check 08: Processed schemas strictly match Team Integration Contract
  Check 09: Timestamps parse correctly as ISO 8601 with explicit UTC zone
  Check 10: Findings have traceable evidence references (EventID, Channel, Record/Rule)
  Check 11: Finding status values strictly from enum {candidate, validated_observation, inconclusive}
  Check 12: ATT&CK mappings include explicit analytical rationales
  Check 13: ATT&CK catalog reconciled (8 evidence-backed techniques; T1087.001 & T1070.006 excluded)
  Check 14: Timeline ordered chronologically
  Check 15: processed_data.json data consistency with CSVs
  Check 16: Dashboard HTML file exists with honesty banner & interactive elements
  Check 17: Local HTTP server launcher script verified
  Check 18: Absence of hardcoded author-specific absolute paths
"""

import csv
import hashlib
import json
import os
import re
import subprocess
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

class TestWindowsThreatHuntingPipeline(unittest.TestCase):

    def setUp(self):
        self.root = ROOT
        self.inv_path = self.root / "data" / "dataset_inventory.csv"
        self.raw_dir = self.root / "data" / "raw"
        self.hayabusa_exe = self.root / "hayabusa" / "hayabusa.exe"
        self.run_log = self.root / "outputs" / "raw" / "hayabusa_run_log.txt"
        self.raw_csv = self.root / "outputs" / "raw" / "hayabusa_raw_output.csv"
        self.findings_csv = self.root / "outputs" / "findings.csv"
        self.shortlist_csv = self.root / "outputs" / "shortlist.csv"
        self.timeline_csv = self.root / "outputs" / "timeline.csv"
        self.attack_csv = self.root / "outputs" / "attack_mapping.csv"
        self.json_path = self.root / "outputs" / "processed_data.json"
        self.html_path = self.root / "src" / "summary.html"
        self.serve_py = self.root / "scripts" / "serve_dashboard.py"

    # ── Check 01: Dataset provenance recorded ────────────────────────────────
    def test_01_dataset_provenance_recorded(self):
        self.assertTrue(self.inv_path.exists(), "dataset_inventory.csv missing")
        with open(self.inv_path, newline="", encoding="utf-8-sig") as f:
            reader = list(csv.DictReader(f))
        self.assertGreaterEqual(len(reader), 3, "Inventory must contain at least 3 datasets")
        for row in reader:
            self.assertTrue(row.get("filename"), "Filename required in inventory")
            self.assertTrue(row.get("sha256"), f"SHA-256 missing for {row.get('filename')}")
            self.assertTrue(row.get("source_url"), f"source_url missing for {row.get('filename')}")
            self.assertEqual(len(row["sha256"].strip()), 64, f"Invalid SHA-256 format in {row['filename']}")

    # ── Check 02: Selected EVTX files exist and are readable ─────────────────
    def test_02_evtx_files_exist_and_readable(self):
        self.assertTrue(self.raw_dir.exists(), "data/raw directory missing")
        evtx_files = list(self.raw_dir.glob("*.evtx"))
        self.assertGreaterEqual(len(evtx_files), 3, "Expected at least 3 EVTX files in data/raw")
        for f in evtx_files:
            size = f.stat().st_size
            self.assertGreater(size, 4096, f"EVTX file {f.name} too small or empty")
            with open(f, "rb") as fh:
                header = fh.read(8)
                self.assertEqual(header, b"ElfFile\x00", f"Invalid EVTX magic header in {f.name}")

    # ── Check 03: SHA-256 integrity match ────────────────────────────────────
    def test_03_evtx_sha256_integrity(self):
        with open(self.inv_path, newline="", encoding="utf-8-sig") as f:
            inventory = {r["filename"]: r["sha256"].lower().strip() for r in csv.DictReader(f)}
        
        for filename, expected_hash in inventory.items():
            evtx_path = self.raw_dir / filename
            self.assertTrue(evtx_path.exists(), f"Expected EVTX file {filename} not found on disk")
            computed_hash = hashlib.sha256(evtx_path.read_bytes()).hexdigest().lower()
            self.assertEqual(computed_hash, expected_hash, f"SHA-256 mismatch for {filename}")

    # ── Check 04: Hayabusa executable & version identified ───────────────────
    def test_04_hayabusa_executable_and_version(self):
        self.assertTrue(self.hayabusa_exe.exists(), "hayabusa/hayabusa.exe missing")
        # Run help to verify command output
        proc = subprocess.run([str(self.hayabusa_exe), "help"], capture_output=True, text=True, check=True)
        self.assertIn("Hayabusa v4.2.0 - Autumn Release", proc.stdout)
        self.assertIn("dfir-timeline", proc.stdout)

    # ── Check 05: Hayabusa dfir-timeline command execution log verified ──────
    def test_05_hayabusa_command_log_verification(self):
        self.assertTrue(self.run_log.exists(), "outputs/raw/hayabusa_run_log.txt missing")
        with open(self.run_log, encoding="utf-8", errors="replace") as f:
            log_text = f.read()
        self.assertIn("Total event log files", log_text)
        self.assertIn("Total | Unique detections: 85 | 33", log_text)

    # ── Check 06: Raw CSV output exists and is parseable ─────────────────────
    def test_06_raw_csv_structure_and_counts(self):
        self.assertTrue(self.raw_csv.exists(), "outputs/raw/hayabusa_raw_output.csv missing")
        with open(self.raw_csv, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        self.assertEqual(len(rows), 85, f"Expected exactly 85 alert rows in raw CSV, found {len(rows)}")
        required_cols = {"Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID"}
        self.assertTrue(required_cols.issubset(set(reader.fieldnames or [])), "Raw CSV missing required columns")

    # ── Check 07: Raw alert counts match run log metrics ─────────────────────
    def test_07_raw_vs_log_count_consistency(self):
        with open(self.raw_csv, newline="", encoding="utf-8-sig") as f:
            raw_count = len(list(csv.DictReader(f)))
        with open(self.run_log, encoding="utf-8", errors="replace") as f:
            log_text = f.read()
        self.assertIn(f"detections: {raw_count}", log_text, "Detection count in run log does not match raw CSV rows")

    # ── Check 08: Processed schemas strictly match Team Integration Contract ─
    def test_08_contract_schemas(self):
        contracts = {
            self.shortlist_csv: [
                "finding_id", "timestamp", "timezone", "alert_name", "severity",
                "rule_name", "source_file", "event_reference", "analyst_note"
            ],
            self.findings_csv: [
                "finding_id", "timestamp", "timezone", "alert_name", "severity",
                "status", "confidence", "evidence_reference", "interpretation",
                "benign_explanation", "limitation", "next_step"
            ],
            self.timeline_csv: [
                "timestamp", "timezone", "finding_id", "event_id", "channel",
                "host_label", "summary", "evidence_reference"
            ],
            self.attack_csv: [
                "finding_id", "tactic", "technique_id", "technique_name",
                "mapping_rationale", "evidence_reference"
            ]
        }
        for csv_path, expected_cols in contracts.items():
            self.assertTrue(csv_path.exists(), f"Output file missing: {csv_path.name}")
            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)
            self.assertEqual(header, expected_cols, f"Schema mismatch in {csv_path.name}")

    # ── Check 09: Timestamps parse correctly as ISO 8601 with explicit UTC ───
    def test_09_timestamp_format_iso8601(self):
        for csv_path in [self.shortlist_csv, self.findings_csv, self.timeline_csv]:
            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader, start=2):
                    ts = row.get("timestamp", "")
                    self.assertTrue(ts, f"Missing timestamp at row {i} in {csv_path.name}")
                    # Validate ISO 8601 parsing
                    dt = datetime.fromisoformat(ts)
                    self.assertIsNotNone(dt.tzinfo, f"Timestamp {ts} in {csv_path.name} missing timezone offset")
                    self.assertEqual(row.get("timezone"), "UTC", f"Timezone column must be UTC in {csv_path.name}")

    # ── Check 10: Findings have traceable evidence references ────────────────
    def test_10_evidence_traceability(self):
        with open(self.findings_csv, newline="", encoding="utf-8") as f:
            findings = list(csv.DictReader(f))
        self.assertEqual(len(findings), 19, "Expected exactly 19 investigated findings")
        for f in findings:
            ev_ref = f.get("evidence_reference", "")
            self.assertTrue(ev_ref, f"Finding {f['finding_id']} has empty evidence reference")
            self.assertIn("EventID:", ev_ref)
            self.assertIn("Channel:", ev_ref)
            self.assertNotIn("/ n/a", ev_ref, f"Finding {f['finding_id']} contains unformatted 'n/a' placeholder")

    # ── Check 11: Finding status classification follows rules ────────────────
    def test_11_finding_status_classification(self):
        valid_statuses = {"candidate", "validated_observation", "inconclusive"}
        with open(self.findings_csv, newline="", encoding="utf-8") as f:
            findings = list(csv.DictReader(f))
        
        status_map = {f["finding_id"]: f["status"] for f in findings}
        for fid, status in status_map.items():
            self.assertIn(status, valid_statuses, f"Invalid status '{status}' in finding {fid}")

        # Check downgraded findings:
        self.assertEqual(status_map.get("F-09"), "inconclusive", "F-09 (Sysmon reg key) must be inconclusive")
        self.assertEqual(status_map.get("F-12"), "inconclusive", "F-12 (Defender task) must be inconclusive")
        # Check duplicate rule candidate:
        self.assertEqual(status_map.get("F-03"), "candidate", "F-03 (duplicate LSASS alert) must be candidate")
        self.assertEqual(status_map.get("F-08"), "candidate", "F-08 (duplicate task deletion) must be candidate")

    # ── Check 12: ATT&CK mappings have valid technique IDs and rationales ────
    def test_12_attack_mapping_rationales(self):
        with open(self.attack_csv, newline="", encoding="utf-8") as f:
            mappings = list(csv.DictReader(f))
        self.assertGreater(len(mappings), 0, "attack_mapping.csv is empty")
        for m in mappings:
            self.assertTrue(m.get("technique_id", "").startswith("T"), f"Invalid technique ID: {m.get('technique_id')}")
            self.assertTrue(len(m.get("mapping_rationale", "")) > 20, f"Rationale too short in mapping for {m.get('finding_id')}")
            self.assertTrue(m.get("evidence_reference"), f"Missing evidence reference in mapping {m.get('finding_id')}")

    # ── Check 13: ATT&CK technique catalog reconciled ────────────────────────
    def test_13_attack_technique_reconciliation(self):
        with open(self.attack_csv, newline="", encoding="utf-8") as f:
            mappings = list(csv.DictReader(f))
        mapped_techs = set(m["technique_id"] for m in mappings)
        
        # Verify unevidenced techniques are removed
        self.assertNotIn("T1070.006", mapped_techs, "T1070.006 (Timestomp) must not be in active attack mappings")
        self.assertNotIn("T1087.001", mapped_techs, "T1087.001 (Local Accounts) must not be mapped (whoami is T1033)")
        
        # Verify whoami is correctly mapped to T1033
        f11_techs = [m["technique_id"] for m in mappings if m["finding_id"] == "F-11"]
        self.assertIn("T1033", f11_techs, "Finding F-11 (whoami) must map to T1033")

        # Verify exactly 8 evidence-backed techniques
        expected_techs = {"T1003.001", "T1055", "T1059.001", "T1059.003", "T1548.002", "T1053.005", "T1070.004", "T1033"}
        self.assertEqual(mapped_techs, expected_techs, f"Expected techniques {expected_techs}, got {mapped_techs}")

    # ── Check 14: Timeline ordered chronologically ───────────────────────────
    def test_14_timeline_chronological_order(self):
        with open(self.timeline_csv, newline="", encoding="utf-8") as f:
            timeline_rows = list(csv.DictReader(f))
        self.assertEqual(len(timeline_rows), 85, "Timeline must contain 85 events matching raw alerts")
        dts = [datetime.fromisoformat(r["timestamp"]) for r in timeline_rows]
        is_sorted = all(dts[i] <= dts[i+1] for i in range(len(dts) - 1))
        self.assertTrue(is_sorted, "Timeline events are not in ascending chronological order")

    # ── Check 15: processed_data.json data consistency with CSVs ─────────────
    def test_15_processed_json_consistency(self):
        self.assertTrue(self.json_path.exists(), "outputs/processed_data.json missing")
        with open(self.json_path, encoding="utf-8") as f:
            data = json.load(f)
        
        meta = data.get("metadata", {})
        self.assertEqual(meta.get("total_raw_alerts"), 85)
        self.assertEqual(meta.get("total_findings"), 19)
        self.assertEqual(meta.get("total_timeline_events"), 85)
        self.assertEqual(meta.get("total_attack_mappings"), 28)
        self.assertEqual(meta.get("total_unique_techniques"), 8)
        self.assertEqual(len(data.get("findings", [])), 19)
        self.assertEqual(len(data.get("timeline", [])), 85)
        self.assertEqual(len(data.get("attack_mappings", [])), 28)

    # ── Check 16: Dashboard HTML file exists with honesty banner & elements ──
    def test_16_dashboard_html_and_embedded_data(self):
        self.assertTrue(self.html_path.exists(), "src/summary.html missing")
        html_text = self.html_path.read_text(encoding="utf-8")
        self.assertGreater(len(html_text), 50000, "Dashboard HTML too small")
        self.assertIn("data-source-banner", html_text, "Honesty banner element missing in HTML")
        self.assertIn("dashboard-error-state", html_text, "Dashboard error state container missing")
        self.assertIn('id="search-input"', html_text, "Search input element missing")
        self.assertIn('id="severity-filter"', html_text, "Severity filter select missing")
        self.assertIn('id="status-filter"', html_text, "Status filter select missing")
        self.assertIn('id="reset-filter-btn"', html_text, "Reset filter button missing")
        self.assertIn('id="finding-modal"', html_text, "Evidence modal missing")

    # ── Check 17: Local server launcher script verified ──────────────────────
    def test_17_serve_script_verified(self):
        self.assertTrue(self.serve_py.exists(), "scripts/serve_dashboard.py missing")
        content = self.serve_py.read_text(encoding="utf-8")
        self.assertIn("ThreadingHTTPServer", content)
        self.assertIn("summary.html", content)

    # ── Check 18: Absence of hardcoded user-specific absolute paths ──────────
    def test_18_no_hardcoded_user_paths(self):
        pattern = re.compile(r'[a-zA-Z]:\\\\Users\\\\[a-zA-Z0-9_-]+(?:\\\\skill[-_]lab)', re.IGNORECASE)
        bad_paths = []
        for dirpath in [self.root / "docs", self.root / "scripts", self.root / "qa", self.root / "tests"]:
            if not dirpath.exists():
                continue
            for f in dirpath.rglob("*"):
                if f.is_file() and f.suffix in [".py", ".ps1", ".md", ".json", ".html"]:
                    text = f.read_text(encoding="utf-8", errors="ignore")
                    if pattern.search(text):
                        bad_paths.append(str(f.relative_to(self.root)))
        self.assertEqual(bad_paths, [], f"Hardcoded developer paths found in: {bad_paths}")

if __name__ == "__main__":
    unittest.main()
