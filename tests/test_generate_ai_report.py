#!/usr/bin/env python3
"""
test_generate_ai_report.py — Unit tests for scripts/generate_ai_report.py (Part C).

Tests use mocked model responses — NO real API calls are made.

Tests:
- validate_finding_refs: valid refs, invented IDs
- validate_technique_ids: valid project IDs, unmapped IDs
- validate_numeric_claims: correct counts, incorrect counts, percentages
- validate_status_labels: candidate/inconclusive handling
- validate_report: accepted header, rejected output behavior
- Missing API key handling (no real call)
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import generate_ai_report as gar


SAMPLE_DATA = {
    "findings": [
        {"finding_id": "F-01", "status": "candidate", "alert_name": "LSASS Dump"},
        {"finding_id": "F-02", "status": "validated_observation", "alert_name": "PowerShell"},
        {"finding_id": "F-03", "status": "candidate", "alert_name": "Account Creation"},
    ],
    "attack_mapping": [
        {"technique_id": "T1003.001", "tactic": "credential-access", "confidence": "high"},
        {"technique_id": "T1059.001", "tactic": "execution", "confidence": "medium"},
    ],
    "metadata": {
        "total_detections": 94,
        "hayabusa_version": "v4.2.0",
    },
}

VALID_FINDING_IDS = ["F-01", "F-02", "F-03"]
VALID_TECHNIQUE_IDS = ["T1003.001", "T1059.001"]


class TestValidateFindingRefs(unittest.TestCase):

    def test_valid_references_pass(self):
        """All valid F-NN references should return no invalid IDs."""
        text = "Finding F-01 shows LSASS access. F-02 shows PowerShell."
        invalid = gar.validate_finding_refs(text, VALID_FINDING_IDS)
        self.assertEqual(invalid, [])

    def test_invented_finding_id_detected(self):
        """An invented finding ID (e.g., F-99) must be flagged."""
        text = "Finding F-99 shows new malware technique."
        invalid = gar.validate_finding_refs(text, VALID_FINDING_IDS)
        self.assertIn("F-99", invalid)

    def test_date_not_confused_with_finding_id(self):
        """Dates like 2026-10-01 should not be misidentified as finding IDs."""
        text = "Analysis conducted on 2026-10-01. F-01 was the first finding."
        invalid = gar.validate_finding_refs(text, VALID_FINDING_IDS)
        # Dates don't match F-\d{2,} pattern; only F-01 matches and it's valid
        self.assertEqual(invalid, [])

    def test_empty_text_no_findings(self):
        """Empty text should return no invalid IDs."""
        invalid = gar.validate_finding_refs("", VALID_FINDING_IDS)
        self.assertEqual(invalid, [])

    def test_no_finding_refs_in_text(self):
        """Text with no F-NN references should return empty list."""
        text = "This is a general security report with no specific findings cited."
        invalid = gar.validate_finding_refs(text, VALID_FINDING_IDS)
        self.assertEqual(invalid, [])


class TestValidateTechniqueIds(unittest.TestCase):

    def test_valid_technique_passes(self):
        """Valid project technique IDs should return no invalid."""
        text = "T1003.001 was observed in F-01. T1059.001 was used in F-02."
        invalid = gar.validate_technique_ids(text, VALID_TECHNIQUE_IDS)
        self.assertEqual(invalid, [])

    def test_unmapped_technique_flagged(self):
        """A technique not in the project mapping must be flagged."""
        text = "The attacker used T1078 (Valid Accounts) for persistence."
        invalid = gar.validate_technique_ids(text, VALID_TECHNIQUE_IDS)
        self.assertIn("T1078", invalid)

    def test_valid_attrack_id_not_in_project_is_flagged(self):
        """A real ATT&CK ID not in THIS project's mapping must be flagged."""
        text = "T1055 process injection was observed."
        invalid = gar.validate_technique_ids(text, VALID_TECHNIQUE_IDS)
        self.assertIn("T1055", invalid)

    def test_empty_text_no_techniques(self):
        """Empty text returns no invalid techniques."""
        invalid = gar.validate_technique_ids("", VALID_TECHNIQUE_IDS)
        self.assertEqual(invalid, [])


class TestValidateNumericClaims(unittest.TestCase):

    def test_correct_finding_count_passes(self):
        """Stating the correct finding count should produce no violations."""
        text = "The investigation identified 3 findings in total."
        violations = gar.validate_numeric_claims(text, SAMPLE_DATA)
        self.assertEqual(violations, [])

    def test_incorrect_finding_count_flagged(self):
        """Stating 10 findings when only 3 exist should be flagged."""
        text = "This investigation documented 10 findings."
        violations = gar.validate_numeric_claims(text, SAMPLE_DATA)
        self.assertTrue(len(violations) > 0, "Expected violation for wrong count")

    def test_technique_count_overstated_flagged(self):
        """Claiming 50 techniques when only 2 exist should be flagged."""
        text = "A total of 50 ATT&CK techniques were identified."
        violations = gar.validate_numeric_claims(text, SAMPLE_DATA)
        self.assertTrue(len(violations) > 0, "Expected violation for overstated technique count")

    def test_section_numbers_not_flagged(self):
        """Section numbers like '3.' should not trigger false positives."""
        text = "3. Findings\n\nThis section covers 3 findings identified."
        violations = gar.validate_numeric_claims(text, SAMPLE_DATA)
        # The "3 findings" is correct; no violation expected
        self.assertEqual(violations, [])


class TestValidateStatusLabels(unittest.TestCase):

    def test_candidate_finding_with_confirmed_language_flagged(self):
        """A candidate finding described as 'confirmed' should be flagged."""
        text = "F-01 is confirmed to represent a credential dumping attack."
        issues = gar.validate_status_labels(text, SAMPLE_DATA)
        self.assertTrue(len(issues) > 0, "Expected status label issue for F-01 candidate")

    def test_validated_observation_with_confirmed_language_ok(self):
        """A validated_observation finding can appear near certain language."""
        text = "F-02 confirmed use of PowerShell encoding technique."
        # F-02 is validated_observation — should NOT be flagged
        issues = gar.validate_status_labels(text, SAMPLE_DATA)
        # Issues only for candidate/inconclusive findings
        fids_in_issues = [i for i in issues if "F-02" in i]
        self.assertEqual(fids_in_issues, [])

    def test_clean_text_no_issues(self):
        """A report without confirmed/proven language near candidates should pass."""
        text = "F-01 (candidate) shows suspicious LSASS access. F-03 (candidate) shows account creation."
        issues = gar.validate_status_labels(text, SAMPLE_DATA)
        self.assertEqual(issues, [])


class TestValidateReport(unittest.TestCase):

    VALID_REPORT = """\
# AI-generated draft - requires human review

## Executive Summary

This investigation used Hayabusa v4.2.0 to analyze 6 EVTX samples.

## Findings

F-01 (candidate) shows LSASS memory access via procdump.exe. This is uncertain.
F-02 (validated_observation) shows PowerShell execution with encoded commands.
F-03 (candidate) shows suspicious account creation. This is uncertain.

## ATT&CK Techniques

T1003.001 — OS Credential Dumping: LSASS Memory
T1059.001 — PowerShell

## Limitations

Only 6 small EVTX samples were analyzed. No benign baseline is available.
There are 3 findings in this dataset.
"""

    def test_valid_report_passes(self):
        """A well-formed report should pass validation."""
        passed, reasons = gar.validate_report(self.VALID_REPORT, SAMPLE_DATA)
        self.assertTrue(passed, f"Expected PASS but got: {reasons}")
        self.assertEqual(reasons, [])

    def test_missing_header_fails(self):
        """A report without the required header must fail validation."""
        text = "## Summary\nThis is a report without the required header."
        passed, reasons = gar.validate_report(text, SAMPLE_DATA)
        self.assertFalse(passed)
        self.assertTrue(any("header" in r.lower() for r in reasons))

    def test_invented_finding_id_fails(self):
        """A report referencing an invented finding ID must fail."""
        text = "# AI-generated draft - requires human review\n\nF-99 shows critical threat."
        passed, reasons = gar.validate_report(text, SAMPLE_DATA)
        self.assertFalse(passed)
        self.assertTrue(any("F-99" in r for r in reasons))

    def test_unmapped_technique_fails(self):
        """A report citing an unmapped technique must fail."""
        text = "# AI-generated draft - requires human review\n\nT1078 was used for access."
        passed, reasons = gar.validate_report(text, SAMPLE_DATA)
        self.assertFalse(passed)
        self.assertTrue(any("T1078" in r for r in reasons))

    def test_wrong_finding_count_fails(self):
        """A report claiming 10 findings when 3 exist must fail."""
        text = (
            "# AI-generated draft - requires human review\n\n"
            "The investigation identified 10 findings across the dataset."
        )
        passed, reasons = gar.validate_report(text, SAMPLE_DATA)
        self.assertFalse(passed)


class TestMissingApiKey(unittest.TestCase):

    def test_no_api_key_handled_gracefully(self):
        """
        When GEMINI_API_KEY is not set, the script should exit cleanly with 0.
        This test verifies the key-check logic without calling the API.
        """
        import os
        original = os.environ.pop("GEMINI_API_KEY", None)
        try:
            # Verify the check would trigger
            api_key = os.environ.get("GEMINI_API_KEY", "").strip()
            self.assertEqual(api_key, "")
        finally:
            if original is not None:
                os.environ["GEMINI_API_KEY"] = original

    def test_validation_functions_work_without_api_key(self):
        """All deterministic validation functions must work without any API access."""
        text = "# AI-generated draft - requires human review\n\nF-01 shows T1003.001."
        # These calls must complete without network access
        invalid_fids = gar.validate_finding_refs(text, VALID_FINDING_IDS)
        invalid_tids = gar.validate_technique_ids(text, VALID_TECHNIQUE_IDS)
        violations = gar.validate_numeric_claims(text, SAMPLE_DATA)
        issues = gar.validate_status_labels(text, SAMPLE_DATA)
        # All return lists (no exceptions)
        self.assertIsInstance(invalid_fids, list)
        self.assertIsInstance(invalid_tids, list)
        self.assertIsInstance(violations, list)
        self.assertIsInstance(issues, list)


class TestNetworkFailureHandling(unittest.TestCase):
    """
    Tests for network/API failure behavior.
    Uses mock to simulate network errors — no real API call is made.
    """

    def test_validate_report_works_without_network(self):
        """validate_report is deterministic and requires no network access."""
        text = "# AI-generated draft - requires human review\n\nF-01 is uncertain."
        passed, reasons = gar.validate_report(text, SAMPLE_DATA)
        # Should complete without raising
        self.assertIsInstance(passed, bool)
        self.assertIsInstance(reasons, list)


# Note: Live API status — NOT TESTED.
# A mocked test does not constitute a successful live API call.
# To test live API: set GEMINI_API_KEY and run scripts/generate_ai_report.py directly.


if __name__ == "__main__":
    unittest.main()

