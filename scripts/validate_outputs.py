#!/usr/bin/env python3
"""
validate_outputs.py — Windows Threat Hunting System
Validates all project outputs against established contracts.

Runs 18 checks and prints PASS/FAIL per check.
Exits with code 0 if all pass, 1 if any fail.

Usage:
    python scripts/validate_outputs.py
"""

import csv
import json
import re
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

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

VALID_STATUSES = {"candidate", "validated_observation", "inconclusive"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}

CHECKS_PASSED = 0
CHECKS_FAILED = 0
CHECKS_TOTAL = 0


def check(label, passed, detail=""):
    global CHECKS_PASSED, CHECKS_FAILED, CHECKS_TOTAL
    CHECKS_TOTAL += 1
    status = "PASS" if passed else "FAIL"
    if passed:
        CHECKS_PASSED += 1
    else:
        CHECKS_FAILED += 1
    suffix = f" — {detail}" if detail else ""
    print(f"  [{status}] {label}{suffix}")
    return passed


def read_csv_rows(path):
    """Return (headers, rows) or (None, None) on error."""
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            return list(reader.fieldnames or []), rows
    except Exception as e:
        return None, None


def main():
    print("=" * 60)
    print("Validate Outputs — Windows Threat Hunting System")
    print("=" * 60)
    print()

    # ── Check 1: hayabusa_raw_output.csv exists ───────────────────────────
    raw_csv = ROOT / "outputs" / "raw" / "hayabusa_raw_output.csv"
    check("1. hayabusa_raw_output.csv exists", raw_csv.exists())

    # ── Check 2: hayabusa_raw_output.csv has 11 lines (1 header + 10 data) ─
    if raw_csv.exists():
        lines = raw_csv.read_text(encoding="utf-8").splitlines()
        check(
            "2. hayabusa_raw_output.csv line count preserved (11)",
            len(lines) == 11,
            f"found {len(lines)} lines",
        )
    else:
        check("2. hayabusa_raw_output.csv line count preserved (11)", False, "file missing")

    # ── Check 3: hayabusa_run_log.txt exists ──────────────────────────────
    run_log = ROOT / "outputs" / "raw" / "hayabusa_run_log.txt"
    check("3. hayabusa_run_log.txt exists", run_log.exists())

    # ── Check 4: hayabusa_real_output.csv exists ──────────────────────────
    real_csv = ROOT / "outputs" / "raw" / "hayabusa_real_output.csv"
    check("4. hayabusa_real_output.csv exists", real_csv.exists())

    # ── Check 5: findings.csv exists with correct headers ─────────────────
    findings_path = ROOT / "outputs" / "findings.csv"
    findings_ok = findings_path.exists()
    check("5. findings.csv exists", findings_ok)
    if findings_ok:
        try:
            with open(findings_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                actual_headers = list(reader.fieldnames or [])
                findings_rows = list(reader)
            headers_match = actual_headers == FINDINGS_HEADERS
            check(
                "6. findings.csv has correct contract headers",
                headers_match,
                f"got {actual_headers[:3]}..." if not headers_match else "OK",
            )
        except Exception as e:
            check("6. findings.csv has correct contract headers", False, str(e))
            findings_rows = []
    else:
        check("6. findings.csv has correct contract headers", False, "file missing")
        findings_rows = []

    # ── Check 7: findings.csv has at least 1 data row ────────────────────
    check(
        "7. findings.csv has at least 1 data row",
        len(findings_rows) >= 1,
        f"found {len(findings_rows)} rows",
    )

    # ── Check 8: All finding_ids use F-NN format ──────────────────────────
    fid_pattern = re.compile(r"^F-\d{2,}$")
    bad_fids = [r["finding_id"] for r in findings_rows if not fid_pattern.match(r.get("finding_id", ""))]
    check(
        "8. All finding_ids use F-NN format",
        len(bad_fids) == 0,
        f"invalid: {bad_fids}" if bad_fids else "",
    )

    # ── Check 9: All status values are valid ──────────────────────────────
    bad_status = [r["status"] for r in findings_rows if r.get("status", "") not in VALID_STATUSES]
    check(
        "9. All status values are in {candidate, validated_observation, inconclusive}",
        len(bad_status) == 0,
        f"invalid: {set(bad_status)}" if bad_status else "",
    )

    # ── Check 10: All severity values are valid ───────────────────────────
    bad_sev = [r["severity"] for r in findings_rows if r.get("severity", "") not in VALID_SEVERITIES]
    check(
        "10. All severity values are valid",
        len(bad_sev) == 0,
        f"invalid: {set(bad_sev)}" if bad_sev else "",
    )

    # ── Check 11: shortlist.csv exists with correct headers ───────────────
    shortlist_path = ROOT / "outputs" / "shortlist.csv"
    sl_ok = shortlist_path.exists()
    check("11. shortlist.csv exists", sl_ok)
    if sl_ok:
        try:
            with open(shortlist_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                sl_headers = list(reader.fieldnames or [])
            check(
                "12. shortlist.csv has correct contract headers",
                sl_headers == SHORTLIST_HEADERS,
                "OK" if sl_headers == SHORTLIST_HEADERS else f"got {sl_headers}",
            )
        except Exception as e:
            check("12. shortlist.csv has correct contract headers", False, str(e))
    else:
        check("12. shortlist.csv has correct contract headers", False, "file missing")

    # ── Check 13: timeline.csv exists with correct headers ────────────────
    timeline_path = ROOT / "outputs" / "timeline.csv"
    tl_ok = timeline_path.exists()
    check("13. timeline.csv exists", tl_ok)
    if tl_ok:
        try:
            with open(timeline_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                tl_headers = list(reader.fieldnames or [])
            check(
                "14. timeline.csv has correct contract headers",
                tl_headers == TIMELINE_HEADERS,
                "OK" if tl_headers == TIMELINE_HEADERS else f"got {tl_headers}",
            )
        except Exception as e:
            check("14. timeline.csv has correct contract headers", False, str(e))
    else:
        check("14. timeline.csv has correct contract headers", False, "file missing")

    # ── Check 15: attack_mapping.csv exists and headers correct ───────────
    attack_path = ROOT / "outputs" / "attack_mapping.csv"
    am_ok = attack_path.exists()
    check("15. attack_mapping.csv exists", am_ok)
    if am_ok:
        try:
            with open(attack_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                am_headers = list(reader.fieldnames or [])
                am_rows = list(reader)
            check(
                "16. attack_mapping.csv has correct contract headers",
                am_headers == ATTACK_HEADERS,
                "OK" if am_headers == ATTACK_HEADERS else f"got {am_headers}",
            )
        except Exception as e:
            check("16. attack_mapping.csv has correct contract headers", False, str(e))
            am_rows = []
    else:
        check("16. attack_mapping.csv has correct contract headers", False, "file missing")
        am_rows = []

    # ── Check 17: attack_mapping finding_ids exist in findings ───────────
    findings_ids = {r.get("finding_id", "") for r in findings_rows}
    missing_refs = [r.get("finding_id", "") for r in am_rows if r.get("finding_id", "") not in findings_ids]
    check(
        "17. attack_mapping finding_ids all exist in findings.csv",
        len(missing_refs) == 0,
        f"missing: {missing_refs}" if missing_refs else "",
    )

    # ── Check 18: processed_data.json exists and is valid JSON ────────────
    json_path = ROOT / "outputs" / "processed_data.json"
    json_ok = json_path.exists()
    check("18. processed_data.json exists", json_ok)
    if json_ok:
        try:
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)
            has_keys = "metadata" in data and "findings" in data
            check(
                "19. processed_data.json has required keys (metadata, findings)",
                has_keys,
            )
        except Exception as e:
            check("19. processed_data.json has required keys (metadata, findings)", False, str(e))
    else:
        check("19. processed_data.json has required keys (metadata, findings)", False, "file missing")

    # ── Check 20: ground_truth.csv exists with 6 rows ─────────────────────
    gt_path = ROOT / "data" / "ground_truth.csv"
    gt_ok = gt_path.exists()
    check("20. data/ground_truth.csv exists", gt_ok)
    if gt_ok:
        try:
            with open(gt_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                gt_rows = list(reader)
            check(
                "21. ground_truth.csv has exactly 6 rows (one per EVTX sample)",
                len(gt_rows) == 6,
                f"found {len(gt_rows)} rows",
            )
        except Exception as e:
            check("21. ground_truth.csv has exactly 6 rows", False, str(e))
    else:
        check("21. ground_truth.csv has exactly 6 rows", False, "file missing")

    # ── Check 22: evaluation.json exists and is valid ────────────────────
    eval_json = ROOT / "outputs" / "evaluation.json"
    eval_ok = eval_json.exists()
    check("22. outputs/evaluation.json exists", eval_ok)
    if eval_ok:
        try:
            with open(eval_json, encoding="utf-8") as f:
                eval_data = json.load(f)
            req_keys = {"metadata", "samples", "limitations"}
            has_req = req_keys.issubset(eval_data.keys())
            check(
                "23. evaluation.json has required keys (metadata, samples, limitations)",
                has_req,
                f"missing: {req_keys - eval_data.keys()}" if not has_req else "",
            )
        except Exception as e:
            check("23. evaluation.json has required keys", False, str(e))
    else:
        check("23. evaluation.json has required keys", False, "file missing")

    # ── Check 24: evaluation.csv exists ──────────────────────────────────
    eval_csv = ROOT / "outputs" / "evaluation.csv"
    check("24. outputs/evaluation.csv exists", eval_csv.exists())

    # ── Check 25: attack_navigator_layer.json exists and valid ────────────
    layer_path = ROOT / "outputs" / "attack_navigator_layer.json"
    layer_ok = layer_path.exists()
    check("25. outputs/attack_navigator_layer.json exists", layer_ok)
    if layer_ok:
        try:
            with open(layer_path, encoding="utf-8") as f:
                layer = json.load(f)
            valid_layer = "techniques" in layer and "domain" in layer and "versions" in layer
            check(
                "26. attack_navigator_layer.json has required Navigator keys",
                valid_layer,
            )
        except Exception as e:
            check("26. attack_navigator_layer.json has required Navigator keys", False, str(e))
    else:
        check("26. attack_navigator_layer.json has required Navigator keys", False, "file missing")

    # ── Check 27: timestamps in findings parse as ISO 8601 ────────────────
    iso_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?$")
    bad_ts = [
        r.get("timestamp", "") for r in findings_rows
        if r.get("timestamp", "") and not iso_pattern.match(r.get("timestamp", ""))
    ]
    check(
        "27. All timestamps in findings.csv parse as ISO 8601",
        len(bad_ts) == 0,
        f"invalid: {bad_ts[:3]}" if bad_ts else "",
    )

    # ── Summary ───────────────────────────────────────────────────────────
    print()
    print("=" * 60)
    print(f"Results: {CHECKS_PASSED}/{CHECKS_TOTAL} checks passed")
    if CHECKS_FAILED > 0:
        print(f"FAILED:  {CHECKS_FAILED} checks — see above for details")
    else:
        print("All checks PASSED")
    print("=" * 60)

    sys.exit(0 if CHECKS_FAILED == 0 else 1)


if __name__ == "__main__":
    main()

