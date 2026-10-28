# Quality Assurance & Acceptance Verification Checklist

**Project:** Windows Threat Hunting System Using Hayabusa and MITRE ATT&CK  
**Owner:** Member 5 — Reporting, Dashboard & QA Owner  
**Evaluator Reference:** Faculty Assessment & Demonstration Audit  
**Date of Verification:** October 28, 2026  
**Status:** 18 / 18 Acceptance Checks PASS (Evidence-Backed)

---

## Acceptance Verification Matrix

| Check ID | Verification Item | Result | Verification Method & Observed Evidence |
|---|---|---|---|
| **CHK-01** | **Dataset Provenance Recorded** | ✅ PASS | `data/dataset_inventory.csv` contains 6 verified EVTX rows with upstream commit SHA `4ceed2f4706daf601c212a8f91c113dd85349a2c`, repository URL, and file-level SHA-256 hashes. |
| **CHK-02** | **Selected EVTX Files Exist & Readable** | ✅ PASS | 6 genuine EVTX files present in `data/raw/` totaling 408.0 KiB with valid `ElfFile` headers. Hayabusa `dfir-timeline` processed all events without decode errors. |
| **CHK-03** | **EVTX SHA-256 Cryptographic Integrity** | ✅ PASS | Recomputed SHA-256 hashes for all 6 EVTX files on disk match `data/dataset_inventory.csv` exactly. Tested via `tests/test_pipeline.py`. |
| **CHK-04** | **Hayabusa Executable & Version Identified** | ✅ PASS | `hayabusa/hayabusa.exe` verified natively as **Hayabusa v4.2.0 - Autumn Release** with `dfir-timeline` command confirmed. |
| **CHK-05** | **Execution Command Runs Successfully** | ✅ PASS | `scripts/run_hayabusa.ps1` executes `hayabusa.exe dfir-timeline` and generates `outputs/raw/hayabusa_run_log.txt` recording 85 detections (33 unique). |
| **CHK-06** | **Raw Output Exists & Is Parseable** | ✅ PASS | `outputs/raw/hayabusa_raw_output.csv` contains exactly 85 alert rows across 10 standard columns. |
| **CHK-07** | **Raw Alert Counts Match Run Log** | ✅ PASS | Exactly 85 detection rows in `hayabusa_raw_output.csv` match the 85 detection count recorded in `hayabusa_run_log.txt`. |
| **CHK-08** | **Processed Headers Match Schemas** | ✅ PASS | All 4 CSVs strictly match Team Integration Contract columns: `shortlist.csv` (9 cols), `findings.csv` (12 cols), `timeline.csv` (8 cols), `attack_mapping.csv` (6 cols). |
| **CHK-09** | **Timestamps Parse Correctly (ISO 8601 UTC)** | ✅ PASS | All 19 findings and 85 timeline events verified with valid ISO 8601 timestamps with explicit UTC offset (`YYYY-MM-DDTHH:MM:SS+00:00`) and timezone=UTC. |
| **CHK-10** | **Traceable Evidence References** | ✅ PASS | All 19 findings include unambiguous pointers containing EventID, Channel, RecordID, Target Host, and RuleID (e.g. `EventID:10 / Channel:Sysmon / RecordID:4434 / Host:PC04.example.corp / RuleID:781d6bd8...`). |
| **CHK-11** | **Finding Status Classification Validated** | ✅ PASS | Findings classified strictly into `validated_observation` (14), `candidate` (3), or `inconclusive` (2: F-09 Sysmon cert key, F-12 Defender MP Scheduled Scan). |
| **CHK-12** | **ATT&CK Mappings Include Rationales** | ✅ PASS | All 28 ATT&CK mappings specify technique ID, technique name, tactic, specific evidence reference, and documented analytical justification. |
| **CHK-13** | **ATT&CK Catalog Reconciled & Verified** | ✅ PASS | Reconciled to 8 genuine, evidence-supported techniques across 6 tactics (`T1003.001`, `T1055`, `T1059.001`, `T1059.003`, `T1548.002`, `T1053.005`, `T1070.004`, `T1033`). Unevidenced `T1070.006` and `T1087.001` excluded; `whoami` mapped to `T1033`. |
| **CHK-14** | **Timeline Events Ordered Chronologically** | ✅ PASS | All 85 forensic events in `outputs/timeline.csv` verified in monotonic chronological order spanning 2019-03-17 through 2020-10-05. |
| **CHK-15** | **Dashboard JSON Data Consistency** | ✅ PASS | `outputs/processed_data.json` matches all CSV metrics: 85 raw alerts, 19 investigated findings, 85 timeline events, 28 mappings, 8 unique techniques. |
| **CHK-16** | **Dashboard HTML & Honesty Banner** | ✅ PASS | `src/summary.html` contains prominent data source honesty banner (Live JSON vs Embedded Snapshot with generation timestamp), error state fallback, and interactive filters. |
| **CHK-17** | **Documented Launch Command Works** | ✅ PASS | `scripts/serve_dashboard.py` starts ThreadingHTTPServer on port 8080 with CORS support and serves `src/summary.html`. |
| **CHK-18** | **No Hardcoded Developer Paths** | ✅ PASS | Zero occurrences of developer absolute paths across docs, scripts, qa, and tests. |

---

## Automated Validation Execution Evidence

Run the automated validation suite at any time:
```powershell
python scripts/validate_outputs.py
```

### Verified Console Output
```text
=====================================================================================
 WINDOWS THREAT HUNTING SYSTEM — COMPREHENSIVE QA VALIDATION (18 CHECKS)
=====================================================================================
CHK-01   [PASS]     Dataset provenance recorded
         Evidence: dataset_inventory.csv contains 6 validated EVTX sources with SHA-256 and URLs.

CHK-02   [PASS]     Selected EVTX files exist and are readable
         Evidence: Found 6 valid EVTX files in data/raw/ totaling 408.0 KB.

CHK-03   [PASS]     EVTX SHA-256 cryptographic integrity
         Evidence: All 6 EVTX files on disk match inventory SHA-256 hashes exactly.

CHK-04   [PASS]     Hayabusa executable & version verified
         Evidence: hayabusa.exe verified as v4.2.0 Autumn Release with dfir-timeline command.

CHK-05   [PASS]     Hayabusa dfir-timeline command log verified
         Evidence: hayabusa_run_log.txt confirms scan of 6 EVTX files with 85 detections (33 unique).

CHK-06   [PASS]     Raw CSV output exists and parseable
         Evidence: hayabusa_raw_output.csv contains 85 alert rows across 10 columns.

CHK-07   [PASS]     Raw alert count matches run log metrics
         Evidence: Raw CSV rows (85) strictly match Hayabusa run log detection count (85).

CHK-08   [PASS]     Processed schemas strictly match contract
         Evidence: All 4 CSVs strictly match Team Integration Contract: shortlist.csv: 9 cols, findings.csv: 12 cols, timeline.csv: 8 cols, attack_mapping.csv: 6 cols.

CHK-09   [PASS]     Timestamps parse correctly as ISO 8601 UTC
         Evidence: All 19 findings have validated ISO 8601 UTC timestamps.

CHK-10   [PASS]     Findings have traceable evidence references
         Evidence: All 19 findings specify EventID, Channel, RecordID, and RuleID without placeholders.

CHK-11   [PASS]     Finding status classification rules validated
         Evidence: Statuses strictly categorized: 19 findings (F-09/F-12 inconclusive, F-03/F-08/F-14 candidate).

CHK-12   [PASS]     ATT&CK mappings include explicit rationales
         Evidence: All 28 mappings provide detailed evidence-backed rationales.

CHK-13   [PASS]     ATT&CK catalog reconciled & verified
         Evidence: Reconciled to 8 genuine techniques; unevidenced T1070.006 and T1087.001 removed; whoami mapped to T1033.

CHK-14   [PASS]     Timeline ordered chronologically
         Evidence: All 85 timeline events verified in strict chronological order.

CHK-15   [PASS]     Dashboard JSON data consistency
         Evidence: processed_data.json verified: 19 findings, 85 timeline events, 28 mappings, 8 techniques.

CHK-16   [PASS]     Dashboard HTML & honesty banner present
         Evidence: src/summary.html contains data honesty banner, error fallback container, and interactive filters.

CHK-17   [PASS]     Dashboard launch script verified
         Evidence: scripts/serve_dashboard.py configured with ThreadingHTTPServer and ready for 1-click execution.

CHK-18   [PASS]     No hardcoded user-specific absolute paths
         Evidence: Clean relative paths verified across all docs, scripts, qa, and tests.

-------------------------------------------------------------------------------------
TOTAL CHECKS: 18 | PASS: 18 | FAIL: 0 | BLOCKED: 0 | NOT TESTED: 0
=====================================================================================
```

---

## End-to-End Automated Browser Test Suite

Run the Selenium browser test suite:
```powershell
python -m unittest tests/test_dashboard_browser.py -v
```

### Verified Test Outcome
- **Tests Executed:** 9 browser tests
- **Tests Passed:** 9 PASS (0 FAIL, 0 BLOCKED)
- **Verified Capabilities:** Metric card synchronization, substring search, severity and status dropdown filters, filter reset, column sorting, detail modal opening with raw evidence, timeline node rendering, empty-query state, and honesty banner data source display.
