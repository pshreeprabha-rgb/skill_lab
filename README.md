# Windows Threat Hunting System Using Hayabusa and MITRE ATT&CK

## Project Overview

A defensive security workflow that uses Hayabusa to scan Windows Event Logs, extract prioritized detections, validate findings against raw event evidence, and defensibly map observations to MITRE ATT&CK techniques.

**Dataset:** Publicly available EVTX samples (EVTX-ATTACK-SAMPLES, CC0) -- see `data/README.md`  
**Tool:** Hayabusa v4.2.0  
**Analysis date:** 2026-10-01 (UTC) | **Report date:** 2026-10-28  
**Active branch:** `feat-improvements`

## Team Roles & Owners

- **Member 1 (Project Lead & Integration Owner)**: Repository structure, schema freeze, final report, demo coordination.
- **Member 2 (Lab Setup & Log Acquisition)**: Authorized dataset, log provenance, `docs/lab_setup.md`, data inventory.
- **Member 3 (Hayabusa Engineer)**: Execution syntax, runbook, raw output preservation, `outputs/shortlist.csv`.
- **Member 4 (Threat Hunter & ATT&CK Mapper)**: Evidence validation, `outputs/findings.csv`, `outputs/timeline.csv`, ATT&CK mappings.
- **Member 5 (Reporting & QA Owner)**: Quality checks, QA checklist, HTML summary dashboard.

## Deliverables Status Tracker

- [x] Repository & contract frozen (Member 1) -- `docs/integration-contract.md`
- [x] Lab dataset inventory & provenance documented (Member 2) -- `docs/lab_setup.md`, `data/README.md`
- [x] Hayabusa runbook and shortlist exported (Member 3) -- `docs/hayabusa_runbook.md`, `outputs/shortlist.csv`
- [x] Findings and timeline validated against evidence (Member 4) -- `outputs/findings.csv`, `outputs/timeline.csv`, `outputs/attack_mapping.csv`
- [x] QA verification completed (Member 5) -- `report/qa_checklist.md`, `src/summary.html`
- [x] Integrated final report and demo checklist finalized (Member 1) -- `report/final_report.md`, `report/demo_checklist.md`
- [x] Detection evaluation script and ground truth (feat-improvements) -- `scripts/evaluate_detection.py`, `data/ground_truth.csv`
- [x] Live dashboard refresh with Evaluation tab (feat-improvements) -- `src/summary.html`
- [x] ATT&CK Navigator layer export (feat-improvements) -- `scripts/export_navigator_layer.py`, `outputs/attack_navigator_layer.json`
- [x] Optional Gemini AI report draft (feat-improvements) -- `scripts/generate_ai_report.py`
- [x] PowerPoint presentation (feat-improvements) -- `report/presentation.pptx`
- [x] 27-check validation script (feat-improvements) -- `scripts/validate_outputs.py`
- [x] 111 unit tests (feat-improvements) -- `tests/`

## Key Findings (8 total: findings F-01 to F-08)

| ID | Technique | Tactic | Confidence |
|---|---|---|---|
| F-01 | T1003.001 - LSASS Memory Dump | Credential Access | Medium |
| F-02 | T1059.001 - PowerShell Encoded Command | Execution | High |
| F-03 | T1053.005 - Scheduled Task | Persistence | High |
| F-04 through F-08 | Various | Various | See findings.csv |

Full mapping table: `outputs/attack_mapping.csv` | Technique IDs: T1003.001, T1086

## Quick Start

```powershell
# Serve over HTTP for live dashboard polling
python -m http.server 8080 --directory .
# Then open: http://localhost:8080/src/summary.html

# View findings data
Import-Csv outputs\findings.csv | Format-Table

# Re-run detection evaluation
python scripts/evaluate_detection.py

# Export ATT&CK Navigator layer
python scripts/export_navigator_layer.py

# Run all 27 validation checks
python scripts/validate_outputs.py

# Run all 111 unit tests
python -m unittest discover -s tests -v

# Generate PowerPoint presentation
python scripts/generate_presentation.py

# (Optional) Generate AI report draft -- requires GEMINI_API_KEY in .env
python scripts/generate_ai_report.py
```

> **Dashboard note:** The live-refresh polling requires the dashboard to be served over HTTP.
> If opened directly as a `file://` URL, it falls back to an embedded data snapshot automatically.

## Dashboard Features (feat-improvements)

- **Live refresh**: Polls `outputs/processed_data.json` every 30 seconds
- **Pause/Resume toggle**: Stop polling without reloading the page
- **Stale data warning**: Banner appears if data is more than 5 minutes old
- **Evaluation tab**: Shows per-sample detection results (6/6 hits)
- **Downloads**: ATT&CK Navigator layer (JSON) and Findings CSV

## Detection Evaluation Summary

| Metric | Value |
|---|---|
| Samples evaluated | 6 |
| Samples with relevant alert (hits) | 6 |
| Samples missed | 0 |
| Processing time (from run log) | 5.404 s |
| Evaluation basis | Technique ID + keyword matching |

> **Limitation:** Matching uses heuristics, not a precision/recall benchmark. Six samples with no benign baseline do not constitute a representative evaluation.

## Running the Validation Suite

```powershell
# All 27 checks must pass before any commit
python scripts/validate_outputs.py

# All 111 tests must pass (16 are skipped -- Selenium and live Gemini API)
python -m unittest discover -s tests -v
```

## Optional: AI Report (requires Gemini API key)

```powershell
# Copy .env.example to .env and fill in your key
Copy-Item .env.example .env
# Edit .env: set GEMINI_API_KEY=<your-key>
python scripts/generate_ai_report.py
```

The script validates the generated report for invented finding IDs, unmapped techniques, inflated numeric claims, and misused status labels before saving.

## File Inventory

| Path | Owner | Description |
|---|---|---|
| `docs/integration-contract.md` | M1 | Team rules and schema freeze |
| `docs/lab_setup.md` | M2 | Environment, dataset source, authorization |
| `docs/methodology.md` | M1 | 4-stage threat hunting methodology |
| `docs/data_dictionary.md` | M1 | Column definitions for all CSV outputs |
| `docs/architecture.md` | M1 | Full pipeline architecture diagram |
| `docs/hayabusa_runbook.md` | M3 | Exact commands, version, run record |
| `data/README.md` | M2 | Dataset provenance and authorization |
| `data/ground_truth.csv` | M1 | 6-sample ground truth for detection evaluation |
| `data/sample/` | M2 | Anonymized CSV sample events |
| `outputs/raw/hayabusa_raw_output.csv` | M3 | Preserved Hayabusa output (IMMUTABLE -- do not edit) |
| `outputs/raw/hayabusa_run_log.txt` | M3 | Hayabusa console log (IMMUTABLE -- do not edit) |
| `outputs/shortlist.csv` | M3 | Candidate detections selected for review |
| `outputs/findings.csv` | M4 | Validated findings with evidence and confidence |
| `outputs/timeline.csv` | M4 | Chronological event table |
| `outputs/attack_mapping.csv` | M4 | MITRE ATT&CK mappings with rationale |
| `outputs/evaluation.csv` | M1 | Per-sample detection evaluation results |
| `outputs/evaluation.json` | M1 | Evaluation metadata, samples, and limitations |
| `outputs/attack_navigator_layer.json` | M1 | ATT&CK Navigator v4.9 layer (importable) |
| `scripts/validate_outputs.py` | M1 | 27-check pipeline validation script |
| `scripts/evaluate_detection.py` | M1 | Detection evaluation against ground truth |
| `scripts/export_navigator_layer.py` | M1 | ATT&CK Navigator layer export |
| `scripts/generate_ai_report.py` | M1 | Optional Gemini AI report draft generator |
| `scripts/generate_presentation.py` | M5 | PowerPoint presentation generator |
| `src/summary.html` | M5 | Interactive findings dashboard |
| `report/final_report.md` | M1 | Full integrated investigation report |
| `report/presentation.pptx` | M5 | 6-slide presentation (DRAFT -- requires human editing) |
| `report/qa_checklist.md` | M5 | QA pass/fail verification checklist |
| `report/demo_checklist.md` | M1 | Live demo script and fallback plan |
| `tests/` | M1 | 111 unit tests across all scripts |
| `.env.example` | M1 | Template for GEMINI_API_KEY (do not commit .env) |

## Blocked / Not Tested

| Item | Status | Reason | Manual Action |
|---|---|---|---|
| Branch `feature/improvements` | BLOCKED | OneDrive ACL denies `/` in ref names | Using `feat-improvements` instead |
| Selenium browser tests | NOT TESTED | ChromeDriver not installed | `pip install selenium webdriver-manager` |
| Live Gemini API | NOT TESTED | GEMINI_API_KEY not configured | Set key in `.env`, run `generate_ai_report.py` |
| PDF export | BLOCKED | `pandoc` and `weasyprint` not installed | Install pandoc from https://pandoc.org/installing.html |
