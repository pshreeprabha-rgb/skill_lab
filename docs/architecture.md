# System Architecture

**Owner:** Member 1 — Project Lead & Integration Owner  
**Status:** Updated for `feat-improvements` branch  
**Last Updated:** 2026-10-28

---

## Overview

The Windows Threat Hunting System is a six-stage, file-based pipeline that processes Windows Event Log (EVTX) samples through Hayabusa, triage, evidence validation, ATT&CK mapping, and an interactive HTML dashboard. All stages are reproducible from the preserved raw outputs without re-running Hayabusa.

---

## Pipeline Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Stage 1: Data Acquisition                                              │
│  EVTX samples (6 files, public domain CC0)                             │
│  babyshark_sample.evtx  CA_sysmon_sample.evtx  Exec_sysmon_sample.evtx │
│  sysmon_10_11.evtx      sysmon_local_account.evtx  temp_scheduled_task │
└───────────────────────────┬─────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Stage 2: Hayabusa Scan (Hayabusa v4.2.0)                               │
│  Command: hayabusa csv-timeline --directory data/ --min-level low --UTC │
│  Produces:                                                              │
│    outputs/raw/hayabusa_raw_output.csv  ← IMMUTABLE (11 rows, ref)     │
│    outputs/raw/hayabusa_run_log.txt     ← IMMUTABLE (run evidence)     │
│    outputs/raw/hayabusa_real_output.csv ← 94 rows, used for processing │
└───────────────────────────┬─────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Stage 3: Processing  (scripts/process_results.py)                      │
│  Reads: hayabusa_real_output.csv                                        │
│  Produces (four contract CSVs — headers frozen):                        │
│    outputs/shortlist.csv                                                │
│    outputs/findings.csv       ← 8 findings (F-01 to F-08)              │
│    outputs/timeline.csv                                                 │
│    outputs/attack_mapping.csv ← 2 techniques (T1003, T1086)            │
│    outputs/processed_data.json  (dashboard data bundle)                 │
└──────────┬─────────────────────┬───────────────────────────────────────┘
           │                     │
           ▼                     ▼
┌──────────────────┐  ┌────────────────────────────────────────────────────┐
│  Stage 4A:       │  │  Stage 4B: Detection Evaluation                   │
│  Dashboard       │  │  (scripts/evaluate_detection.py)                   │
│  (src/summary.html) │  Reads: data/ground_truth.csv                     │
│                  │  │         outputs/raw/hayabusa_real_output.csv       │
│  HTTP polling    │  │         outputs/attack_mapping.csv                 │
│  every 30 s for  │  │  Produces:                                        │
│  processed_data  │  │    outputs/evaluation.csv                          │
│  .json           │  │    outputs/evaluation.json                         │
│                  │  └────────────────────────────────────────────────────┘
│  Tabs:           │
│  - Findings      │  ┌────────────────────────────────────────────────────┐
│  - Evaluation    │  │  Stage 4C: ATT&CK Navigator Layer Export          │
│                  │  │  (scripts/export_navigator_layer.py)               │
│  Downloads:      │  │  Reads: outputs/attack_mapping.csv                 │
│  - Navigator JSON│  │  Produces: outputs/attack_navigator_layer.json     │
│  - Findings CSV  │  └────────────────────────────────────────────────────┘
└──────────────────┘
                            │
                            ▼ (optional)
┌─────────────────────────────────────────────────────────────────────────┐
│  Stage 4D: AI Report Draft  (scripts/generate_ai_report.py)             │
│  Requires: GEMINI_API_KEY (set in .env, never committed)                │
│  Reads: outputs/findings.csv, outputs/attack_mapping.csv                │
│  Validates: finding refs, technique IDs, numeric claims, status labels  │
│  Produces: outputs/ai_report_accepted.md  OR  outputs/ai_report_        │
│            rejected.md  (never overwrites an accepted report)           │
└─────────────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Stage 5: Report Deliverables                                           │
│    report/final_report.md      ← Human-authored final report           │
│    report/presentation.pptx   ← 6-slide deck (python-pptx)            │
│    report/final_report.pdf    ← BLOCKED (pandoc/weasyprint unavailable)│
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Component Descriptions

### Immutable Evidence Files

| File | Description | Lines |
|---|---|---|
| `outputs/raw/hayabusa_raw_output.csv` | Preserved Hayabusa reference output. Must not be modified. Used by validation checks only. | 11 (header + 10) |
| `outputs/raw/hayabusa_run_log.txt` | Console log from the Hayabusa run. Contains processing time (5.404 s). Must not be modified. | — |

### Contract CSV Files (Headers Frozen)

All four files have frozen column headers. No column may be added, removed, or renamed without explicit team lead approval and a data dictionary update.

| File | Rows | Key Columns |
|---|---|---|
| `outputs/shortlist.csv` | 4 | finding_id, alert_name, source_file |
| `outputs/findings.csv` | 8 | finding_id, status, confidence, techniques |
| `outputs/timeline.csv` | — | timestamp, finding_id, host_label |
| `outputs/attack_mapping.csv` | 2 | finding_id, technique_id, confidence |

### Dashboard (`src/summary.html`)

- Served over HTTP (e.g., `python -m http.server 8080 --directory .`) for live polling to work.
- Polls `outputs/processed_data.json` every 30 seconds via `fetch()`.
- Falls back to an embedded data snapshot if the JSON is unreachable (e.g., opened as a local `file://` URL).
- Tab navigation: **Findings** tab (default) and **Evaluation** tab.
- Status bar shows live/stale state and a pause/resume toggle.
- Download buttons: ATT&CK Navigator layer (JSON) and Findings CSV.
- `processed_data.json` uses `run_timestamp` as the metadata timestamp key (not `generated_at`).

### Detection Evaluation (`scripts/evaluate_detection.py`)

- Compares `data/ground_truth.csv` (6 EVTX samples) against Hayabusa alerts and ATT&CK mappings.
- Matching is performed on technique IDs and keyword heuristics — not a precision/recall benchmark.
- Produces `outputs/evaluation.csv` and `outputs/evaluation.json`.
- Processing time is parsed from `hayabusa_run_log.txt` after stripping ANSI escape codes.
- All six samples are attributed via host name patterns observed in `hayabusa_real_output.csv`.

### ATT&CK Navigator Layer (`scripts/export_navigator_layer.py`)

- Reads `outputs/attack_mapping.csv` and produces a valid ATT&CK Navigator v4.9 / layer v4.5 JSON.
- Technique entries are colored by confidence (red = high, orange = medium, yellow = low).
- Multiple findings for the same technique are merged into a single entry.
- Output: `outputs/attack_navigator_layer.json` — importable at https://mitre-attack.github.io/attack-navigator/

### Optional AI Report (`scripts/generate_ai_report.py`)

- Requires `GEMINI_API_KEY` in environment (via `.env`, which is `.gitignore`d).
- Validates the generated report for: invented finding IDs, unmapped technique IDs, inflated numeric claims, and misused status labels.
- Will not overwrite an existing accepted report.
- No real API call is made in unit tests (all mocked).

### Validation (`scripts/validate_outputs.py`)

Runs 27 deterministic checks across all pipeline outputs. All checks must pass before a commit.

```powershell
python scripts/validate_outputs.py   # exit 0 = all 27 PASS
```

### Unit Tests (`tests/`)

```powershell
python -m unittest discover -s tests -v  # 111 tests, OK (16 skipped)
```

Skipped tests require external infrastructure:
- Selenium + ChromeDriver (browser automation — NOT TESTED)
- `GEMINI_API_KEY` (live Gemini API — NOT TESTED)

---

## Data Flow: Key Identifiers

- **`finding_id`** (format `F-NN`): foreign key across all four contract CSVs and the dashboard.
- **`technique_id`** (MITRE ATT&CK format, e.g., `T1003.001`): used in `attack_mapping.csv`, `evaluation.json`, and `attack_navigator_layer.json`.
- **Semicolon separator** for multiple technique IDs in `ground_truth.csv` `expected_technique_ids` column and in `findings.csv` `techniques` column.

---

## Status Labels (Immutable)

| Label | Meaning |
|---|---|
| `validated_observation` | Evidence directly supports the conclusion |
| `candidate` | Alert fired; evidence reviewed but not fully confirmed |
| `inconclusive` | Insufficient evidence to determine malicious or benign |

These three values are the only allowed values for `status` in `findings.csv`. No other values may be used.

---

## Running the Pipeline

```powershell
# 1. Serve the project over HTTP (required for dashboard live polling)
python -m http.server 8080 --directory .
# Then open: http://localhost:8080/src/summary.html

# 2. Re-run detection evaluation
python scripts/evaluate_detection.py

# 3. Re-export the ATT&CK Navigator layer
python scripts/export_navigator_layer.py

# 4. (Optional) Generate AI report draft
#    First: set GEMINI_API_KEY in .env
python scripts/generate_ai_report.py

# 5. Generate PowerPoint presentation
python scripts/generate_presentation.py

# 6. Run all validation checks
python scripts/validate_outputs.py

# 7. Run all unit tests
python -m unittest discover -s tests -v
```

---

## Branch and Git Conventions

- Active branch: `feat-improvements`
- Branch `feature/improvements` could not be created due to OneDrive filesystem ACL restrictions on subdirectory creation in `.git/refs/heads/`.
- Commits use explicit `git add <path>` — never `git add .` or `git add -A`.
- Protected files are never staged: `outputs/raw/hayabusa_raw_output.csv`, `outputs/raw/hayabusa_run_log.txt`, EVTX files, `.env`.

