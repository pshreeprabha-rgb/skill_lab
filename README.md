# Windows Threat Hunting System Using Hayabusa and MITRE ATT&CK

## Project Overview
A defensive security workflow that uses Hayabusa to scan Windows Event Logs, extract prioritized detections, validate findings against raw event evidence, and defensibly map observations to MITRE ATT&CK techniques.

**Dataset:** Publicly available EVTX samples (EVTX-ATTACK-SAMPLES, CC0) — see `data/README.md`  
**Tool:** Hayabusa v2.18.0  
**Analysis date:** 2026-10-01 (UTC) | **Report date:** 2026-10-28

## Team Roles & Owners
* **Member 1 (Project Lead & Integration Owner)**: Repository structure, schema freeze, final report, demo coordination.
* **Member 2 (Lab Setup & Log Acquisition)**: Authorized dataset, log provenance, `docs/lab_setup.md`, data inventory.
* **Member 3 (Hayabusa Engineer)**: Execution syntax, runbook, raw output preservation, `outputs/shortlist.csv`.
* **Member 4 (Threat Hunter & ATT&CK Mapper)**: Evidence validation, `outputs/findings.csv`, `outputs/timeline.csv`, ATT&CK mappings.
* **Member 5 (Reporting & QA Owner)**: Quality checks, QA checklist, HTML summary dashboard.

## Deliverables Status Tracker
- [x] Repository & contract frozen (Member 1) — `docs/integration-contract.md`
- [x] Lab dataset inventory & provenance documented (Member 2) — `docs/lab_setup.md`, `data/README.md`
- [x] Hayabusa runbook and shortlist exported (Member 3) — `docs/hayabusa_runbook.md`, `outputs/shortlist.csv`
- [x] Findings and timeline validated against evidence (Member 4) — `outputs/findings.csv`, `outputs/timeline.csv`, `outputs/attack_mapping.csv`
- [x] QA verification completed (Member 5) — `report/qa_checklist.md`, `src/summary.html`
- [x] Integrated final report and demo checklist finalized (Member 1) — `report/final_report.md`, `report/demo_checklist.md`

## Key Findings (4 total: 3 Validated Observations, 1 Candidate)

| ID | Technique | Tactic | Confidence |
|---|---|---|---|
| F-01 | T1003.001 — LSASS Memory Dump | Credential Access | Medium |
| F-02 | T1059.001 — PowerShell Encoded Command | Execution | High |
| F-02 | T1027.010 — Command Obfuscation | Defense Evasion | High |
| F-03 | T1136.001 — Local Account Creation | Persistence | Medium (Candidate) |
| F-04 | T1053.005 — Scheduled Task | Persistence | High |

## Quick Start

```powershell
# View the interactive summary dashboard
start src\summary.html

# View the final report
cat report\final_report.md

# View findings data
Import-Csv outputs\findings.csv | Format-Table

# Follow the runbook to reproduce the Hayabusa analysis
cat docs\hayabusa_runbook.md
```

## File Inventory

| Path | Owner | Description |
|---|---|---|
| `docs/integration-contract.md` | M1 | Team rules and schema freeze |
| `docs/lab_setup.md` | M2 | Environment, dataset source, authorization |
| `docs/methodology.md` | M1 | 4-stage threat hunting methodology |
| `docs/data_dictionary.md` | M1 | Column definitions for all CSV outputs |
| `docs/hayabusa_runbook.md` | M3 | Exact commands, version, run record |
| `data/README.md` | M2 | Dataset provenance and authorization |
| `data/sample/` | M2 | Anonymized CSV sample events |
| `outputs/raw/hayabusa_raw_output.csv` | M3 | Preserved Hayabusa output (do not edit) |
| `outputs/shortlist.csv` | M3 | 4 candidate detections selected for review |
| `outputs/findings.csv` | M4 | Validated findings with evidence and confidence |
| `outputs/timeline.csv` | M4 | Chronological event table |
| `outputs/attack_mapping.csv` | M4 | MITRE ATT&CK mappings with rationale |
| `src/summary.html` | M5 | Interactive findings dashboard |
| `report/final_report.md` | M1 | Full integrated investigation report |
| `report/qa_checklist.md` | M5 | QA pass/fail verification checklist |
| `report/demo_checklist.md` | M1 | Live demo script and fallback plan |