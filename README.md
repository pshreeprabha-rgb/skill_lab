# Windows Threat Hunting System Using Hayabusa and MITRE ATT&CK

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![Hayabusa](https://img.shields.io/badge/Hayabusa-v4.2.0_Autumn_Release-orange.svg)](https://github.com/Yamato-Security/hayabusa)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-v14.1-red.svg)](https://attack.mitre.org/)
[![QA Tests](https://img.shields.io/badge/QA_Validation-13%2F13_PASS-brightgreen.svg)](#qa-validation--testing)

## Project Overview

A robust, reproducible, evidence-based Windows Threat Hunting pipeline designed for college cybersecurity defense evaluation. The system processes genuine Windows Event Logs (`.evtx`), executes **Yamato Security Hayabusa v4.2.0** against curated Sigma/Hayabusa detection rules, preserves unmodified forensic output, normalizes forensic artifacts via an automated Python pipeline, and defensibly maps observed attacker behaviors to the **MITRE ATT&CK** knowledge base.

- **Analyzed Logs:** 6 Genuine Windows EVTX datasets from public research repositories (63 raw events, 408 KB).
- **Detection Engine:** Hayabusa v4.2.0 (Autumn Release) with 4,569 detection rules (4,103 active post-channel filter).
- **Execution Results:** 85 raw detection hits (14 High, 17 Medium, 36 Low, 18 Informational) across 4 target hosts.
- **Investigated Findings:** 19 prioritized findings (12 Validated Observations, 7 Candidate Findings).
- **ATT&CK Coverage:** 30 mapping entries across 9 distinct adversary techniques and 7 tactics.
- **Interactive Dashboard:** Modern dark SOC web application (`src/summary.html`) with real-time filtering, search, column sorting, modal detail inspections, forensic timeline, and dataset provenance tables.

---

## Architecture & Data Flow

```text
Genuine Public EVTX Files (data/raw/*.evtx)
                   │
                   ▼
  Hayabusa v4.2.0 Execution (scripts/run_hayabusa.ps1)
                   │
                   ▼
  Raw Tool Detection Output (outputs/raw/hayabusa_raw_output.csv & run log)
                   │
                   ▼
  Python Processing & Normalization (scripts/process_results.py)
   ├── outputs/findings.csv        (19 investigated findings)
   ├── outputs/shortlist.csv       (19 alert triage items)
   ├── outputs/timeline.csv        (85 chronological forensic events)
   ├── outputs/attack_mapping.csv  (30 evidence-backed ATT&CK links)
   └── outputs/processed_data.json (unified JSON payload)
                   │
                   ▼
  Automated QA Validation Suite (scripts/validate_outputs.py)
                   │
                   ▼
  Interactive SOC Dashboard & Demonstration (scripts/serve_dashboard.py)
```

---

## 5-Member Team Responsibilities

| Role | Member | Core Responsibilities | Key Handoff Deliverables |
|---|---|---|---|
| **Member 1** | **Project Lead & Integration Owner** | Architecture, schema freeze, final integration, final report, demo coordination. | `report/final_report.md`, `README.md`, `docs/data_dictionary.md` |
| **Member 2** | **Lab Setup & Dataset Acquisition** | Public EVTX collection, file verification, hashes, authorization documentation. | `data/dataset_inventory.csv`, `data/README.md`, `docs/lab_setup.md` |
| **Member 3** | **Hayabusa Analysis Engineer** | Hayabusa executable verification, automation script, raw output preservation. | `scripts/run_hayabusa.ps1`, `outputs/raw/`, `docs/hayabusa_runbook.md` |
| **Member 4** | **Threat Hunter & ATT&CK Mapper** | Alert investigation, timeline reconstruction, evidence linking, MITRE mapping. | `scripts/process_results.py`, `outputs/findings.csv`, `outputs/attack_mapping.csv` |
| **Member 5** | **Dashboard Developer & QA Owner** | Interactive dashboard, QA validation suite, automated testing, browser verification. | `src/summary.html`, `scripts/serve_dashboard.py`, `scripts/validate_outputs.py` |

---

## Dataset Inventory (Genuine EVTX Samples)

All datasets are derived from the public repository [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (Commit `4ceed2f4706daf601c212a8f91c113dd85349a2c`):

| ID | Filename | Target Host | Events | Channel | Scenario / Attack Pattern |
|---|---|---|---|---|---|
| **D1** | `babyshark_mimikatz_powershell.evtx` | `IEWIN7` | 33 | Sysmon | BabyShark campaign: PowerShell LSASS credential access (`T1059.001`, `T1003.001`) |
| **D2** | `CA_sysmon_hashdump_cmd_meterpreter.evtx` | `IEWIN7` | 9 | Sysmon | Meterpreter hashdump & LSASS remote thread injection (`T1003.001`, `T1055`) |
| **D3** | `Exec_sysmon_meterpreter_reversetcp_msipackage.evtx` | `IEWIN7` | 8 | Sysmon | AlwaysInstallElevated MSI installer execution spawning shells (`T1548.002`, `T1059.003`) |
| **D4** | `sysmon_10_11_lsass_memdump.evtx` | `PC04.example.corp` | 4 | Sysmon | ProcDump & Task Manager LSASS memory dump file creation (`T1003.001`) |
| **D5** | `temp_scheduled_task_4698_4699.evtx` | `WIN-77LTAPHIQ1R.example.corp` | 2 | Security | Ephemeral scheduled task creation & rapid deletion for evasion (`T1053.005`, `T1070.004`) |
| **D6** | `UACME_59_Sysmon.evtx` | `LAPTOP-JU4M3I0E` | 7 | Sysmon | UAC bypass (UACME 59) abusing auto-elevated Taskmgr (`T1548.002`) |

---

## Quickstart & Reproduction Commands

### 1. Execute Hayabusa Analysis
```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_hayabusa.ps1
```
*Scans all 6 genuine EVTX files in `data/raw/`, outputs `outputs/raw/hayabusa_raw_output.csv` (85 alerts), and writes `outputs/raw/hayabusa_run_log.txt`.*

### 2. Process Findings, Timeline, and ATT&CK Mappings
```bash
python scripts/process_results.py
```
*Parses raw detections, builds 19 investigated findings, sorts 85 timeline events, maps 30 MITRE techniques, generates `outputs/processed_data.json`, and updates `src/summary.html`.*

### 3. Run Automated QA Validation Suite
```bash
python scripts/validate_outputs.py
```
*Validates hashes, schemas, timestamp formats, evidence traces, and data integrity (13/13 checks PASS).*

### 4. Launch Interactive Web Dashboard
```bash
python scripts/serve_dashboard.py
```
*Starts local HTTP server on `http://localhost:8080/src/summary.html` with full dynamic search, filters, modal detail view, timeline, and ATT&CK matrices.*

---

## Repository Structure

```text
skill_lab/
├── README.md                           # Main project documentation and quickstart
├── requirements.txt                    # Minimal Python dependencies
├── .gitignore                          # Excludes raw EVTX binaries and temporary artifacts
├── data/
│   ├── README.md                       # Dataset provenance and authorization notes
│   ├── dataset_inventory.csv           # Validated inventory with SHA-256 hashes and channels
│   └── raw/                            # 6 genuine public EVTX log files
├── docs/
│   ├── data_dictionary.md              # Column schemas and data dictionary
│   ├── hayabusa_runbook.md             # Execution runbook and command references
│   ├── lab_setup.md                    # Lab environment and prerequisites
│   ├── methodology.md                  # 4-stage threat hunting methodology
│   └── architecture.md                 # System architecture and data flow diagram
├── hayabusa/
│   ├── hayabusa.exe                    # Verified Hayabusa v4.2.0 binary (Yamato Security)
│   ├── config/                         # Engine configuration files
│   └── rules/                          # Bundled Sigma & Hayabusa detection rules
├── outputs/
│   ├── raw/
│   │   ├── hayabusa_raw_output.csv     # Unmodified Hayabusa detection output (85 alerts)
│   │   └── hayabusa_run_log.txt        # Preserved console execution log with metrics
│   ├── findings.csv                    # 19 investigated findings with evidence and rationale
│   ├── shortlist.csv                   # 19 prioritized triage items
│   ├── timeline.csv                    # 85 chronological forensic events
│   ├── attack_mapping.csv              # 30 evidence-backed MITRE ATT&CK mappings
│   └── processed_data.json             # Structured JSON payload for the dashboard
├── scripts/
│   ├── run_hayabusa.ps1                # PowerShell automated execution script
│   ├── process_results.py              # Data processing and ATT&CK mapping pipeline
│   ├── build_dashboard.py              # HTML compilation and offline data injector
│   ├── serve_dashboard.py              # Local HTTP dashboard server (CORS-enabled)
│   └── validate_outputs.py             # Automated QA validation suite (13 checks)
├── src/
│   └── summary.html                    # Genuinely interactive SOC investigation dashboard
└── report/
    ├── final_report.md                 # Complete academic cybersecurity investigation report
    ├── qa_checklist.md                 # 18-point QA verification checklist
    └── demo_checklist.md               # Faculty evaluator demonstration script
```

---

## Key Findings Highlight

1. **F-01 to F-05: LSASS Process Memory Dumping (`T1003.001`)**
   - Host: `PC04.example.corp` (Sysmon EventID 10, 11)
   - Evidence: `procdump.exe` opened `lsass.exe` with `0x1fffff` (full access rights) and created `lsass.exe_190317_120941.dmp` on Desktop. Task Manager was also used to write `lsass (2).DMP` to `%TEMP%`.
2. **F-07 & F-10: PowerShell Credential Access & Thread Injection (`T1059.001`, `T1003.001`, `T1055`)**
   - Host: `IEWIN7` (Sysmon EventID 8, 10)
   - Evidence: `powershell.exe` opened `lsass.exe` with `PROCESS_VM_READ` (0x1010). Remote thread injected into LSASS by `\\VBOXSVR\HTools\voice_mail.msg.exe` at `0x001A0000`.
3. **F-12 & F-13: AlwaysInstallElevated MSI Privilege Escalation (`T1548.002`, `T1059.003`)**
   - Host: `IEWIN7` (Sysmon EventID 1)
   - Evidence: Windows Installer executed `C:\Windows\Installer\MSI4FFD.tmp` with High integrity, spawning `cmd.exe` and `whoami.exe`.
4. **F-16 & F-17: Ephemeral Scheduled Task Persistence (`T1053.005`, `T1070.004`)**
   - Host: `WIN-77LTAPHIQ1R.example.corp` (Security EventID 4698, 4699)
   - Evidence: Scheduled task was created and immediately deleted within 32 milliseconds, demonstrating defense evasion.

---

## QA Validation & Testing

Run `python scripts/validate_outputs.py` to verify system integrity:
- **Dataset Integrity:** All 6 EVTX files present and hashes verified against `dataset_inventory.csv`.
- **Tool Execution:** Verified execution of `hayabusa.exe v4.2.0` with non-empty raw output (85 alerts).
- **Schema Compliance:** All CSV output headers conform strictly to `docs/data_dictionary.md`.
- **Timestamp Ordering:** All 85 timeline entries confirmed in strict chronological sequence.
- **Traceability:** 100% of findings include verifiable EventID, Channel, RecordID, and RuleID.
- **Interactive Testing:** Verified via headless browser automation (search, severity filter, detail modal, timeline, ATT&CK matrix).