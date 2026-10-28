# Threat Hunting System Architecture & Data Flow

**Owner:** Member 1 — Project Lead & Integration Owner  
**Version:** 2.0  
**Status:** Approved & Verified  
**Last Updated:** October 28, 2026  

---

## 1. High-Level System Architecture

The Windows Threat Hunting System transforms heterogeneous binary Windows Event Logs (`.evtx`) into evidence-backed, normalized forensic intelligence mapped to the MITRE ATT&CK framework.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        DATA TIER: LOG ACQUISITION                      │
│                                                                        │
│   EVTX-ATTACK-SAMPLES (CC0 / Public Domain - Commit 4ceed2f)           │
│   ├── babyshark_mimikatz_powershell.evtx  (33 events - IEWIN7)        │
│   ├── CA_sysmon_hashdump_cmd_meterpreter  (9 events - IEWIN7)         │
│   ├── Exec_sysmon_meterpreter_msipackage  (8 events - IEWIN7)         │
│   ├── sysmon_10_11_lsass_memdump.evtx     (4 events - PC04)           │
│   ├── temp_scheduled_task_4698_4699.evtx  (2 events - WIN-77LTAP)     │
│   └── UACME_59_Sysmon.evtx                (7 events - LAPTOP-JU4M)    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      DETECTION & FORENSICS ENGINE                      │
│                                                                        │
│   Yamato Security Hayabusa v4.2.0 (Autumn Release)                     │
│   ├── Execution: scripts/run_hayabusa.ps1                              │
│   ├── Detection Rules: 4,569 Bundled Sigma & Hayabusa Rules            │
│   ├── Channel Filtering: 4,103 Active Rules Applied                   │
│   └── Raw Output Preservation:                                         │
│       ├── outputs/raw/hayabusa_raw_output.csv (85 Raw Alerts)          │
│       └── outputs/raw/hayabusa_run_log.txt    (Execution Log)          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 NORMALIZATION & MITRE ATT&CK CORRELATION               │
│                                                                        │
│   Python ETL & Threat Hunting Pipeline (scripts/process_results.py)    │
│   ├── Timestamp Normalization (ISO 8601 UTC)                           │
│   ├── Event Deduplication & Triage Prioritization                      │
│   ├── Analyst Interpretation & Benign Explanation Generation           │
│   ├── Forensic Limitations & Telemetry Gap Tagging                     │
│   └── MITRE ATT&CK Behavioral Mapping Engine                           │
│       ├── outputs/findings.csv        (19 Investigated Findings)       │
│       ├── outputs/shortlist.csv       (19 Triage Items)                │
│       ├── outputs/timeline.csv        (85 Chronological Events)        │
│       ├── outputs/attack_mapping.csv  (30 Technique Mappings)          │
│       └── outputs/processed_data.json (Unified JSON Schema)            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     PRESENTATION & EVALUATION TIER                     │
│                                                                        │
│   Interactive Analyst SOC Dashboard (src/summary.html)                 │
│   ├── Local CORS Server: scripts/serve_dashboard.py (Port 8080)        │
│   ├── Real-time Multi-Criteria Search & Filtering                      │
│   ├── Interactive Findings Table with Sortable Columns                 │
│   ├── Deep-Dive Traceable Evidence Modal Inspector                     │
│   ├── Chronological Forensic Timeline Component                        │
│   └── MITRE ATT&CK Technique Matrix Coverage                           │
│                                                                        │
│   Automated QA Validation Suite (scripts/validate_outputs.py)          │
│   └── 13/13 Acceptance Checks Validated (PASS)                         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Directory Structure

```text
skill_lab/
├── README.md                           # Main technical documentation
├── requirements.txt                    # Project dependencies
├── .gitignore                          # Excludes raw EVTX binaries
├── data/
│   ├── README.md                       # Provenance & authorization
│   ├── dataset_inventory.csv           # Validated inventory with SHA-256
│   └── raw/                            # 6 Genuine public EVTX files
├── docs/
│   ├── architecture.md                 # System architecture (this file)
│   ├── data_dictionary.md              # Column schemas and data dictionary
│   ├── hayabusa_runbook.md             # Hayabusa execution runbook
│   ├── lab_setup.md                    # Lab environment and setup
│   └── methodology.md                  # 4-stage threat hunting methodology
├── hayabusa/
│   ├── hayabusa.exe                    # Hayabusa v4.2.0 binary
│   ├── config/                         # Engine configuration files
│   └── rules/                          # Bundled Sigma & Hayabusa rules
├── outputs/
│   ├── raw/                            # Preserved unmodified tool outputs
│   ├── findings.csv                    # 19 investigated findings
│   ├── shortlist.csv                   # 19 triage items
│   ├── timeline.csv                    # 85 chronological forensic events
│   ├── attack_mapping.csv              # 30 MITRE ATT&CK mappings
│   └── processed_data.json             # Structured JSON payload
├── scripts/
│   ├── run_hayabusa.ps1                # PowerShell automated runner
│   ├── process_results.py              # Forensic ETL & ATT&CK mapper
│   ├── build_dashboard.py              # Dashboard compiler & fallback injector
│   ├── serve_dashboard.py              # Local HTTP web server
│   └── validate_outputs.py             # Automated QA test suite
├── src/
│   └── summary.html                    # Interactive SOC dashboard
└── report/
    ├── final_report.md                 # Complete evaluation report
    ├── qa_checklist.md                 # 18-point QA verification checklist
    └── demo_checklist.md               # Faculty demonstration walkthrough
```

---

## 3. Data Dictionary & Contract Compliance

Every generated file conforms strictly to the schemas defined in `docs/data_dictionary.md`:
- **`outputs/findings.csv`**: Contains `finding_id`, `timestamp` (ISO 8601 UTC), `timezone`, `alert_name`, `severity`, `status`, `confidence`, `host`, `event_id`, `channel`, `record_id`, `rule_id`, `evidence_reference`, `details`, `interpretation`, `benign_explanation`, `limitation`, `next_step`, `techniques`.
- **`outputs/timeline.csv`**: Strictly sorted monotonically by timestamp.
- **`outputs/attack_mapping.csv`**: Maps observable events to techniques with explicit rationale and confidence ratings.
