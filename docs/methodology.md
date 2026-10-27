# Analysis Methodology

**Owner:** Member 1 — Project Lead & Integration Owner  
**Contributes to:** Final report Section 2 (Methodology)  
**Status:** Complete  
**Last Updated:** 2026-10-28

---

## 1. Overview

This project applies a **detection-driven threat hunting workflow** using Hayabusa as the primary tool for automated Windows Event Log triage, followed by manual analyst validation and MITRE ATT&CK mapping.

The workflow has four stages:

```
[1] Data Preparation  →  [2] Automated Detection (Hayabusa)  →  [3] Manual Validation  →  [4] Reporting & Mapping
```

---

## 2. Stage 1: Data Preparation (Member 2)

### 2.1 Dataset Selection

We selected **publicly available Windows Event Log (EVTX) samples** from:
- The Hayabusa project's own test corpus (MIT licensed)
- The `EVTX-ATTACK-SAMPLES` public repository (public domain)

Selection criteria:
- Events cover common attack techniques (credential access, execution, persistence)
- Files are small enough for overnight analysis
- No personal or production data involved

### 2.2 Log Channels Analyzed

| Channel | Event IDs of Interest |
|---|---|
| Security | 4688 (Process creation), 4698 (Scheduled task created), 4624/4625 (Logon) |
| Microsoft-Windows-Sysmon/Operational | 1 (Process create), 10 (Process access), 11 (File create) |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 (Script block logging) |

### 2.3 Timestamp Normalization

All event timestamps are treated as **UTC** throughout the analysis. Where the EVTX source uses local time, the offset is documented in `docs/lab_setup.md`.

---

## 3. Stage 2: Automated Detection — Hayabusa (Member 3)

### 3.1 Tool Choice Rationale

| Property | Value |
|---|---|
| Tool | Hayabusa v2.18.0 |
| Rule set | Built-in + community Sigma rules (updated 2026-10-27) |
| Why Hayabusa | Fast EVTX scanning, MITRE ATT&CK–tagged output, CSV/JSON output, active maintenance |

### 3.2 Core Command

```powershell
.\hayabusa.exe csv-timeline `
    --directory data\working_copy\ `
    --output outputs\raw\hayabusa_raw_output.csv `
    --min-level low `
    --UTC `
    --no-wizard `
    2>&1 | Tee-Object -FilePath outputs\raw\hayabusa_run.log
```

**Flags explained:**
- `csv-timeline`: Produces a time-sorted CSV of all triggered rules
- `--directory`: Scans the entire EVTX directory recursively
- `--min-level low`: Captures all severity levels (we filter later)
- `--UTC`: Forces UTC output (important for timeline accuracy)
- `--no-wizard`: Non-interactive mode

### 3.3 Output Selection

From the raw CSV, candidates were shortlisted by applying the following priority order:
1. Severity ≥ `high` → always included
2. Severity = `medium` + MITRE ATT&CK tactic = `Credential Access` or `Execution` → included
3. All remaining events → reviewed for obvious patterns, otherwise excluded
4. Selection criteria recorded in `outputs/shortlist.csv` (column: `analyst_note`)

---

## 4. Stage 3: Manual Validation (Member 4)

### 4.1 Validation Process

For each candidate alert from the shortlist:

1. **Locate source event**: Identify the exact Event ID, log channel, timestamp, host, and relevant fields (process name, parent process, command line, etc.)
2. **Assess evidence quality**: Does the raw event data support the alert claim?
3. **Consider benign explanations**: Could legitimate software produce the same event?
4. **Assign confidence label**: `candidate` / `validated_observation` / `inconclusive`
5. **Map to ATT&CK** (only if evidence supports the behavior)

### 4.2 Evidence Quality Criteria

| Criterion | Strong Evidence | Weak Evidence |
|---|---|---|
| Source | Known-malicious process name + command-line arguments | Generic process name only |
| Corroboration | Multiple related events (process → network → file) | Single isolated event |
| Uniqueness | Rare on this host / time pattern | Common system activity |
| Context | Clear attacker-controlled path or payload | Ambiguous user action |

### 4.3 Confidence Labels

| Label | Meaning |
|---|---|
| `validated_observation` | Evidence directly and specifically supports the conclusion |
| `candidate` | Alert fired; evidence reviewed, suspicious but not confirmed malicious |
| `inconclusive` | Evidence insufficient; cannot distinguish malicious from benign |

---

## 5. Stage 4: Reporting & QA (Members 1 and 5)

### 5.1 Report Structure

1. Executive Summary
2. Methodology (this document)
3. Dataset Description
4. Findings (one sub-section per finding)
5. Timeline
6. ATT&CK Mapping
7. Limitations & Future Work
8. Appendix: Raw Output, Runbook, QA Checklist

### 5.2 Quality Gate (per work plan Section 6)

- [ ] Commands in runbook match the version of Hayabusa used
- [ ] Dataset source and authorization documented
- [ ] Analysis repeatable from runbook without relying on memory
- [ ] Every finding points to specific event evidence
- [ ] ATT&CK mappings justified by observed behavior
- [ ] Tool output clearly distinguished from analyst interpretation
- [ ] Demo has fallback (screenshots + saved CSV output)
- [ ] Final PDF and slides open correctly

---

## 6. Limitations

- **Sample size**: Three EVTX files covering a simulated single-day scenario. A production investigation would use weeks of logs across multiple systems.
- **No live environment**: We used static sample data; dynamic attacker behavior (e.g., C2 traffic) is not observable.
- **Rule coverage**: Hayabusa's detection rules are signature-based. Novel attacks or living-off-the-land techniques that don't match known patterns will be missed.
- **Confirmation bias**: When analyzing a known-malicious sample, there is a risk of over-interpreting benign events. We mitigated this by explicitly documenting benign explanations.
- **No network telemetry**: Without network logs or EDR data, lateral movement cannot be confirmed.
