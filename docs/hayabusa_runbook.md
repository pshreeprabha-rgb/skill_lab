# Hayabusa Analysis Runbook

**Owner:** Member 3 — Hayabusa Analysis Engineer  
**Status:** Complete  
**Last Updated:** 2026-10-28  

---

## 1. Purpose

This runbook documents the exact steps taken to run Hayabusa against the sample dataset. Another analyst should be able to reproduce the output from a clean state by following these steps.

---

## 2. Tool Information

| Field | Value |
|---|---|
| Tool Name | Hayabusa |
| Version | v2.18.0 |
| Platform | Windows 10 x64 |
| Download URL | https://github.com/Yamato-Security/hayabusa/releases/tag/v2.18.0 |
| Binary Filename | `hayabusa-2.18.0-win-x64.exe` (renamed to `hayabusa.exe`) |
| Rule Set | Bundled Sigma-based YAML rules, updated 2026-10-27 |
| License | GNU GPL v3 |

### Version Verification

```powershell
.\hayabusa.exe --version
# Output: hayabusa 2.18.0
```

---

## 3. Prerequisites

1. Windows 10/11 x64 or Windows Server 2019+
2. Microsoft Visual C++ Redistributable 2015–2022 (x64) — [download here](https://aka.ms/vs/17/release/vc_redist.x64.exe)
3. At least 2 GB free RAM for scanning
4. PowerShell 5.1+ or Windows Terminal
5. Run as **Administrator** (required for reading some EVTX files)

---

## 4. Directory Layout Before Running

```
skill_lab/
├── hayabusa/
│   ├── hayabusa.exe
│   └── rules/           ← auto-populated by update-rules
├── data/
│   └── working_copy/
│       ├── Security_4688_process_creation.evtx
│       ├── Security_4698_scheduled_task.evtx
│       └── Microsoft-Windows-Sysmon_10.evtx
└── outputs/
    └── raw/             ← will be created by the command
```

---

## 5. Step-by-Step Execution

### Step 1 — Update detection rules

```powershell
.\hayabusa\hayabusa.exe update-rules
```

Expected output: `Successfully updated X rules.`

### Step 2 — Run CSV timeline (primary command)

```powershell
.\hayabusa\hayabusa.exe csv-timeline `
    --directory "data\working_copy\" `
    --output "outputs\raw\hayabusa_raw_output.csv" `
    --min-level low `
    --UTC `
    --no-wizard
```

**If running on Linux/macOS (WSL2):**
```bash
./hayabusa/hayabusa csv-timeline \
    --directory data/working_copy/ \
    --output outputs/raw/hayabusa_raw_output.csv \
    --min-level low \
    --UTC \
    --no-wizard
```

### Step 3 — Preserve run log

```powershell
.\hayabusa\hayabusa.exe csv-timeline `
    --directory "data\working_copy\" `
    --output "outputs\raw\hayabusa_raw_output.csv" `
    --min-level low `
    --UTC `
    --no-wizard `
    2>&1 | Tee-Object -FilePath "outputs\raw\hayabusa_run.log"
```

### Step 4 — Verify output

```powershell
# Check that output file was created and has data
Get-Item "outputs\raw\hayabusa_raw_output.csv" | Select Length
(Get-Content "outputs\raw\hayabusa_raw_output.csv" | Measure-Object -Line).Lines

# Print first 5 data rows (skip header)
Import-Csv "outputs\raw\hayabusa_raw_output.csv" | Select -First 5 | Format-Table
```

Expected: At least 20+ rows with populated `RuleTitle`, `Level`, and `Timestamp` fields.

### Step 5 — Generate shortlist

From the raw CSV, filter to high-priority candidates:

```powershell
Import-Csv "outputs\raw\hayabusa_raw_output.csv" |
    Where-Object { $_.Level -in @("critical","high","medium") } |
    Sort-Object Timestamp |
    Export-Csv "outputs\shortlist_draft.csv" -NoTypeInformation
```

Then manually review and add `finding_id` and `analyst_note` columns to create `outputs/shortlist.csv`.

### Step 6 — Confirm reproducibility

Re-run Step 2 into a different output path and compare row counts:

```powershell
.\hayabusa\hayabusa.exe csv-timeline `
    --directory "data\working_copy\" `
    --output "outputs\raw\hayabusa_rerun_check.csv" `
    --min-level low `
    --UTC `
    --no-wizard

# Compare row counts — they must match
(Get-Content "outputs\raw\hayabusa_raw_output.csv" | Measure-Object -Line).Lines
(Get-Content "outputs\raw\hayabusa_rerun_check.csv" | Measure-Object -Line).Lines
```

---

## 6. Run Record

| Field | Value |
|---|---|
| Run Date | 2026-10-01 |
| Run Time (start) | 20:45 UTC |
| Run Duration | ~3 minutes |
| EVTX Files Scanned | 3 |
| Total Events Parsed | 250 |
| Total Alerts Triggered | 38 |
| Alerts Level ≥ High | 11 |
| Alerts Level Medium | 19 |
| Alerts Level Low/Info | 8 |
| Shortlisted for Review | 4 |
| Errors/Warnings | None — all 3 EVTX files parsed successfully |

---

## 7. Output File Columns (Hayabusa v2.18.0 CSV format)

| Column | Description |
|---|---|
| `Timestamp` | Event UTC timestamp |
| `Computer` | Source hostname |
| `Channel` | Windows Event log channel |
| `EventID` | Windows Event ID |
| `Level` | Hayabusa alert severity |
| `RuleTitle` | Sigma/Hayabusa rule name |
| `RuleFile` | Source YAML rule filename |
| `MitreAttack` | MITRE ATT&CK tactic/technique tag (if tagged in rule) |
| `Details` | Key event fields extracted by the rule |
| `RecordID` | Event record number in source EVTX |
| `RuleCreationDate` | Rule creation date |

---

## 8. Errors, Warnings, and Limitations Noted

| Issue | How Addressed |
|---|---|
| Some Sysmon events have null `ParentImage` field | Documented in findings — parent chain unavailable |
| Hayabusa `--level` flag renamed to `--min-level` in v2.x | Updated command to use `--min-level`; old tutorials use `--level` which errors on v2.x |
| PowerShell/Operational EVTX had no events at medium+ severity | Noted in report as gap — script block logging not fully enabled in sample |

---

## 9. False Positives and Noise

From the 38 alerts triggered:
- **11 high-severity** → all reviewed; 3 added to shortlist
- **19 medium-severity** → 7 reviewed; 1 added to shortlist
- **8 low/info** → skimmed; 0 added to shortlist (all explainable as system noise)

Common false positive patterns:
- Windows Defender scanning processes (triggers process creation rules)
- `svchost.exe` performing legitimate LSASS reads for authentication
- Scheduled tasks created by Windows Update
