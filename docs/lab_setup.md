# Lab Setup & Log Acquisition

**Owner:** Member 2 — Lab Setup & Log Acquisition  
**Status:** Complete  
**Last Updated:** 2026-10-28  

---

## 1. Environment Overview

| Parameter | Value |
|---|---|
| Analysis Platform | Windows 10 (22H2) x64 |
| Analysis Hostname | `ANALYST-WS01` (isolated lab VM) |
| Time Zone | UTC (all timestamps normalized to UTC) |
| Hayabusa Version | v2.18.0 |
| Dataset Type | Public sample Windows Event Log data (EVTX) |
| Dataset Source | Hayabusa project test corpus + public EVTX-ATTACK-SAMPLES |

---

## 2. Authorization Statement

> **Authorization:** This investigation uses publicly available, anonymized Windows Event Log sample files distributed by the Hayabusa project (licensed MIT) and the EVTX-ATTACK-SAMPLES repository (public domain / CC0). No production logs, personal data, or logs from systems the team is not authorized to access have been used. Raw EVTX files are stored locally and are **not** committed to the repository (see `.gitignore`).

---

## 3. Hayabusa Installation

### Prerequisites

- Windows 10/11 x64 or Linux (WSL2), or macOS.
- Internet access to download the Hayabusa binary from GitHub Releases.
- Microsoft Visual C++ Redistributable 2015–2022 (x64) — required for the Windows build.

### Installation Steps

```powershell
# Step 1: Download Hayabusa v2.18.0 binary for Windows
Invoke-WebRequest -Uri "https://github.com/Yamato-Security/hayabusa/releases/download/v2.18.0/hayabusa-2.18.0-win-x64.zip" `
    -OutFile "hayabusa-2.18.0-win-x64.zip"

# Step 2: Extract
Expand-Archive -Path "hayabusa-2.18.0-win-x64.zip" -DestinationPath ".\hayabusa\"

# Step 3: Verify version
.\hayabusa\hayabusa.exe --version
# Expected output: hayabusa 2.18.0

# Step 4: Update detection rules (requires internet)
.\hayabusa\hayabusa.exe update-rules
```

### Version Confirmation

```
Tool:    Hayabusa
Version: 2.18.0
Rules:   Updated 2026-10-27 (Sigma-based YAML rules embedded)
Binary:  SHA256: [hash recorded at download]
```

---

## 4. Dataset Acquisition

### Dataset Source

| Field | Value |
|---|---|
| Repository | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES (public) |
| License | CC0 / Public Domain |
| Files Selected | 3 sample EVTX files (see inventory below) |
| Storage Location | `data/sample/` (committed) and `data/` (raw, gitignored) |

### Dataset Inventory

| Filename | Event Log Channel | Approx. Time Coverage | Events | Notes |
|---|---|---|---|---|
| `Security_4688_process_creation.evtx` | Security | Simulated 2026-10-01 00:00–23:59 UTC | ~150 | Process creation events; includes cmd.exe and PowerShell |
| `Security_4698_scheduled_task.evtx` | Security | Simulated 2026-10-01 02:00–08:00 UTC | ~20 | Scheduled task creation events |
| `Microsoft-Windows-Sysmon_10.evtx` | Microsoft-Windows-Sysmon/Operational | Simulated 2026-10-01 01:00–05:00 UTC | ~80 | Sysmon process-access events (lsass.exe) |

> **Note:** Because full EVTX files are excluded from the repository, a synthetic CSV representation of the relevant events is stored in `data/sample/` for reproducibility. The runbook documents how to reproduce from the original EVTX files.

### Data Handling Rules

1. Original EVTX files are kept **read-only** in the local lab environment.
2. Hayabusa output is written to `outputs/raw/` — never back to the data directory.
3. No user-identifiable information is included in committed files.
4. The `data/` directory is git-ignored; only `data/sample/` (anonymized CSV) is committed.

---

## 5. Sanity Checks

```powershell
# Verify EVTX files are readable (run before passing to Member 3)
Get-WinEvent -Path "data\Security_4688_process_creation.evtx" -MaxEvents 5 | Format-List

# Confirm timestamps and time zone
Get-WinEvent -Path "data\Security_4688_process_creation.evtx" -MaxEvents 1 | Select TimeCreated

# Expected: TimeCreated in UTC-equivalent format
```

All 3 EVTX files were confirmed readable and timestamps were consistent with the UTC assumption.

---

## 6. Troubleshooting Notes

| Issue | Resolution |
|---|---|
| `Hayabusa: missing rule files` | Run `.\hayabusa.exe update-rules` first |
| `EVTX file access denied` | Ensure running as Administrator or copy file to a user-writable path |
| `No events found` | Confirm correct `-d` (directory) vs `-f` (single file) flag per Hayabusa v2.x syntax |
| `Timestamp appears in local time` | Add `--UTC` flag to force UTC output in Hayabusa v2.18.0 |

---

## 7. Handoff Notes to Member 3

- Input directory: `data/` (local; EVTX files placed in `data/Security/` and `data/Sysmon/`)
- Working copy path: `data/working_copy/` (separate from originals)
- Analysis start timestamp assumption: **UTC throughout**
- Contact Member 2 if any EVTX file fails to parse — do not silently skip files
