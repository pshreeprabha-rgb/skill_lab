# Hayabusa Analysis Runbook

**Owner:** Member 3 — Hayabusa Analysis Engineer  
**Status:** Complete & Verified  
**Engine:** Hayabusa v4.2.0 (Autumn Release)  
**Last Updated:** October 28, 2026  

---

## 1. Purpose

This runbook documents the exact commands, environment configurations, and verification steps necessary to execute **Yamato Security Hayabusa v4.2.0** against genuine Windows Event Logs (`.evtx`), preserving raw detection output and run logs.

---

## 2. Tool Information

| Field | Value |
|---|---|
| **Tool Name** | Yamato Security Hayabusa |
| **Version** | v4.2.0 — Autumn Release |
| **Platform** | Windows 10/11 x64 |
| **Official Repository** | https://github.com/Yamato-Security/hayabusa |
| **Documentation** | https://github.com/Yamato-Security/hayabusa/tree/main/docs |
| **Binary Location** | `skill_lab/hayabusa/hayabusa.exe` |
| **Detection Rules** | 4,569 Bundled Rules (Sigma + Hayabusa native rules) |
| **License** | Open Source (GNU GPL v3) |

### Version Verification Command
```powershell
.\hayabusa\hayabusa.exe help
```

---

## 3. Prerequisites & Environment

1. **Operating System:** Windows 10/11 x64 or Windows Server 2019+
2. **Runtime Dependencies:** Microsoft Visual C++ Redistributable (x64)
3. **Hardware:** At least 2 GB free RAM for in-memory timeline correlation
4. **Shell:** Windows PowerShell 5.1+ or PowerShell Core 7+
5. **Permissions:** Standard user or Administrator permissions to read input logs

---

## 4. Input Datasets (`data/raw/`)

The analysis processes six genuine public EVTX files in `data/raw/`:

1. `babyshark_mimikatz_powershell.evtx` (33 events, Sysmon)
2. `CA_sysmon_hashdump_cmd_meterpreter.evtx` (9 events, Sysmon)
3. `Exec_sysmon_meterpreter_reversetcp_msipackage.evtx` (8 events, Sysmon)
4. `sysmon_10_11_lsass_memdump.evtx` (4 events, Sysmon)
5. `temp_scheduled_task_4698_4699.evtx` (2 events, Security)
6. `UACME_59_Sysmon.evtx` (7 events, Sysmon)

*Total: 6 files, 408.0 KiB, 63 raw events.*

---

## 5. Execution Instructions

### Option A: Automated Execution Script (Recommended)
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_hayabusa.ps1
```

### Option B: Manual Command-Line Execution
Run directly from the `skill_lab\` directory:
```powershell
.\hayabusa\hayabusa.exe dfir-timeline `
    --directory "data\raw" `
    --output "outputs\raw\hayabusa_raw_output.csv" `
    --UTC `
    --no-wizard `
    --clobber
```

#### Parameter Explanation
- `-d, --directory "data\raw"`: Path to directory containing target `.evtx` files.
- `-o, --output "outputs\raw\hayabusa_raw_output.csv"`: Path to save detection timeline CSV.
- `-U, --utc`: Formats timestamps as UTC.
- `-w, --no-wizard`: Runs in automated mode without interactive terminal prompts.
- `-C, --clobber`: Overwrites existing output file if present.

### Option C: Preserving Console Run Log
```powershell
& .\hayabusa\hayabusa.exe dfir-timeline -d "data\raw" -o "outputs\raw\hayabusa_raw_output.csv" -U -w -C | Out-File -FilePath "outputs\raw\hayabusa_run_log.txt" -Encoding utf8
```

---

## 6. Observed Execution Results

From genuine execution on October 28, 2026:
- **Elapsed Time:** 2.58 seconds
- **Loaded Rules after Channel Filter:** 4,103 rules
- **Total Detections Generated:** 85 detection alerts (33 unique rules)
- **Data Reduction:** 12 events eliminated (19.05% reduction)
- **Severity Breakdown:**
  - High: 14 alerts (8 unique rules)
  - Medium: 17 alerts (9 unique rules)
  - Low: 36 alerts (9 unique rules)
  - Informational: 18 alerts (7 unique rules)

---

## 7. Troubleshooting & Common Pitfalls

| Issue | Cause | Resolution |
|---|---|---|
| `error: unexpected argument '--version'` | Hayabusa v4.2.0 uses subcommands for help | Run `.\hayabusa.exe help` or `.\hayabusa.exe <COMMAND> -h` |
| `error: unrecognized subcommand 'csv-timeline'` | `csv-timeline` was replaced by `dfir-timeline` in Hayabusa v3/v4 | Use `dfir-timeline` subcommand |
| Output CSV is empty | Incorrect input directory path | Verify that `.evtx` files exist in `data/raw/` using `Get-ChildItem .\data\raw\` |
| Access Denied during git checkout | Antivirus / Windows Defender signature hit on malware-named samples | Use vetted Sysmon logs; avoid downloading active exploit strings directly |
| Output file encoding issues | PowerShell `>` redirects as UTF-16LE | Use `Out-File -Encoding utf8` to ensure compatibility with Python and web dashboard |
