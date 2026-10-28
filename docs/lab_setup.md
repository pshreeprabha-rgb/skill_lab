# Lab Setup & Log Acquisition

**Owner:** Member 2 — Lab Setup & Dataset Acquisition  
**Engine:** Hayabusa v4.2.0 (Autumn Release)  
**Status:** Complete & Verified  
**Last Updated:** October 28, 2026  

---

## 1. Environment Overview

| Parameter | Value |
|---|---|
| **Analysis Platform** | Windows 10/11 x64 (Workstation Environment) |
| **Shell Environment** | Windows PowerShell 5.1 / PowerShell Core 7+ |
| **Python Version** | Python 3.10+ |
| **Analysis Timezone** | UTC (all timestamps normalized to ISO 8601 UTC) |
| **Hayabusa Version** | v4.2.0 (Autumn Release) |
| **Dataset Source** | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (CC0 / Public Domain) |
| **Upstream Commit SHA**| `4ceed2f4706daf601c212a8f91c113dd85349a2c` |

---

## 2. Authorization Statement

> **Authorization & Compliance:** All event logs analyzed in this project are acquired strictly from authorized, publicly accessible digital forensics research repositories. No production logs, personal identification records, or proprietary corporate data are stored or processed. Raw `.evtx` files are excluded from Git version tracking via `.gitignore`.

---

## 3. Hayabusa Setup & Verification

Hayabusa is pre-staged in `skill_lab/hayabusa/`:

```powershell
# 1. Inspect engine help and confirm version
.\hayabusa\hayabusa.exe help

# 2. Inspect dfir-timeline command options
.\hayabusa\hayabusa.exe dfir-timeline -h

# 3. Check rule catalog count (4,569 rules)
.\hayabusa\hayabusa.exe log-metrics -d .\data\raw\ -O
```

---

## 4. Curated Public EVTX Datasets (`data/raw/`)

Six distinct Windows Event Log files demonstrating diverse MITRE ATT&CK tactics were acquired and verified:

| Filename | Source Tactic | Event Channel | SHA-256 Hash | Target Host |
|---|---|---|---|---|
| `babyshark_mimikatz_powershell.evtx` | Credential Access / Execution | Sysmon/Operational | `3747c33a60a32142bf4e30bf023f155b2c0d6e7a018bce8b7bafbd5aa7ec109c` | `IEWIN7` |
| `CA_sysmon_hashdump_cmd_meterpreter.evtx` | Credential Access / Injection | Sysmon/Operational | `897206ca4c3c427753fde880970048494cd5a99be9aaba6154b4e3ac499e24c9` | `IEWIN7` |
| `Exec_sysmon_meterpreter_reversetcp_msipackage.evtx` | Privilege Escalation / Execution | Sysmon/Operational | `328ec1b4b6c531af991a2de2221900ec93db1853f7446f61c7e3c9bf9bf052e3` | `IEWIN7` |
| `sysmon_10_11_lsass_memdump.evtx` | Credential Dumping (ProcDump) | Sysmon/Operational | `915f0859251552b6c33efc32f6184d2c25419c5859852124a7f14ed6ec1a3723` | `PC04.example.corp` |
| `temp_scheduled_task_4698_4699.evtx` | Persistence / Evasion | Security | `a7decf0fbabc340e37de7e7c39fddd5398a7106a4f6acded0ea1d2ffa6bf8b70` | `WIN-77LTAPHIQ1R.example.corp` |
| `UACME_59_Sysmon.evtx` | Privilege Escalation (UAC Bypass) | Sysmon/Operational | `1de3775180143fd5d956bae48f572367534ae8c10f6ffbe98dd4b4e0e47e0fa1` | `LAPTOP-JU4M3I0E` |

---

## 5. Reproducing Dataset Acquisition

To acquire and verify the dataset from GitHub:

```powershell
# Clone upstream repository at pinned revision
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git temp_evtx

# Verify repository commit hash
git -C temp_evtx rev-parse HEAD
# Output: 4ceed2f4706daf601c212a8f91c113dd85349a2c

# Copy selected files into data/raw/
Copy-Item "temp_evtx\Credential Access\sysmon_10_11_lsass_memdump.evtx" -Destination ".\data\raw\"
Copy-Item "temp_evtx\Execution\Exec_sysmon_meterpreter_reversetcp_msipackage.evtx" -Destination ".\data\raw\"
Copy-Item "temp_evtx\Execution\temp_scheduled_task_4698_4699.evtx" -Destination ".\data\raw\"
Copy-Item "temp_evtx\Privilege Escalation\UACME_59_Sysmon.evtx" -Destination ".\data\raw\"
Copy-Item "temp_evtx\Credential Access\CA_sysmon_hashdump_cmd_meterpreter.evtx" -Destination ".\data\raw\"
Copy-Item "temp_evtx\Credential Access\babyshark_mimikatz_powershell.evtx" -Destination ".\data\raw\"

# Compute SHA-256 hashes to confirm byte-for-byte integrity
Get-FileHash -Path .\data\raw\*.evtx -Algorithm SHA256
```
