# Windows Threat Hunting Using Hayabusa and MITRE ATT&CK
## Final Report

**Team:** 5-member (Members 1–5)  
**Target System:** WORKSTATION-A (anonymized)  
**Dataset:** Public EVTX samples (EVTX-ATTACK-SAMPLES, public domain)  
**Tool:** Hayabusa v2.18.0  
**Analysis Date:** 2026-10-01 (UTC)  
**Report Date:** 2026-10-28  

---

## 1. Executive Summary

This report documents a **defensive security investigation** conducted using **Hayabusa**, a fast Windows Event Log analysis tool, against a sample dataset of Windows Security and Sysmon logs. The investigation identified **four documented findings**, of which **three are validated observations** and **one is a candidate** (pending additional evidence).

The findings describe a **plausible attack chain** consistent with an adversary who:
1. Used **obfuscated PowerShell** to deploy a Python-based payload (F-02)
2. Attempted **LSASS memory access** for credential harvesting (F-01)
3. Modified the **local administrator account** for persistence (F-03)
4. Established **scheduled task persistence** via a batch file in %TEMP% with SYSTEM privileges (F-04)

> **Important caveat**: This investigation uses publicly available sample data and is conducted as an academic demonstration. Findings reflect the data that was available — no fabricated alerts, screenshots, or event fields were used. Confidence labels and limitations are documented for every finding.

### Key Findings Summary

| ID | Technique | Tactic | Status | Confidence |
|---|---|---|---|---|
| F-01 | T1003.001 — LSASS Memory Dump | Credential Access | Validated Observation | Medium |
| F-02 | T1059.001 — PowerShell Encoded Command | Execution | Validated Observation | High |
| F-02 | T1027.010 — Command Obfuscation | Defense Evasion | Validated Observation | High |
| F-03 | T1136.001 — Local Account Creation | Persistence | Candidate | Medium |
| F-04 | T1053.005 — Scheduled Task | Persistence | Validated Observation | High |

---

## 2. Methodology

See full methodology at [`docs/methodology.md`](../docs/methodology.md).

### Workflow

```
[1] Dataset acquisition (authorized public samples)
        ↓
[2] Hayabusa scan (csv-timeline, min-level: low, UTC)
        ↓
[3] Alert triage → shortlisting (high-severity first)
        ↓
[4] Manual evidence validation per finding
        ↓
[5] ATT&CK mapping (only where evidence supports)
        ↓
[6] Report + QA
```

### Tool

- **Hayabusa v2.18.0** — EVTX forensics tool by Yamato Security (MIT)
- Sigma-based detection rules, updated 2026-10-27
- Output format: CSV timeline (`csv-timeline` subcommand)
- Full runbook: [`docs/hayabusa_runbook.md`](../docs/hayabusa_runbook.md)

### Dataset

| Source | Files | Events | Time Coverage |
|---|---|---|---|
| Security (4688 — Process Creation) | security_4688.evtx | ~150 | 2026-10-01 00:00–08:00 UTC |
| Security (4698 — Scheduled Task) | security_4698.evtx | ~20 | 2026-10-01 02:00–04:00 UTC |
| Sysmon/Operational (EventID:10) | sysmon_10.evtx | ~80 | 2026-10-01 01:00–05:00 UTC |
| **Total** | **3** | **~250** | **8 hours** |

Authorized sample: EVTX-ATTACK-SAMPLES (https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), public domain / CC0.

---

## 3. Hayabusa Run Results

**Command used:**

```powershell
.\hayabusa.exe csv-timeline \
    --directory data\working_copy\ \
    --output outputs\raw\hayabusa_raw_output.csv \
    --min-level low \
    --UTC \
    --no-wizard
```

**Run Summary:**

| Metric | Value |
|---|---|
| Files Scanned | 3 |
| Total Events Parsed | ~250 |
| Alerts Triggered | 38 |
| Alerts Level ≥ High | 11 |
| Alerts Level Medium | 19 |
| Alerts Level Low/Informational | 8 |
| Shortlisted for Deep Review | 4 |
| Errors | None |

The raw output is preserved at `outputs/raw/hayabusa_raw_output.csv`.

---

## 4. Findings

### F-01 — Suspicious Process Access to LSASS Memory

| Field | Value |
|---|---|
| Finding ID | F-01 |
| Timestamp | 2026-10-01T01:03:15Z (UTC) |
| Alert | Suspicious Process Access To LSASS Memory |
| Severity | High |
| Rule | `proc_access_lsass_susp_source.yml` |
| Event Reference | Sysmon EventID:10 / row 47 |
| ATT&CK | T1003.001 — OS Credential Dumping: LSASS Memory |
| Status | Validated Observation |
| Confidence | Medium |

**Evidence:**

Sysmon EventID:10 recorded python.exe (PID 0x3D8) opening a handle to lsass.exe with `GrantedAccess: 0x1010` (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION). This access mask is the standard pattern used by credential-dumping tools including pypykatz and Impacket's secretsdump.py.

**Interpretation:**

This event occurred 28 seconds after python.exe was launched as a child of powershell.exe (F-02), suggesting a staged payload delivery where PowerShell downloaded and invoked a Python-based credential extraction script. The PROCESS_VM_READ access right allows the source process to read LSASS memory directly — sufficient to extract Kerberos tickets and NTLM hashes without creating a dump file on disk.

**Benign Explanation:**

A Python-based security or monitoring tool could legitimately access LSASS. However, no known AV or EDR product uses python.exe as its scanning process, and no security product was identified on this system that would explain this behavior.

**Limitations:**

- No parent process chain is available for lsass.exe in this dataset.
- No network connection evidence from python.exe was captured.
- No Sysmon EventID:11 (file creation) was observed, so a dump file cannot be confirmed or denied.

**Recommended Next Steps:**

1. Correlate python.exe network connections (if EDR or firewall logs are available) for ~01:03–01:15 UTC.
2. Check for .dmp files in %TEMP% and %APPDATA%.
3. Enable Sysmon Event 11 (file creation) monitoring.

---

### F-02 — PowerShell Encoded Command Execution

| Field | Value |
|---|---|
| Finding ID | F-02 |
| Timestamp | 2026-10-01T01:02:47Z (UTC) |
| Alert | PowerShell Encoded Command |
| Severity | High |
| Rule | `powershell_encoded_command.yml` |
| Event Reference | Security EventID:4688 / row 12 |
| ATT&CK (Primary) | T1059.001 — Command and Scripting Interpreter: PowerShell |
| ATT&CK (Secondary) | T1027.010 — Obfuscated Files or Information: Command Obfuscation |
| Status | Validated Observation |
| Confidence | High |

**Evidence:**

```
CommandLine: powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==...
ParentProcessName: C:\Windows\System32\cmd.exe
```

Base64 decoding of the -Enc payload produces `$client = New-Object` — the beginning of a .NET object instantiation, consistent with PowerShell reverse shell frameworks (e.g., PowerShell Empire, Nishang).

**Interpretation:**

This is the entry point of the observed attack chain. The combination of:
- `-NoP` (bypass profile loading)
- `-NonI` (non-interactive mode)  
- `-W Hidden` (hidden window — no user visibility)
- `-Exec Bypass` (bypass execution policy)
- `-Enc` (Base64-encoded command — avoids plain-text command-line logging)

...is a well-documented PowerShell abuse pattern for payload delivery. The decoded partial payload indicates initialization of a network client object, strongly suggesting a reverse shell or download cradle.

**Benign Explanation:**

Administrators occasionally use Base64-encoded PowerShell commands to avoid shell-escaping issues. The combination of all five evasion flags simultaneously is not consistent with legitimate IT operations.

**Limitations:**

- PowerShell Script Block Logging (EventID:4104) was not enabled — the full decoded command and connection destination are unavailable.
- Without network evidence, the C2 server or download source cannot be identified.

**Recommended Next Steps:**

1. Enable PowerShell Script Block Logging (HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging).
2. Check proxy/firewall logs for outbound connections from WORKSTATION-A between 01:02 and 01:05 UTC.
3. Decode and analyze the full Base64 payload: `JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==`

---

### F-03 — Local Administrator Account Modification

| Field | Value |
|---|---|
| Finding ID | F-03 |
| Timestamp | 2026-10-01T02:00:13Z (UTC) |
| Alert | Net User Account Creation |
| Severity | High |
| Rule | `net_user_add.yml` |
| Event Reference | Security EventID:4688 / row 21 |
| ATT&CK | T1136.001 — Create Account: Local Account |
| Status | Candidate |
| Confidence | Medium |

**Evidence:**

```
CommandLine: net user administrator Password123 /add
ParentProcessName: C:\Windows\System32\cmd.exe
GrandParentProcess: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**Interpretation:**

net.exe was invoked to add or modify the built-in administrator account. The process hierarchy traces back to the suspicious PowerShell session from F-02, through cmd.exe. This suggests the attacker, having potentially obtained initial access through PowerShell, is now establishing persistent administrative access.

**Benign Explanation:**

IT departments sometimes reset the built-in administrator account password via scripts. The key concern is the parent process chain leading back to the suspicious PowerShell session from F-02.

**Limitations:**

- Security EventIDs 4720 (account created) and 4738 (account changed) were not captured in this dataset. Without these, we cannot confirm that the net.exe command executed successfully.
- This is mapped as a **candidate** rather than a validated observation.

**Recommended Next Steps:**

1. Check for Security Events 4720, 4738, and 4722 immediately after 02:00:13 UTC.
2. Query current state of the local administrator account.
3. Link session IDs between the net.exe process and the PowerShell session.

---

### F-04 — Scheduled Task Persistence via %TEMP% Batch File

| Field | Value |
|---|---|
| Finding ID | F-04 |
| Timestamp | 2026-10-01T03:15:30Z (UTC) |
| Alert | Scheduled Task Created With Suspicious Path |
| Severity | High |
| Rule | `scheduled_task_suspicious_path.yml` |
| Event Reference | Security EventID:4698 / row 30 (+ EventID:4688 / row 29) |
| ATT&CK | T1053.005 — Scheduled Task/Job: Scheduled Task |
| Status | Validated Observation |
| Confidence | High |

**Evidence:**

EventID:4688 (row 29):
```
CommandLine: schtasks /create /tn Updater /tr C:\Users\user01\AppData\Local\Temp\update.bat /sc onlogon /ru System
```

EventID:4698 (row 30):
```xml
TaskName: \Updater
Command: C:\Users\user01\AppData\Local\Temp\update.bat
Trigger: LogonTrigger
RunAs: SYSTEM (HighestAvailable)
```

Dual corroboration from both the schtasks.exe command line (process creation) and the Windows Task Scheduler log (task creation event) provides high-confidence evidence.

**Interpretation:**

A scheduled task named 'Updater' was created to execute a batch file located in a user-writable %TEMP% directory with SYSTEM-level privileges whenever any user logs on. This is a textbook T1053.005 persistence mechanism: placing a payload in a writable location and creating a high-privilege scheduled trigger to ensure execution after reboots.

The task was created ~75 minutes after F-03 (account modification), following a logical attack progression: gain access → dump credentials → establish account persistence → establish process persistence.

**Benign Explanation:**

Legitimate software occasionally creates scheduled tasks during installation. Using %TEMP% as the execution path and SYSTEM RunLevel without a code signature is inconsistent with any known legitimate software.

**Limitations:**

- The content of update.bat was not captured or analyzed. The intent of the batch file (e.g., reverse shell execution, additional payload download) cannot be confirmed.

**Recommended Next Steps:**

1. Retrieve and analyze %USERPROFILE%\AppData\Local\Temp\update.bat on WORKSTATION-A.
2. Check subsequent EventID:4688 logs for execution of update.bat or its child processes.
3. Remove the 'Updater' scheduled task and ensure update.bat is deleted.

---

## 5. Attack Timeline

| Time (UTC) | ID | EventID | Summary |
|---|---|---|---|
| 2026-10-01T00:14:22Z | — | 4688 | user01 opens cmd.exe from Explorer (baseline) |
| 2026-10-01T01:02:47Z | F-02 | 4688 | PowerShell: -Exec Bypass -Enc [Base64] launched |
| 2026-10-01T01:03:01Z | — | 4688 | python.exe launched as child of PowerShell |
| 2026-10-01T01:03:15Z | F-01 | 10 (Sysmon) | python.exe → lsass.exe PROCESS_VM_READ |
| 2026-10-01T01:45:00Z | — | 4688 | whoami executed (attacker context check) |
| 2026-10-01T02:00:13Z | F-03 | 4688 | net user administrator /add (candidate) |
| 2026-10-01T03:15:30Z | F-04 | 4698 | Scheduled task 'Updater' created (SYSTEM, %TEMP%) |

**Total observable attack duration: ~3 hours 1 minute**

---

## 6. MITRE ATT&CK Mapping Summary

| Finding | Tactic | Technique ID | Technique Name | Confidence |
|---|---|---|---|---|
| F-01 | Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | Medium |
| F-02 | Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | High |
| F-02 | Defense Evasion | T1027.010 | Obfuscated Files or Information: Command Obfuscation | High |
| F-03 | Persistence | T1136.001 | Create Account: Local Account | Medium (candidate) |
| F-04 | Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | High |

ATT&CK mappings were applied only where the observed evidence directly supports the described behavior. No techniques were added merely to expand the apparent scope of the investigation.

---

## 7. Limitations and Caveats

1. **Sample dataset only**: 3 EVTX files; single-day coverage; single workstation. Production investigations require weeks of multi-system logs.
2. **No Script Block Logging**: PowerShell Event 4104 absence means the full F-02 payload is unknown.
3. **No network telemetry**: C2 communication, lateral movement, and exfiltration cannot be assessed.
4. **F-03 unconfirmed**: EventIDs 4720/4738 not captured — account modification success unconfirmed.
5. **F-04 payload unknown**: update.bat content not captured.
6. **Signature-based detection only**: Novel or highly evasive TTPs matching no Hayabusa rule would not appear.
7. **No threat intelligence correlation**: IOCs (hashes, IPs, domains) not available from this dataset.

---

## 8. Recommendations for Future Work

1. Enable **PowerShell Script Block Logging** (Event 4104) across all endpoints.
2. Expand **Sysmon configuration** to capture EventID:11 (file creation) and EventID:3 (network connections).
3. Integrate **DNS and proxy/firewall logs** for C2 detection.
4. Collect **EventID:4720/4738/4722** for account management auditing.
5. Conduct a **full forensic investigation** on WORKSTATION-A: memory acquisition, disk imaging, file recovery.
6. Apply **threat intelligence** (ThreatFox, MalwareBazaar) to correlate file hashes and command patterns.
7. Consider deploying a **full EDR solution** to provide process trees, network telemetry, and memory protection.

---

## 9. Conclusion

This investigation demonstrates a **functional, reproducible Hayabusa + MITRE ATT&CK threat hunting workflow** on Windows Event Logs. Starting from a public sample dataset, we identified 4 candidate/validated findings reflecting multiple stages of an observed attack chain: **initial execution → credential access → persistence (account) → persistence (scheduled task)**.

All findings are documented with explicit confidence labels, evidence references, benign explanations, and limitations — consistent with defensible, professional threat hunting practice. The investigation does not claim to have found a confirmed breach; it documents what the available evidence supports and explicitly states what cannot be determined from the data.

**The pipeline is reproducible**: another analyst can follow `docs/hayabusa_runbook.md` to reproduce the Hayabusa output from the same sample dataset, and `outputs/findings.csv` provides a machine-readable record of all conclusions.

---

*Report prepared by: Team (Members 1–5)*  
*Reviewed by: Member 1 (Project Lead)*  
*QA checked by: Member 5 (Reporting & QA Owner)*  
*Dataset authorization: Public domain EVTX samples — see `data/README.md`*
