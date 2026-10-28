# Threat Hunting System Demonstration Script & Evaluator Checklist

**Project:** Windows Threat Hunting System Using Hayabusa and MITRE ATT&CK  
**Audience:** Faculty Evaluator & Examination Committee  
**Target Duration:** 8 to 10 Minutes Total  
**Demonstration Mode:** Live Interactive Execution (with Verified Offline Fallback)

---

## 1. Pre-Demonstration Setup Checklist

Complete 15 minutes before presentation:
- [ ] Ensure PowerShell terminal is open in repository root: `skill_lab\`
- [ ] Confirm Python 3.8+ and PowerShell execution policy are available: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
- [ ] Launch the local dashboard web server:
  ```powershell
  python scripts/serve_dashboard.py
  ```
- [ ] Open the browser to `http://localhost:8080/src/summary.html`
- [ ] Have VS Code or Markdown reader open to `report/final_report.md`

---

## 2. Step-by-Step Demonstration Walkthrough

### Step 1: Open Project & Architecture Overview (1 Minute — Member 1)
- **Action:** Open terminal in `skill_lab\` and display the repository structure.
- **Presenter Script:**
  > "Good morning evaluators. Our project implements an end-to-end Windows Threat Hunting pipeline. Rather than analyzing simulated or fabricated logs, we built a fully reproducible pipeline using genuine Windows Event Log (`.evtx`) samples, Yamato Security Hayabusa v4.2.0, automated Python artifact normalization, defensible MITRE ATT&CK mappings, and an interactive SOC analyst dashboard."
- **Reference:** Point to `README.md` and `docs/architecture.md`.

---

### Step 2: Selected EVTX Datasets & Provenance (1 Minute — Member 2)
- **Action:** Display `data/dataset_inventory.csv` and show files in `data/raw/`.
- **Command:**
  ```powershell
  Get-ChildItem -Path .\data\raw\*.evtx | Select-Object Name, Length
  ```
- **Presenter Script:**
  > "Member 2 acquired six genuine public EVTX datasets from the recognized EVTX-ATTACK-SAMPLES repository (Head commit `4ceed2f4706daf601c212a8f91c113dd85349a2c`). Each file has an independently verified SHA-256 hash. These files demonstrate distinct attack patterns across four target hosts: `IEWIN7`, `PC04.example.corp`, `WIN-77LTAPHIQ1R.example.corp`, and `LAPTOP-JU4M3I0E`."
- **Reference:** Show `data/dataset_inventory.csv` with file sizes (68 KB each, totaling 408 KB) and hashes.

---

### Step 3: Verify Hayabusa Version & Engine (45 Seconds — Member 3)
- **Action:** Verify Hayabusa version and help commands natively.
- **Command:**
  ```powershell
  .\hayabusa\hayabusa.exe help
  ```
- **Presenter Script:**
  > "Member 3 verified our detection engine: Yamato Security Hayabusa v4.2.0 (Autumn Release). Hayabusa is bundled with 4,569 detection rules combining Sigma community rules and native Hayabusa rules. After applying Hayabusa's native channel filter, 4,103 rules are actively evaluated against our loaded EVTX logs."

---

### Step 4: Live Execution of Hayabusa Pipeline (1 Minute — Member 3)
- **Action:** Run the automated PowerShell execution script.
- **Command:**
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\run_hayabusa.ps1
  ```
- **Observed Result:**
  - Scans all 6 EVTX files in `data/raw/`
  - Completes in ~2.5 seconds
  - Generates `outputs/raw/hayabusa_raw_output.csv` (85 detections)
  - Saves run metrics in `outputs/raw/hayabusa_run_log.txt`
- **Presenter Script:**
  > "Execution completes in under 3 seconds. The raw detection output is preserved unmodified in `outputs/raw/` to ensure strict forensic chain-of-custody."

---

### Step 5: Review Raw Detection Output & Metrics (1 Minute — Member 3)
- **Action:** Display the preserved run log and raw output count.
- **Command:**
  ```powershell
  Get-Content .\outputs\raw\hayabusa_run_log.txt | Select-Object -Last 35
  ```
- **Presenter Script:**
  > "The raw engine identified 85 detection alerts across 33 unique rules: 14 High alerts, 17 Medium alerts, 36 Low alerts, and 18 Informational alerts. Data reduction achieved was 19.05%."

---

### Step 6: Process Data & Explain Genuine Findings (2.5 Minutes — Member 4)
- **Action:** Run data processing and open findings table.
- **Command:**
  ```powershell
  python scripts/process_results.py
  ```
- **Presenter Script:**
  > "Our Python pipeline normalized timestamps to ISO 8601 UTC, deduplicated recurring engine hits, and promoted 19 investigated findings. Let us highlight two core attack findings with indisputable forensic evidence:"
  1. **Finding F-01 & F-02 (Credential Access on PC04.example.corp):**
     - *Evidence:* `procdump.exe` opened `lsass.exe` with `0x1fffff` (`PROCESS_ALL_ACCESS`) and wrote `lsass.exe_190317_120941.dmp` directly to the Desktop (Sysmon Event ID 10 & 11). Task Manager also dumped `lsass (2).DMP` to `%TEMP%`.
     - *ATT&CK Mapping:* **T1003.001 (OS Credential Dumping: LSASS Memory)**.
  2. **Finding F-10 (Remote Thread Injection on IEWIN7):**
     - *Evidence:* Masqueraded process `\\VBOXSVR\HTools\voice_mail.msg.exe` injected a remote thread into `lsass.exe` at address `0x001A0000` (Sysmon Event ID 8).
     - *ATT&CK Mapping:* **T1055 (Process Injection)** and **T1003.001 (LSASS Memory)**.
  3. **Finding F-13 (AlwaysInstallElevated Abuse on IEWIN7):**
     - *Evidence:* MSI Installer spawned `MSI4FFD.tmp` with High integrity, which spawned `cmd.exe` and `whoami.exe` (Sysmon Event ID 1).
     - *ATT&CK Mapping:* **T1548.002 (Bypass UAC)** and **T1059.003 (Command Shell)**.

---

### Step 7: MITRE ATT&CK Mapping Defense (1 Minute — Member 4)
- **Action:** Show `outputs/attack_mapping.csv` or Dashboard ATT&CK tab.
- **Presenter Script:**
  > "Every mapping has an explicit documented rationale. We do not map techniques solely because an Event ID occurred. For example, Event ID 10 is only mapped to T1003.001 when the TargetImage is `lsass.exe` and the access mask grants memory read rights (`0x1fffff` or `0x1010`). We also distinguish between Validated Observations (High Confidence) and Candidate Findings (Medium Confidence)."

---

### Step 8: Live Dashboard Demonstration (2 Minutes — Member 5)
- **Action:** Switch to browser window showing `http://localhost:8080/src/summary.html`.
- **Demonstration Steps:**
  1. **Search Test:** Type `"LSASS"` into the search bar. Show how the table filters instantly from 19 findings down to 9 LSASS findings.
  2. **Reset Filter:** Click `"Reset Filters"` to show all findings restore.
  3. **Severity Filter:** Select `"High"` from dropdown. Show the 8 High-severity findings.
  4. **Modal Detail View:** Click `"View Evidence"` on `F-01`. Walk through the popup modal displaying:
     - Target Host & Timestamp
     - Event ID 11 / Sysmon / RecordID 4433
     - Raw details string
     - Forensic analyst interpretation
     - Benign explanation (crash troubleshooting)
     - Telemetry gaps & recommended next steps
  5. **Tab Navigation:**
     - Click **Forensic Timeline** tab: Show the 85 events arranged chronologically with links back to findings.
     - Click **MITRE ATT&CK Mapping** tab: Show the 30 mapped techniques with tactics.
     - Click **Datasets & Hashes** tab: Show the 6 verified EVTX sources with SHA-256 hashes.

---

### Step 9: Limitations, QA Results & Conclusion (1 Minute — Member 1 & 5)
- **Action:** Run the automated QA validation suite.
- **Command:**
  ```powershell
  python scripts/validate_outputs.py
  ```
- **Presenter Script:**
  > "We close with scientific transparency. We disclose our telemetry limitations: PowerShell Script Block Logging was inactive in the BabyShark log, and network telemetry is absent in standalone EVTX samples. However, our automated QA test suite confirms 13 out of 13 acceptance checks pass with zero failures. The entire pipeline is verifiable and reproducible. Thank you, and we welcome your questions."

---

## 3. Fallback Demonstration Plan

If the live presentation environment experiences technical restrictions:
1. **No Network Access:** The pipeline is completely offline; all EVTX files, binaries, scripts, and rules are local on disk.
2. **Local HTTP Server Blocked:** Double-click `src/summary.html` directly in File Explorer. The dashboard incorporates build-time embedded fallback data and functions offline via `file://` protocol.
3. **Execution Time Constraint:** Review pre-generated artifacts in `outputs/` (`findings.csv`, `timeline.csv`, `attack_mapping.csv`, `processed_data.json`) and the automated QA test suite (`python -m unittest tests/test_pipeline.py`).
4. **Visual Evidence:** Review verified browser screenshots in `screenshots/` (`01_overview.png`, `02_filtered_findings.png`, `03_evidence_modal.png`, `04_timeline.png`).
