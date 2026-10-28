# Threat Hunting & Forensic Analysis Methodology

**Owner:** Member 1 — Project Lead & Integration Owner  
**Engine:** Hayabusa v4.2.0 (Autumn Release)  
**Status:** Complete & Verified  
**Last Updated:** October 28, 2026  

---

## 1. Overview & Framework Alignment

This project applies an evidence-driven, defensive threat-hunting methodology aligned with the **NIST SP 800-86** (*Guide to Integrating Forensic Techniques into Incident Response*) and the **MITRE ATT&CK Enterprise Matrix v14.1**.

The workflow operates across four structured stages:

```
┌────────────────────────┐      ┌────────────────────────┐
│  STAGE 1: ACQUISITION  │ ───► │   STAGE 2: DETECTION   │
│  - Vetted Public EVTX  │      │  - Hayabusa v4.2.0     │
│  - Cryptographic Hash  │      │  - 4,569 Sigma Rules   │
│  - Scope Definition    │      │  - Preserved Raw CSV   │
└────────────────────────┘      └────────────────────────┘
                                            │
                                            ▼
┌────────────────────────┐      ┌────────────────────────┐
│   STAGE 4: REPORTING   │ ◄─── │  STAGE 3: TRIAGE & QA  │
│  - ATT&CK Mapping      │      │  - Evidence Validation │
│  - Interactive Web SOC │      │  - Benign Hypotheses   │
│  - Automated QA Suite  │      │  - Gap Disclosures     │
└────────────────────────┘      └────────────────────────┘
```

---

## 2. Stage 1: Dataset Acquisition & Verification

### 2.1 Source Selection
Datasets were acquired from the public repository [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (Head Commit `4ceed2f4706daf601c212a8f91c113dd85349a2c`).

Selection criteria:
1. **Diverse Adversary Tactics:** Samples must demonstrate distinct attack stages, including Credential Access, Execution, Persistence, Privilege Escalation, Defense Evasion, and Discovery.
2. **Channel Diversity:** Coverage of both Windows Security auditing (`Security.evtx`) and Sysmon operational logging (`Microsoft-Windows-Sysmon/Operational`).
3. **Cryptographic Integrity:** Every raw EVTX file is independently hashed (SHA-256) upon acquisition and documented in `data/dataset_inventory.csv`.
4. **Non-Destructive Storage:** Original EVTX files remain unchanged in `data/raw/` and excluded from Git commits via `.gitignore`.

---

## 3. Stage 2: Automated Detection — Hayabusa v4.2.0

### 3.1 Detection Engine
Hayabusa v4.2.0 was selected for its high execution velocity (Rust-based engine), native parsing of offline EVTX binary format, and extensive embedded catalog of 4,569 Sigma rules.

### 3.2 Standardized Execution Command
```powershell
.\hayabusa\hayabusa.exe dfir-timeline `
    --directory "data\raw" `
    --output "outputs\raw\hayabusa_raw_output.csv" `
    --UTC `
    --no-wizard `
    --clobber
```

### 3.3 Raw Preservation
Raw output is saved directly to `outputs/raw/hayabusa_raw_output.csv`, and full console output is written to `outputs/raw/hayabusa_run_log.txt`. No manual editing of raw outputs is permitted.

---

## 4. Stage 3: Evidence Corroboration & Triage

1. **Timestamp Normalization:** Timestamps are normalized to ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`).
2. **Triage Prioritization:**
   - All **High** and **Critical** severity alerts are automatically promoted to investigated findings.
   - **Medium** alerts matching priority threat indicators (e.g., `lsass`, `dump`, `powershell`, `injection`, `AlwaysInstallElevated`) are triaged.
   - Key **Low** and **Informational** events representing evasive persistence (e.g. rapid scheduled task deletion) are retained to capture complete attack chains.
3. **Traceability:** Every finding preserves an `evidence_reference` containing EventID, Channel, RecordID, Target Host, and RuleID.
4. **Hypothesis Evaluation:** For each finding, analysts formulate:
   - *Analyst Interpretation:* What the attacker achieved.
   - *Benign Explanation:* Legitimate IT or developer operations that could produce similar telemetry.
   - *Limitations & Gaps:* Missing logs or unrecovered payload files.
   - *Next Investigation Steps:* Actions required to confirm or remediate the event.

---

## 5. Stage 4: MITRE ATT&CK Mapping & Presentation

1. **Mapping Criteria:** Mapping requires observable telemetry indicators (e.g., access rights `0x1fffff` or `0x1010` for LSASS dumping; `CreateRemoteThread` for Process Injection).
2. **Confidence Ratings:**
   - **Validated Observation (High Confidence):** Observable malicious indicators or confirmed exploit tooling.
   - **Candidate Finding (Medium Confidence):** Suspicious behavior that could have an alternative benign explanation in enterprise environments.
3. **Interactive Visualization:** Results are published to `outputs/processed_data.json` and rendered in the interactive web dashboard (`src/summary.html`).
4. **Automated Verification:** The pipeline is validated via `scripts/validate_outputs.py` before final release.
