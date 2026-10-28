# Data Dictionary

**Owner:** Member 1 -- Project Lead & Integration Owner  
**Status:** Updated for `feat-improvements` branch (headers frozen -- do not change column names without team approval)  
**Last Updated:** 2026-10-28

---

## Purpose

This document defines every field across all shared output files. All members must use these exact column names and formats. Changes require team lead approval and a README update.

---

## 1. Timestamp Format

All timestamps use **ISO 8601 with UTC offset** unless otherwise noted:

```
YYYY-MM-DDTHH:MM:SSZ       (UTC)
YYYY-MM-DDTHH:MM:SS+HH:MM  (local with offset)
```

Example: `2026-10-01T02:34:17Z`

---

## 2. `outputs/shortlist.csv`

**Contract headers (frozen):** `finding_id,timestamp,timezone,alert_name,severity,rule_id,source_file,event_reference,analyst_note`

| Column | Type | Description | Example |
|---|---|---|---|
| `finding_id` | String | Stable identifier, format F-NN | `F-01` |
| `timestamp` | ISO 8601 | Event timestamp | `2026-10-01T02:34:17Z` |
| `timezone` | String | Time zone assumption | `UTC` |
| `alert_name` | String | Hayabusa rule/alert name | `Suspicious Process Access To LSASS Memory` |
| `severity` | Enum | Hayabusa severity level | `high` / `medium` / `low` / `informational` |
| `rule_id` | String | Underlying Sigma rule ID | `proc_access_lsass_susp_source` |
| `source_file` | String | Source EVTX file | `Security_4688.evtx` |
| `event_reference` | String | Event ID and log channel | `EventID:10 / Sysmon/Operational` |
| `analyst_note` | String | Brief initial note from Member 3 | `lsass.exe accessed by python.exe -- high priority for review` |

---

## 3. `outputs/findings.csv`

**Contract headers (frozen):** `finding_id,timestamp,timezone,alert_name,severity,status,confidence,host,event_id,channel,record_id,rule_id,evidence_reference,details,interpretation,benign_explanation,limitation,next_step,techniques`

| Column | Type | Description | Example |
|---|---|---|---|
| `finding_id` | String | Foreign key to shortlist | `F-01` |
| `timestamp` | ISO 8601 | Validated event timestamp | `2026-10-01T02:34:17Z` |
| `timezone` | String | Time zone used | `UTC` |
| `alert_name` | String | Hayabusa alert name | `Suspicious Process Access To LSASS Memory` |
| `severity` | Enum | `critical`, `high`, `medium`, `low`, `informational` | `high` |
| `status` | Enum | `candidate`, `validated_observation`, `inconclusive` | `validated_observation` |
| `confidence` | Enum | `high`, `medium`, `low` | `medium` |
| `host` | String | Host identifier from Hayabusa output | `IEWIN7` |
| `event_id` | Integer | Windows Event ID | `10` |
| `channel` | String | Log channel | `Microsoft-Windows-Sysmon/Operational` |
| `record_id` | String | Hayabusa record identifier | `47` |
| `rule_id` | String | Sigma rule ID | `proc_access_lsass_susp_source` |
| `evidence_reference` | String | Event ID, channel, field, row | `EventID:10 / Sysmon row 47` |
| `details` | String | Raw detail field from Hayabusa | `SourceImage: python.exe` |
| `interpretation` | String | What the event indicates | `Process opened LSASS memory with PROCESS_VM_READ` |
| `benign_explanation` | String | Plausible non-malicious explanation | `Security scanner or AV product performing memory scan` |
| `limitation` | String | Missing evidence or gaps | `No parent process chain available` |
| `next_step` | String | What additional evidence would confirm | `Correlate with network connections from the same host` |
| `techniques` | String | Semicolon-separated ATT&CK technique IDs | `T1003.001;T1059.001` |

---

## 4. `outputs/timeline.csv`

**Contract headers (frozen):** `timestamp,timezone,finding_id,event_id,channel,host_label,level,summary,evidence_reference`

| Column | Type | Description | Example |
|---|---|---|---|
| `timestamp` | ISO 8601 | Event time | `2026-10-01T02:34:17Z` |
| `timezone` | String | UTC or offset | `UTC` |
| `finding_id` | String | Associated finding (if any) | `F-01` |
| `event_id` | Integer | Windows Event ID | `10` |
| `channel` | String | Log channel | `Microsoft-Windows-Sysmon/Operational` |
| `host_label` | String | Anonymized host identifier | `IEWIN7` |
| `level` | String | Hayabusa alert level | `high` |
| `summary` | String | One-line description | `python.exe accessed lsass.exe (PROCESS_VM_READ)` |
| `evidence_reference` | String | File and row/line | `Sysmon_10.evtx row 47` |

---

## 5. `outputs/attack_mapping.csv`

**Contract headers (frozen):** `finding_id,tactic,technique_id,technique_name,mapping_rationale,evidence_reference,confidence,mapping_status,limitation`

| Column | Type | Description | Example |
|---|---|---|---|
| `finding_id` | String | Foreign key | `F-01` |
| `tactic` | String | MITRE ATT&CK tactic name | `Credential Access` |
| `technique_id` | String | MITRE ATT&CK technique ID | `T1003.001` |
| `technique_name` | String | Full technique name | `OS Credential Dumping: LSASS Memory` |
| `mapping_rationale` | String | Evidence-based reason for mapping | `Python process opened lsass.exe with PROCESS_VM_READ` |
| `evidence_reference` | String | Pointer to supporting evidence | `findings.csv F-01, Sysmon EventID:10 row 47` |
| `confidence` | Enum | `high`, `medium`, `low` | `medium` |
| `mapping_status` | String | Status of the mapping | `confirmed` |
| `limitation` | String | Limitations of the mapping | `No dump file observed` |

---

## 6. `data/ground_truth.csv`

**Purpose:** Six-row dataset used by `scripts/evaluate_detection.py` for detection evaluation.  
**Note:** This is not a precision/recall benchmark. Six samples with no benign baseline do not constitute a representative evaluation.

| Column | Type | Description | Example |
|---|---|---|---|
| `filename` | String | EVTX sample filename (without path) | `babyshark_sample.evtx` |
| `expected_behavior` | String | Expected malicious behavior based on sample description and analyst review | `Credential dumping via LSASS access` |
| `expected_technique_ids` | String | Semicolon-separated ATT&CK technique IDs expected for this sample | `T1003.001;T1059.001` |
| `source_note` | String | Basis for the expected behavior (repo description + analyst review) | `repo description + analyst review` |

**Limitation documentation:** The ground truth source label `repo description + analyst review` is a convention describing the evidence basis. Six small samples do not represent the full breadth of malicious behaviors.

---

## 7. `outputs/evaluation.csv`

**Purpose:** Per-sample evaluation results produced by `scripts/evaluate_detection.py`.

| Column | Type | Description | Example |
|---|---|---|---|
| `filename` | String | EVTX sample filename | `babyshark_sample.evtx` |
| `expected_behavior` | String | Expected behavior from ground truth | `Credential dumping via LSASS access` |
| `evaluation_status` | Enum | `hit`, `miss`, `uncertain` | `hit` |
| `matching_alert_titles` | String | Semicolon-separated alert rule titles that matched | `Password Dumper Remote Thread in LSASS` |
| `relevant_finding_ids` | String | Semicolon-separated finding IDs relevant to this sample | `F-01;F-02` |
| `mapped_technique_ids` | String | Semicolon-separated technique IDs from the ATT&CK mapping | `T1003.001` |
| `noise_alert_count` | Integer | Alerts present but not relevant to expected behavior | `3` |
| `notes` | String | Analyst note on the evaluation result | `Alert matched on LSASS technique ID` |

---

## 8. `outputs/evaluation.json`

**Purpose:** Machine-readable evaluation summary with metadata and limitations.

**Top-level keys:**

| Key | Type | Description |
|---|---|---|
| `metadata` | Object | Run metadata: `generated_at`, `script`, `processing_time_seconds`, `processing_time_note` |
| `samples` | Array | One object per EVTX sample (see below) |
| `summary` | Object | Aggregate counts: `total`, `hits`, `misses`, `uncertain` |
| `limitations` | Array | List of limitation strings |

**`samples` array item keys:**

| Key | Type | Description |
|---|---|---|
| `filename` | String | EVTX sample filename |
| `expected_behavior` | String | Expected behavior |
| `evaluation_status` | String | `hit`, `miss`, or `uncertain` |
| `matching_alert_titles` | Array | List of matching alert rule titles |
| `relevant_finding_ids` | Array | Finding IDs relevant to this sample |
| `mapped_technique_ids` | Array | Technique IDs from ATT&CK mapping |
| `noise_alert_count` | Integer | Count of alerts not relevant to expected behavior |
| `notes` | String | Evaluation note |

**Processing time note:** Parsed from `outputs/raw/hayabusa_run_log.txt` after stripping ANSI escape codes. The value `5.404` seconds was recorded from the actual run. If the log does not contain a parseable duration, the field is set to `null` and `processing_time_note` explains why.

---

## 9. `outputs/attack_navigator_layer.json`

**Purpose:** ATT&CK Navigator v4.9 layer file for visual technique highlighting.  
**Import at:** https://mitre-attack.github.io/attack-navigator/

**Top-level structure (Navigator layer v4.5):**

| Key | Description |
|---|---|
| `name` | Layer name |
| `versions` | Object with keys `attack`, `navigator`, `layer` |
| `domain` | Always `enterprise-attack` |
| `techniques` | Array of technique entry objects |

**Technique entry keys:**

| Key | Description |
|---|---|
| `techniqueID` | ATT&CK technique ID (e.g., `T1003.001`) |
| `enabled` | Always `true` |
| `color` | Red (`#ff6666`) for high, orange (`#ffaa44`) for medium, yellow (`#ffee44`) for low confidence |
| `comment` | Associated finding ID(s) |

Multiple findings for the same technique are merged into a single entry. Only techniques present in `outputs/attack_mapping.csv` appear in the layer.

---

## 10. `outputs/processed_data.json`

**Purpose:** Data bundle polled by `src/summary.html` every 30 seconds.  
**Important:** The metadata timestamp key is `run_timestamp` (not `generated_at`).

**Top-level keys:** `metadata`, `findings`, `timeline`, `attack_mapping`

---

## 11. Immutable Files

| File | Description | Constraint |
|---|---|---|
| `outputs/raw/hayabusa_raw_output.csv` | Preserved Hayabusa reference output (11 lines: 1 header + 10 data) | Must not be modified, renamed, or regenerated |
| `outputs/raw/hayabusa_run_log.txt` | Hayabusa console log; contains processing time 5.404 s | Must not be modified |

---

## 12. Status / Severity Labels

### Severity (from Hayabusa output)

| Label | Meaning |
|---|---|
| `critical` | Highly specific rule; strong indicator of malicious activity |
| `high` | Strong indicator; context still needed |
| `medium` | Suspicious; requires additional evidence |
| `low` | Weak signal; often benign |
| `informational` | Audit / logging artifact; not suspicious in isolation |

### Finding Status (analyst label -- immutable, three values only)

| Label | Meaning |
|---|---|
| `validated_observation` | Evidence directly supports the conclusion |
| `candidate` | Alert fired; evidence reviewed but not fully confirmed |
| `inconclusive` | Insufficient evidence to determine malicious or benign |

No other status values are permitted. Scripts must reject any row with a status outside these three.

### Confidence

| Label | Meaning |
|---|---|
| `high` | Strong evidence; low ambiguity |
| `medium` | Reasonable evidence; alternative explanations possible |
| `low` | Weak evidence; significant uncertainty |
