# Data Dictionary

**Owner:** Member 1 — Project Lead & Integration Owner  
**Status:** Complete (frozen — do not change column names without team approval)  
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

| Column | Type | Description | Example |
|---|---|---|---|
| `finding_id` | String | Stable identifier, format F-NN | `F-01` |
| `timestamp` | ISO 8601 | Event timestamp | `2026-10-01T02:34:17Z` |
| `timezone` | String | Time zone assumption | `UTC` |
| `alert_name` | String | Hayabusa rule/alert name | `Suspicious Process Access To LSASS Memory` |
| `severity` | Enum | Hayabusa severity level | `high` / `medium` / `low` / `informational` |
| `rule_name` | String | Underlying Sigma rule filename | `proc_access_lsass_susp_source.yml` |
| `source_file` | String | Source EVTX file | `Security_4688.evtx` |
| `event_reference` | String | Event ID and log channel | `EventID:10 / Sysmon/Operational` |
| `analyst_note` | String | Brief initial note from Member 3 | `lsass.exe accessed by python.exe — high priority for review` |

---

## 3. `outputs/findings.csv`

| Column | Type | Description | Example |
|---|---|---|---|
| `finding_id` | String | Foreign key to shortlist | `F-01` |
| `timestamp` | ISO 8601 | Validated event timestamp | `2026-10-01T02:34:17Z` |
| `timezone` | String | Time zone used | `UTC` |
| `alert_name` | String | Hayabusa alert name | `Suspicious Process Access To LSASS Memory` |
| `severity` | Enum | `critical`, `high`, `medium`, `low`, `informational` | `high` |
| `status` | Enum | `candidate`, `validated_observation`, `inconclusive` | `validated_observation` |
| `confidence` | Enum | `high`, `medium`, `low` | `medium` |
| `evidence_reference` | String | Event ID, channel, field, row | `EventID:10 / Sysmon row 47` |
| `interpretation` | String | What the event indicates | `Process opened LSASS memory with PROCESS_VM_READ access rights — behavior consistent with credential dumping` |
| `benign_explanation` | String | Plausible non-malicious explanation | `Security scanner or AV product performing memory scan` |
| `limitation` | String | Missing evidence or gaps | `No parent process chain available; no network connection evidence` |
| `next_step` | String | What additional evidence would confirm | `Correlate with network connections from the same host; check for lsass dump files` |

---

## 4. `outputs/timeline.csv`

| Column | Type | Description | Example |
|---|---|---|---|
| `timestamp` | ISO 8601 | Event time | `2026-10-01T02:34:17Z` |
| `timezone` | String | UTC or offset | `UTC` |
| `finding_id` | String | Associated finding (if any) | `F-01` |
| `event_id` | Integer | Windows Event ID | `10` |
| `channel` | String | Log channel | `Microsoft-Windows-Sysmon/Operational` |
| `host_label` | String | Anonymized host identifier | `WORKSTATION-A` |
| `summary` | String | One-line description | `python.exe accessed lsass.exe (PROCESS_VM_READ)` |
| `evidence_reference` | String | File and row/line | `Sysmon_10.evtx row 47` |

---

## 5. `outputs/attack_mapping.csv`

| Column | Type | Description | Example |
|---|---|---|---|
| `finding_id` | String | Foreign key | `F-01` |
| `tactic` | String | MITRE ATT&CK tactic name | `Credential Access` |
| `technique_id` | String | MITRE ATT&CK technique ID | `T1003.001` |
| `technique_name` | String | Full technique name | `OS Credential Dumping: LSASS Memory` |
| `mapping_rationale` | String | Evidence-based reason for mapping | `Python process opened lsass.exe with PROCESS_VM_READ — consistent with credential extraction tools such as Mimikatz` |
| `evidence_reference` | String | Pointer to supporting evidence | `findings.csv F-01, Sysmon EventID:10 row 47` |

---

## 6. Status / Severity Labels

### Severity (from Hayabusa output)
| Label | Meaning |
|---|---|
| `critical` | Highly specific rule; strong indicator of malicious activity |
| `high` | Strong indicator; context still needed |
| `medium` | Suspicious; requires additional evidence |
| `low` | Weak signal; often benign |
| `informational` | Audit / logging artifact; not suspicious in isolation |

### Status / Confidence (analyst label)
| Label | Meaning |
|---|---|
| `validated_observation` | Evidence directly supports the conclusion |
| `candidate` | Alert fired; evidence reviewed but not fully confirmed |
| `inconclusive` | Insufficient evidence to determine malicious or benign |
