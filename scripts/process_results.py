#!/usr/bin/env python3
"""
process_results.py — Windows Threat Hunting System
Member 3/4 processing pipeline.

Reads the real Hayabusa v4.2.0 dfir-timeline CSV output and produces:
  outputs/shortlist.csv
  outputs/findings.csv
  outputs/timeline.csv
  outputs/attack_mapping.csv
  outputs/processed_data.json  (used by the dashboard)

Usage:
    python scripts/process_results.py
"""

import csv
import json
import os
import sys
from pathlib import Path
from datetime import datetime, timezone

# ── Path setup ──────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
RAW_CSV = ROOT / "outputs" / "raw" / "hayabusa_real_output.csv"
OUT_DIR = ROOT / "outputs"

# ── MITRE ATT&CK technique registry ──────────────────────────────────────────
TECHNIQUE_NAMES = {
    "T1003":     ("Credential Access", "OS Credential Dumping"),
    "T1003.001": ("Credential Access", "OS Credential Dumping: LSASS Memory"),
    "T1033":     ("Discovery", "System Owner/User Discovery"),
    "T1053.005": ("Persistence / Privilege Escalation", "Scheduled Task/Job: Scheduled Task"),
    "T1059.001": ("Execution", "Command and Scripting Interpreter: PowerShell"),
    "T1088":     ("Privilege Escalation", "Bypass User Account Control"),
    "T1086":     ("Execution", "PowerShell"),
    "T1055":     ("Defense Evasion / Privilege Escalation", "Process Injection"),
    "T1027.010": ("Defense Evasion", "Obfuscated Files or Information: Command Obfuscation"),
    "T1136.001": ("Persistence", "Create Account: Local Account"),
}

def parse_timestamp(ts_str):
    """Parse Hayabusa v4 timestamp like '2019-04-18 16:58:14.811 +00:00'."""
    if not ts_str:
        return None
    ts_str = ts_str.strip()
    # Handle formats like "2019-04-18 16:58:14.811 +00:00"
    for fmt in [
        "%Y-%m-%d %H:%M:%S.%f %z",
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
    ]:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None

def iso_ts(dt):
    """Return ISO 8601 UTC timestamp string."""
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def load_raw_csv(path):
    """Load and basic-validate the raw Hayabusa CSV."""
    rows = []
    required_cols = {"Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID"}
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        cols = set(reader.fieldnames or [])
        missing = required_cols - cols
        if missing:
            print(f"WARNING: Missing expected columns: {missing}", file=sys.stderr)
        for i, row in enumerate(reader):
            row["_line"] = i + 2
            rows.append(row)
    return rows

def extract_technique(rule_title, details):
    """Extract MITRE technique IDs from rule title or details field."""
    techniques = []
    text = f"{rule_title} {details}".lower()
    # Check for explicit technique IDs in details
    for tid, (tactic, name) in TECHNIQUE_NAMES.items():
        tid_lower = tid.lower()
        if tid_lower in text:
            techniques.append(tid)
    return list(set(techniques))

def classify_finding(row):
    """Determine if a row should be elevated to a documented finding."""
    level = row.get("Level", "").lower()
    rule = row.get("RuleTitle", "")
    # high/critical/emergency always qualify
    if level in ("high", "emergency", "critical"):
        return True
    # Promote medium alerts that match suspicious keywords (handles v4 abbrev 'med')
    priority_keywords = [
        "lsass", "credential", "dump", "mimikatz", "password dumper",
        "scheduled task", "persistence", "powershell", "injection"
    ]
    if level in ("medium", "med") and any(k in rule.lower() for k in priority_keywords):
        return True
    return False

def assign_confidence(row, techniques):
    """Assign confidence based on rule level and technique evidence."""
    level = row.get("Level", "").lower()
    has_technique = len(techniques) > 0
    if level in ("emergency", "critical"):
        return "high"
    if level == "high" and has_technique:
        return "high"
    if level == "high":
        return "medium"
    return "medium"

def map_severity_tag(level):
    """Normalize Hayabusa level to our schema severity (handles v4 abbreviations)."""
    level = level.lower().strip()
    mapping = {
        "emergency": "critical",
        "critical": "critical",
        "high": "high",
        "med": "medium",
        "medium": "medium",
        "low": "low",
        "informational": "informational",
        "info": "informational",
    }
    return mapping.get(level, level)

def generate_interpretation(row):
    """Generate an evidence-backed interpretation of the finding."""
    rule = row.get("RuleTitle", "")
    details = row.get("Details", "")
    computer = row.get("Computer", "")
    eid = row.get("EventID", "")
    channel = row.get("Channel", "")

    interps = {
        "Password Dumper Remote Thread in LSASS": (
            f"A remote thread was injected into lsass.exe on {computer}. "
            "This is a classic Mimikatz CreateRemoteThread injection pattern (EventID:8 Sysmon). "
            "The thread injection approach allows credential extraction from LSASS memory without a full dump file."
        ),
        "LSASS Process Memory Dump Files": (
            f"A dump file of the lsass.exe process was created on {computer}. "
            "Sysmon EventID:11 file creation event recorded a .dmp file consistent with procdump.exe or Task Manager memory dump. "
            "LSASS dump files contain Kerberos tickets and NTLM hashes in plaintext."
        ),
        "LSASS Memory Access by Tool With Dump Keyword In Name": (
            f"procdump.exe opened lsass.exe with full access mask (0x1fffff) on {computer}. "
            "Sysmon EventID:10 captured the process access with PROCESS_ALL_ACCESS rights. "
            "This confirms deliberate credential extraction using ProcDump, a Sysinternals tool commonly misused for LSASS dumping."
        ),
        "LSASS Process Memory Dump Creation Via Taskmgr.EXE": (
            f"Task Manager was used to create an LSASS process dump on {computer}. "
            "Task Manager's Create Dump File feature writes a full process dump to %TEMP%. "
            "This is a documented low-tech credential theft technique requiring only GUI access."
        ),
        "Suspicious Process Access to LSASS with Dbgcore/Dbghelp DLLs": (
            f"procdump.exe accessed lsass.exe using Dbgcore/Dbghelp DLLs on {computer}. "
            "The use of debug helper DLLs indicates a legitimate-looking dump mechanism being used offensively. "
            "Access mask 0x1fffff grants full process access including memory read."
        ),
        "Proc Access (Sysmon Alert)": (
            f"PowerShell.exe opened lsass.exe with PROCESS_VM_READ (0x1010) access rights on {computer}. "
            "Sysmon EventID:10 captured this credential access pattern linked to Invoke-Mimikatz or similar PowerShell-based tools. "
            "Access mask 0x1010 is used to read LSASS memory for credential extraction without writing a dump file."
        ),
        "Proc Exec (Sysmon Alert)": (
            f"Sysmon EventID:1 process creation alert on {computer}. "
            "Details indicate suspicious process execution that matched a high-confidence Sysmon detection rule. "
            f"Full details: {details[:200]}"
        ),
        "Proc Exec (Non-Exe Filetype)": (
            f"A non-standard executable filetype was launched on {computer}. "
            "This may indicate DLL execution, scripted payload, or renamed executable — a common defense evasion technique."
        ),
        "Scheduled Task Created - FileCreation": (
            f"A scheduled task was created on {computer}. "
            "Sysmon captured file creation events associated with task XML definition files. "
            "Scheduled tasks are a common persistence mechanism and require investigation of the task action and trigger."
        ),
        "Non Interactive PowerShell Process Spawned": (
            f"A non-interactive PowerShell process spawned on {computer}. "
            "Non-interactive PowerShell is commonly used for automated/scripted attack payloads. "
            "Combined with other indicators in this dataset, this represents the PowerShell-based attack vector."
        ),
        "Potential Credential Dumping Activity Via LSASS": (
            f"Potential credential dumping activity targeting LSASS was detected on {computer}. "
            "This detection correlates multiple indicators suggesting active credential theft from LSASS memory."
        ),
        "Potential Credential Dumping Attempt Via PowerShell": (
            f"PowerShell-based credential dumping attempt detected on {computer}. "
            "Sysmon EventID:4104 script block logging captured suspicious PowerShell commands targeting LSASS."
        ),
    }

    for key, interp in interps.items():
        if key.lower() in rule.lower():
            return interp

    # Generic fallback
    return (
        f"Hayabusa rule '{rule}' triggered on {computer} (EventID:{eid}, Channel:{channel}). "
        f"Evidence: {details[:300]}"
    )

def generate_benign_explanation(rule):
    """Generate a plausible benign explanation."""
    mapping = {
        "lsass": "Security software (AV, EDR) legitimately reads LSASS for process monitoring. However, process name and context should be verified against known security products.",
        "dump": "System administrators use dump tools for debugging and crash analysis. Task Manager memory dumps are also used for legitimate troubleshooting.",
        "powershell": "IT automation extensively uses PowerShell. Non-interactive PowerShell sessions are used by Group Policy, scheduled tasks, and deployment tools.",
        "scheduled task": "Software installers and system management tools create scheduled tasks. The trigger and action path should be evaluated for legitimacy.",
        "injection": "Some legitimate software uses thread injection for inter-process communication. Anti-cheat software and certain monitoring tools exhibit similar patterns.",
        "account": "IT administrators routinely create and modify local accounts. Password policies and account management scripts may trigger this rule.",
    }
    rule_lower = rule.lower()
    for key, expl in mapping.items():
        if key in rule_lower:
            return expl
    return "This event may be generated by legitimate system activity. Further context (parent process chain, user context, frequency) is required to assess."

def generate_next_steps(rule, techniques):
    """Generate concrete investigation next steps."""
    steps = []
    rule_lower = rule.lower()
    if "lsass" in rule_lower or "dump" in rule_lower:
        steps.append("Verify the source process is a known security product (check signed binary, product metadata).")
        steps.append("Check for .dmp files in %TEMP% and %APPDATA% directories.")
        steps.append("Correlate with any subsequent use of extracted credentials (lateral movement).")
    if "powershell" in rule_lower or "T1059.001" in techniques:
        steps.append("Enable PowerShell Script Block Logging (EventID:4104) if not already active.")
        steps.append("Decode any Base64-encoded command parameters.")
        steps.append("Check proxy/firewall logs for outbound connections from the PowerShell process.")
    if "scheduled task" in rule_lower or "T1053.005" in techniques:
        steps.append("Retrieve and analyze the scheduled task XML definition.")
        steps.append("Examine the task action path for suspicious file locations.")
        steps.append("Check for task execution events in Task Scheduler Operational log.")
    if "injection" in rule_lower or "T1055" in techniques:
        steps.append("Investigate the source process that performed the thread injection.")
        steps.append("Check for network activity from the target process after injection.")
    if not steps:
        steps.append("Collect full command-line arguments and parent process chain.")
        steps.append("Correlate timestamps with other suspicious events in the same window.")
    return " | ".join(steps)

def generate_limitation(row):
    """Document evidence gaps and limitations."""
    rule = row.get("RuleTitle", "")
    rule_lower = rule.lower()
    limitations = []
    if "dump" in rule_lower or "lsass" in rule_lower:
        limitations.append("No network telemetry available to confirm credential exfiltration.")
    if "powershell" in rule_lower:
        limitations.append("Script Block Logging availability depends on system configuration.")
    if "high" in row.get("Level", "").lower():
        limitations.extend(["Sample EVTX file contains limited time window.", "No threat intelligence correlation available."])
    if not limitations:
        limitations.append("Single-file sample — full attack chain may extend beyond captured events.")
    return " | ".join(limitations)

def main():
    print(f"[+] Loading raw Hayabusa output: {RAW_CSV}")
    if not RAW_CSV.exists():
        print(f"[-] ERROR: File not found: {RAW_CSV}", file=sys.stderr)
        sys.exit(1)

    rows = load_raw_csv(RAW_CSV)
    print(f"[+] Loaded {len(rows)} detection rows")

    # Parse timestamps and sort
    for r in rows:
        r["_dt"] = parse_timestamp(r.get("Timestamp", ""))
    rows.sort(key=lambda r: (r["_dt"] or datetime.min.replace(tzinfo=timezone.utc)))

    # Level distribution
    from collections import Counter
    level_counts = Counter(r.get("Level", "").lower() for r in rows)
    print(f"[+] Level distribution: {dict(level_counts)}")

    # ── Build findings ───────────────────────────────────────────────────────
    findings = []
    shortlist = []
    fid = 1

    seen_rules = set()
    for r in rows:
        if not classify_finding(r):
            continue
        rule = r.get("RuleTitle", "")
        computer = r.get("Computer", "")
        eid = r.get("EventID", "")
        key = f"{rule}|{computer}|{eid}"
        if key in seen_rules:
            continue
        seen_rules.add(key)

        techniques = extract_technique(rule, r.get("Details", ""))
        confidence = assign_confidence(r, techniques)
        severity = map_severity_tag(r.get("Level", ""))
        status = "validated_observation" if confidence == "high" else "candidate"
        finding_id = f"F-{fid:02d}"
        fid += 1

        ts_str = iso_ts(r["_dt"]) if r["_dt"] else r.get("Timestamp", "")
        evidence_ref = (
            f"EventID:{eid} / {r.get('Channel', '')} / RecordID:{r.get('RecordID', 'n/a')} / "
            f"Source: {r.get('_line', 'n/a')} / RuleID: {r.get('RuleID', 'n/a')}"
        )

        finding = {
            "finding_id": finding_id,
            "timestamp": ts_str,
            "timezone": "UTC",
            "alert_name": rule,
            "severity": severity,
            "status": status,
            "confidence": confidence,
            "host": computer,
            "event_id": eid,
            "channel": r.get("Channel", ""),
            "record_id": r.get("RecordID", ""),
            "rule_id": r.get("RuleID", ""),
            "source_file": r.get("_source_file", ""),
            "evidence_reference": evidence_ref,
            "details": r.get("Details", "")[:500],
            "interpretation": generate_interpretation(r),
            "benign_explanation": generate_benign_explanation(rule),
            "limitation": generate_limitation(r),
            "next_step": generate_next_steps(rule, techniques),
            "techniques": ",".join(techniques),
        }
        findings.append(finding)

        short = {
            "finding_id": finding_id,
            "timestamp": ts_str,
            "timezone": "UTC",
            "alert_name": rule,
            "severity": severity,
            "rule_id": r.get("RuleID", ""),
            "source_file": f"{r.get('Channel', '')} / EventID:{eid}",
            "event_reference": evidence_ref,
            "analyst_note": f"{generate_interpretation(r)[:200]}...",
        }
        shortlist.append(short)

    print(f"[+] Findings identified: {len(findings)}")

    # ── Build timeline ───────────────────────────────────────────────────────
    timeline = []
    # Map rule → finding_id
    rule_to_fid = {f["alert_name"]: f["finding_id"] for f in findings}

    for r in rows:
        rule = r.get("RuleTitle", "")
        ts_str = iso_ts(r["_dt"]) if r["_dt"] else r.get("Timestamp", "")
        fid_ref = rule_to_fid.get(rule, "")
        timeline.append({
            "timestamp": ts_str,
            "timezone": "UTC",
            "finding_id": fid_ref,
            "event_id": r.get("EventID", ""),
            "channel": r.get("Channel", ""),
            "host_label": r.get("Computer", ""),
            "level": map_severity_tag(r.get("Level", "")),
            "summary": f"{rule} — {r.get('Details', '')[:200]}",
            "evidence_reference": f"RecordID:{r.get('RecordID', 'n/a')} / RuleID:{r.get('RuleID', 'n/a')}",
        })

    print(f"[+] Timeline entries: {len(timeline)}")

    # ── Build ATT&CK mapping ─────────────────────────────────────────────────
    attack_mappings = []
    used_combos = set()

    for f in findings:
        techniques_str = f.get("techniques", "")
        if not techniques_str:
            continue
        for tid in techniques_str.split(","):
            tid = tid.strip()
            if not tid or (f["finding_id"], tid) in used_combos:
                continue
            used_combos.add((f["finding_id"], tid))
            tactic, tname = TECHNIQUE_NAMES.get(tid, ("Unknown", tid))
            attack_mappings.append({
                "finding_id": f["finding_id"],
                "tactic": tactic,
                "technique_id": tid,
                "technique_name": tname,
                "mapping_rationale": (
                    f"Finding {f['finding_id']} ({f['alert_name']}) triggered at {f['timestamp']} "
                    f"on {f.get('host', 'unknown')}. {f['interpretation'][:300]}"
                ),
                "evidence_reference": f["evidence_reference"],
                "confidence": f["confidence"],
                "mapping_status": f["status"],
                "limitation": f["limitation"],
            })

    print(f"[+] ATT&CK mappings: {len(attack_mappings)}")

    # ── Write outputs ────────────────────────────────────────────────────────
    def write_csv(path, rows, fieldnames):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        print(f"[+] Written: {path} ({len(rows)} rows)")

    FINDINGS_FIELDS = [
        "finding_id", "timestamp", "timezone", "alert_name", "severity", "status",
        "confidence", "host", "event_id", "channel", "record_id", "rule_id",
        "evidence_reference", "details", "interpretation", "benign_explanation",
        "limitation", "next_step", "techniques",
    ]
    SHORTLIST_FIELDS = [
        "finding_id", "timestamp", "timezone", "alert_name", "severity",
        "rule_id", "source_file", "event_reference", "analyst_note",
    ]
    TIMELINE_FIELDS = [
        "timestamp", "timezone", "finding_id", "event_id", "channel",
        "host_label", "level", "summary", "evidence_reference",
    ]
    ATTACK_FIELDS = [
        "finding_id", "tactic", "technique_id", "technique_name",
        "mapping_rationale", "evidence_reference", "confidence",
        "mapping_status", "limitation",
    ]

    write_csv(OUT_DIR / "findings.csv", findings, FINDINGS_FIELDS)
    write_csv(OUT_DIR / "shortlist.csv", shortlist, SHORTLIST_FIELDS)
    write_csv(OUT_DIR / "timeline.csv", timeline, TIMELINE_FIELDS)
    write_csv(OUT_DIR / "attack_mapping.csv", attack_mappings, ATTACK_FIELDS)

    # ── Write JSON for dashboard ─────────────────────────────────────────────
    dashboard_data = {
        "metadata": {
            "hayabusa_version": "v4.2.0",
            "run_timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_detections": len(rows),
            "level_counts": {
                "high": level_counts.get("high", 0),
                "medium": level_counts.get("medium", 0),
                "low": level_counts.get("low", 0),
                "informational": level_counts.get("informational", 0),
            },
            "evtx_files": [
                "babyshark_mimikatz_powershell.evtx",
                "CA_sysmon_hashdump_cmd_meterpreter.evtx",
                "Exec_sysmon_meterpreter_reversetcp_msipackage.evtx",
                "sysmon_10_11_lsass_memdump.evtx",
                "sysmon_local_account_creation_and_added_admingroup_12_13.evtx",
                "temp_scheduled_task_4698_4699.evtx",
            ],
        },
        "findings": findings,
        "timeline": timeline,
        "attack_mapping": attack_mappings,
    }

    json_path = OUT_DIR / "processed_data.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(dashboard_data, f, indent=2, default=str)
    print(f"[+] Written: {json_path}")

    print("\n[DONE] Processing complete.")
    print(f"    Findings:      {len(findings)}")
    print(f"    Timeline:      {len(timeline)}")
    print(f"    ATT&CK maps:   {len(attack_mappings)}")
    print(f"    Total detects: {len(rows)}")

if __name__ == "__main__":
    main()
