#!/usr/bin/env python3
"""
evaluate_detection.py — Windows Threat Hunting System
Part A: Detection Evaluation.

Compares the six EVTX sample ground-truth expectations against:
  1. Hayabusa alerts in outputs/raw/hayabusa_real_output.csv
  2. Existing ATT&CK mapping in outputs/attack_mapping.csv

Produces:
  outputs/evaluation.csv
  outputs/evaluation.json

Usage:
    python scripts/evaluate_detection.py

LIMITATIONS:
  - Only six small samples are included.
  - This is not a benchmark.
  - No benign baseline is available.
  - Results do not establish production detection performance.
  - Potential noise is not equivalent to a verified false positive.
  - Alert-to-sample attribution is inferred from hostname patterns because
    hayabusa_real_output.csv contains no source-file field.
  - The evaluation does not constitute precision, recall, or accuracy metrics.
"""

import csv
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

GROUND_TRUTH_CSV   = ROOT / "data" / "ground_truth.csv"
REAL_OUTPUT_CSV    = ROOT / "outputs" / "raw" / "hayabusa_real_output.csv"
ATTACK_MAPPING_CSV = ROOT / "outputs" / "attack_mapping.csv"
RUN_LOG_TXT        = ROOT / "outputs" / "raw" / "hayabusa_run_log.txt"
EVAL_CSV           = ROOT / "outputs" / "evaluation.csv"
EVAL_JSON          = ROOT / "outputs" / "evaluation.json"

LIMITATIONS = [
    "Only six small EVTX samples are included — not a representative benchmark.",
    "No benign baseline is available; all samples are attack-focused.",
    "Results do not establish production detection performance.",
    "Alert-to-sample attribution is inferred from hostname patterns (no source-file field in CSV).",
    "Potential noise counts are not verified false positives.",
    "The evaluation does not constitute precision, recall, or F1 scores.",
    "Multiple EVTX files may map to the same hostname (IEWIN7), making per-file attribution uncertain.",
]

# Hostname → EVTX filename mapping (inferred from run log and dataset context)
# Attribution confidence is documented per sample in the ground truth CSV.
HOST_TO_SAMPLE = {
    "PC04.example.corp":           "sysmon_10_11_lsass_memdump.evtx",
    "LAPTOP-JU4M3I0E":            "sysmon_local_account_creation_and_added_admingroup_12_13.evtx",
    "WIN-77LTAPHIQ1R.example.corp": "temp_scheduled_task_4698_4699.evtx",
    # IEWIN7 is shared by multiple EVTX files; attribution requires additional heuristics below
}

# Alert rules and keywords that suggest relevance to a given technique
TECHNIQUE_ALERT_KEYWORDS = {
    "T1003.001": ["lsass", "dump", "procdump", "credential dump", "password dumper", "proc access"],
    "T1003":     ["lsass", "dump", "credential", "hash"],
    "T1059.001": ["powershell", "pwsh", "scriptblock"],
    "T1059.003": ["cmd", "command shell"],
    "T1053.005": ["scheduled task", "schtask", "task created"],
    "T1136.001": ["account creat", "local account", "net user", "group add"],
    "T1055":     ["inject", "proc inject", "remote thread"],
    "T1566.001": ["phish", "attachment", "msi"],
    "T1086":     ["powershell"],
}


def parse_processing_time(log_path):
    """
    Extract the Hayabusa dfir-timeline elapsed time from the run log.
    Returns (seconds: float, raw: str) or (None, 'unavailable: <reason>').
    """
    if not log_path.exists():
        return None, "unavailable: run log not found"
    text = log_path.read_text(encoding="utf-8", errors="replace")
    # Look for the dfir-timeline elapsed time line
    # Format: "Elapsed time: 00:00:05.404"
    # Strip ANSI escape codes before matching (run log uses VT100 colour codes)
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    m = re.search(r"Elapsed time:\s+(\d{2}):(\d{2}):(\d{2})\.(\d+)", text)
    if m:
        h, mn, s, frac = m.groups()
        seconds = int(h) * 3600 + int(mn) * 60 + int(s) + float(f"0.{frac}")
        raw = f"{h}:{mn}:{s}.{frac}"
        return seconds, raw
    return None, "unavailable: elapsed time pattern not found in run log"


def load_ground_truth(path):
    if not path.exists():
        raise FileNotFoundError(f"Ground truth CSV not found: {path}")
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    if not rows:
        raise ValueError("Ground truth CSV has no data rows")
    return rows


def load_real_output(path):
    """Load hayabusa_real_output.csv. Returns list of dicts."""
    if not path.exists():
        raise FileNotFoundError(f"Real output CSV not found: {path}")
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            row["_line"] = i + 2
            rows.append(row)
    return rows


def load_attack_mapping(path):
    """Load attack_mapping.csv. Returns list of dicts."""
    if not path.exists():
        return []
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def get_sample_alerts(sample_filename, all_alerts):
    """
    Return alerts attributed to the given sample filename.
    Attribution logic:
      - If hostname maps directly: use that host's alerts.
      - For IEWIN7 samples: use EventID heuristics to partition.
    """
    # Direct host mapping
    direct_hosts = {v: k for k, v in HOST_TO_SAMPLE.items()}
    if sample_filename in direct_hosts:
        host = direct_hosts[sample_filename]
        return [a for a in all_alerts if a.get("Computer", "") == host]

    # IEWIN7 heuristics
    iewin7_alerts = [a for a in all_alerts if a.get("Computer", "") == "IEWIN7"]
    if sample_filename == "babyshark_mimikatz_powershell.evtx":
        # Mimikatz remote thread injection → Sysmon EventID:8 and EventID:10 with lsass
        return [
            a for a in iewin7_alerts
            if str(a.get("EventID", "")) == "8"
            or ("lsass" in str(a.get("Details", "")).lower() and str(a.get("EventID", "")) == "10")
            or "password dumper" in a.get("RuleTitle", "").lower()
        ]
    elif sample_filename == "CA_sysmon_hashdump_cmd_meterpreter.evtx":
        # Meterpreter cmd hashdump → EventID:1 process creation, Proc Exec alerts
        return [
            a for a in iewin7_alerts
            if str(a.get("EventID", "")) == "1"
            and a.get("Level", "").lower() in ("high", "med", "medium")
        ]
    elif sample_filename == "Exec_sysmon_meterpreter_reversetcp_msipackage.evtx":
        # MSI reverse TCP → remaining IEWIN7 alerts not in the above buckets
        # Attribution is UNCERTAIN for this sample; return low-confidence subset
        return [
            a for a in iewin7_alerts
            if str(a.get("EventID", "")) == "1"
            and a.get("Level", "").lower() not in ("high", "med", "medium")
        ]
    return []


def alerts_relevant_to_techniques(alerts, technique_ids_str):
    """
    Classify each alert as relevant or noise relative to expected techniques.
    Returns (relevant_alerts, noise_alerts).
    """
    if not technique_ids_str or not technique_ids_str.strip():
        return [], alerts

    expected_tids = [t.strip() for t in technique_ids_str.split(";") if t.strip()]
    keywords = set()
    for tid in expected_tids:
        for kw in TECHNIQUE_ALERT_KEYWORDS.get(tid, []):
            keywords.add(kw)
    # Also add base technique (T1003 from T1003.001)
    for tid in expected_tids:
        base = tid.split(".")[0]
        for kw in TECHNIQUE_ALERT_KEYWORDS.get(base, []):
            keywords.add(kw)

    relevant, noise = [], []
    for a in alerts:
        rule = a.get("RuleTitle", "").lower()
        details = a.get("Details", "").lower()
        combined = f"{rule} {details}"
        if any(kw in combined for kw in keywords):
            relevant.append(a)
        else:
            noise.append(a)
    return relevant, noise


def get_finding_ids_for_sample(sample_filename, attack_rows, all_finding_ids_from_csv):
    """
    Get finding IDs relevant to this sample based on attack_mapping.csv.
    Uses hostname heuristics — not authoritative.
    """
    # Map sample to host(s)
    direct_hosts = {v: k for k, v in HOST_TO_SAMPLE.items()}
    host = direct_hosts.get(sample_filename)
    if not host and "iewin7" in sample_filename.lower():
        host = "IEWIN7"
    if not host:
        return []
    # All attack_mapping rows where the finding is on this host — approximate
    # (attack_mapping.csv doesn't have host field directly; derive from findings)
    return []  # Cannot reliably do this without joining findings — skip


def evaluate_samples(ground_truth, all_alerts, attack_rows, findings_rows):
    """Run per-sample evaluation. Returns list of sample result dicts."""
    results = []

    for gt_row in ground_truth:
        filename = gt_row.get("filename", "").strip()
        expected_behavior = gt_row.get("expected_behavior", "").strip()
        expected_tids_str = gt_row.get("expected_technique_ids", "").strip()
        source_note = gt_row.get("source_note", "").strip()

        # Get alerts attributed to this sample
        sample_alerts = get_sample_alerts(filename, all_alerts)

        # Classify relevant vs noise
        relevant_alerts, noise_alerts = alerts_relevant_to_techniques(sample_alerts, expected_tids_str)

        # Determine status
        if not sample_alerts:
            status = "miss"
            attribution_note = "No alerts attributed to this sample via hostname mapping."
        elif relevant_alerts:
            status = "hit"
            attribution_note = "At least one alert relevant to expected techniques found."
        else:
            status = "uncertain"
            attribution_note = (
                "Alerts attributed to this host but none clearly match expected techniques; "
                "may reflect noise or misattribution."
            )

        # Uncertain attribution override for specific samples
        if "UNCERTAIN" in source_note.upper() or "uncertain" in source_note.lower():
            if status == "hit":
                attribution_note += " NOTE: Attribution confidence is low for this sample."

        # Collect matching alert rule titles (unique, sorted)
        matching_titles = sorted(set(a.get("RuleTitle", "") for a in relevant_alerts if a.get("RuleTitle")))

        # Matched technique IDs: those we found evidence for
        matched_tids = []
        expected_tids = [t.strip() for t in expected_tids_str.split(";") if t.strip()]
        for tid in expected_tids:
            kws = TECHNIQUE_ALERT_KEYWORDS.get(tid, []) + TECHNIQUE_ALERT_KEYWORDS.get(tid.split(".")[0], [])
            if any(
                any(kw in f"{a.get('RuleTitle','').lower()} {a.get('Details','').lower()}" for kw in kws)
                for a in relevant_alerts
            ):
                matched_tids.append(tid)

        results.append({
            "filename": filename,
            "expected_behavior": expected_behavior,
            "expected_technique_ids": expected_tids,
            "status": status,
            "matching_alert_titles": matching_titles,
            "matching_finding_ids": [],  # cannot reliably join without host field in mapping
            "matched_technique_ids": matched_tids,
            "possible_noise_alert_count": len(noise_alerts),
            "attribution_note": attribution_note,
            "total_attributed_alerts": len(sample_alerts),
            "relevant_alert_count": len(relevant_alerts),
        })

    return results


def write_eval_csv(results, path):
    """Write evaluation.csv."""
    fieldnames = [
        "filename", "expected_behavior", "expected_technique_ids",
        "status", "matching_alert_titles", "matching_finding_ids",
        "matched_technique_ids", "possible_noise_count", "attribution_note",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            writer.writerow({
                "filename": r["filename"],
                "expected_behavior": r["expected_behavior"],
                "expected_technique_ids": ";".join(r["expected_technique_ids"]),
                "status": r["status"],
                "matching_alert_titles": "|".join(r["matching_alert_titles"]),
                "matching_finding_ids": "|".join(r["matching_finding_ids"]),
                "matched_technique_ids": ";".join(r["matched_technique_ids"]),
                "possible_noise_count": r["possible_noise_alert_count"],
                "attribution_note": r["attribution_note"],
            })
    print(f"[+] Written: {path}")


def write_eval_json(results, processing_time_s, processing_time_raw, path):
    """Write evaluation.json."""
    hits = sum(1 for r in results if r["status"] == "hit")
    misses = sum(1 for r in results if r["status"] == "miss")
    uncertain = sum(1 for r in results if r["status"] == "uncertain")

    data = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "processing_time_seconds": processing_time_s,
            "processing_time_raw": processing_time_raw,
            "processing_time_source": "outputs/raw/hayabusa_run_log.txt (dfir-timeline elapsed time)",
            "total_samples": len(results),
            "samples_with_relevant_alerts": hits,
            "samples_missed": misses,
            "samples_uncertain": uncertain,
            "note": (
                "Attribution of alerts to specific EVTX files is inferred from hostname patterns. "
                "The hayabusa_real_output.csv contains no source-file field. "
                "These metrics are approximate indicators, not benchmark results."
            ),
        },
        "limitations": LIMITATIONS,
        "samples": [
            {
                "filename": r["filename"],
                "expected_behavior": r["expected_behavior"],
                "expected_technique_ids": r["expected_technique_ids"],
                "status": r["status"],
                "matching_alert_titles": r["matching_alert_titles"],
                "matching_finding_ids": r["matching_finding_ids"],
                "matched_technique_ids": r["matched_technique_ids"],
                "possible_noise_alert_count": r["possible_noise_alert_count"],
                "total_attributed_alerts": r["total_attributed_alerts"],
                "relevant_alert_count": r["relevant_alert_count"],
                "attribution_note": r["attribution_note"],
            }
            for r in results
        ],
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Written: {path}")


def main():
    print("[+] Loading ground truth...")
    try:
        ground_truth = load_ground_truth(GROUND_TRUTH_CSV)
    except (FileNotFoundError, ValueError) as e:
        print(f"[-] ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"[+] Ground truth: {len(ground_truth)} samples")

    print("[+] Loading Hayabusa real output...")
    try:
        all_alerts = load_real_output(REAL_OUTPUT_CSV)
    except FileNotFoundError as e:
        print(f"[-] ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"[+] Alerts loaded: {len(all_alerts)}")

    print("[+] Loading ATT&CK mapping...")
    attack_rows = load_attack_mapping(ATTACK_MAPPING_CSV)
    print(f"[+] ATT&CK mappings: {len(attack_rows)}")

    print("[+] Parsing processing time from run log...")
    processing_time_s, processing_time_raw = parse_processing_time(RUN_LOG_TXT)
    if processing_time_s is not None:
        print(f"[+] Processing time: {processing_time_raw} ({processing_time_s}s)")
    else:
        print(f"[!] Processing time: {processing_time_raw}")

    print("[+] Running per-sample evaluation...")
    results = evaluate_samples(ground_truth, all_alerts, attack_rows, [])

    # Print summary
    print()
    print("=== Evaluation Summary ===")
    for r in results:
        print(f"  {r['status'].upper():9s} | {r['filename']}")
        if r["matching_alert_titles"]:
            print(f"           | Matching rules: {', '.join(r['matching_alert_titles'][:3])}")
    print()
    hits   = sum(1 for r in results if r["status"] == "hit")
    misses = sum(1 for r in results if r["status"] == "miss")
    unc    = sum(1 for r in results if r["status"] == "uncertain")
    print(f"  Total samples evaluated: {len(results)}")
    print(f"  Hits (relevant alert found): {hits}")
    print(f"  Misses (no alerts attributed): {misses}")
    print(f"  Uncertain (alerts present but unclear relevance): {unc}")
    print()
    print("LIMITATIONS (see evaluation.json for full list):")
    for lim in LIMITATIONS[:3]:
        print(f"  - {lim}")
    print()

    write_eval_csv(results, EVAL_CSV)
    write_eval_json(results, processing_time_s, processing_time_raw, EVAL_JSON)

    print("[DONE] Evaluation complete.")


if __name__ == "__main__":
    main()
