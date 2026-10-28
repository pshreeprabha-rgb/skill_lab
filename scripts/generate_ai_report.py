#!/usr/bin/env python3
"""
generate_ai_report.py — Windows Threat Hunting System
Part C: Optional Gemini AI Report Draft.

This feature is OPTIONAL. The project works normally without it.
Requires GEMINI_API_KEY environment variable.

Usage:
    GEMINI_API_KEY=<key> python scripts/generate_ai_report.py

Outputs:
  report/ai_summary.md         (accepted — passes validation)
  report/ai_summary.REJECTED.md (rejected — failed validation)

IMPORTANT: The generated report is a draft requiring human review.
           Do not treat AI-generated prose as verified forensic conclusions.
"""

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PROCESSED_JSON  = ROOT / "outputs" / "processed_data.json"
EVAL_JSON       = ROOT / "outputs" / "evaluation.json"
ATTACK_CSV      = ROOT / "outputs" / "attack_mapping.csv"
REPORT_ACCEPTED = ROOT / "report" / "ai_summary.md"
REPORT_REJECTED = ROOT / "report" / "ai_summary.REJECTED.md"

REQUIRED_HEADER = "AI-generated draft - requires human review"

# Official SDK: google-generativeai (pip install google-generativeai)
# Documentation: https://ai.google.dev/gemini-api/docs/quickstart?lang=python
# Verified: 2026-10-28 at https://ai.google.dev/api/python/google/generativeai
MODEL_NAME = "gemini-2.0-flash"


def load_approved_data():
    """Load and return only approved public project data for the prompt."""
    data = {}

    if PROCESSED_JSON.exists():
        with open(PROCESSED_JSON, encoding="utf-8") as f:
            raw = json.load(f)
        # Build minimal safe input
        meta = raw.get("metadata", {})
        findings = raw.get("findings", [])
        attack_mapping = raw.get("attack_mapping", [])
        data["metadata"] = {
            "hayabusa_version": meta.get("hayabusa_version", ""),
            "run_timestamp": meta.get("run_timestamp", ""),
            "total_detections": meta.get("total_detections", 0),
            "evtx_files": meta.get("evtx_files", []),
        }
        data["findings"] = [
            {
                "finding_id": f.get("finding_id", ""),
                "timestamp": f.get("timestamp", ""),
                "alert_name": f.get("alert_name", ""),
                "severity": f.get("severity", ""),
                "status": f.get("status", ""),
                "confidence": f.get("confidence", ""),
                "host": f.get("host", ""),
                "interpretation": f.get("interpretation", ""),
                "limitation": f.get("limitation", ""),
            }
            for f in findings
        ]
        data["attack_mapping"] = [
            {
                "finding_id": m.get("finding_id", ""),
                "tactic": m.get("tactic", ""),
                "technique_id": m.get("technique_id", ""),
                "technique_name": m.get("technique_name", ""),
                "confidence": m.get("confidence", ""),
                "mapping_status": m.get("mapping_status", ""),
            }
            for m in attack_mapping
        ]
    else:
        print("[!] processed_data.json not found — using empty findings", file=sys.stderr)
        data["findings"] = []
        data["attack_mapping"] = []
        data["metadata"] = {}

    if EVAL_JSON.exists():
        with open(EVAL_JSON, encoding="utf-8") as f:
            eval_data = json.load(f)
        data["evaluation"] = {
            "metadata": eval_data.get("metadata", {}),
            "limitations": eval_data.get("limitations", []),
            "sample_count": len(eval_data.get("samples", [])),
        }
    else:
        data["evaluation"] = {"note": "evaluation.json not available"}

    return data


def build_prompt(data):
    """Build the model prompt from approved project data."""
    findings_text = json.dumps(data.get("findings", []), indent=2)
    attack_text = json.dumps(data.get("attack_mapping", []), indent=2)
    meta_text = json.dumps(data.get("metadata", {}), indent=2)
    eval_text = json.dumps(data.get("evaluation", {}), indent=2)

    valid_finding_ids = [f["finding_id"] for f in data.get("findings", [])]
    valid_technique_ids = [m["technique_id"] for m in data.get("attack_mapping", [])]
    total_findings = len(data.get("findings", []))

    prompt = f"""You are assisting a security analyst in drafting a summary report of a threat hunting investigation.

STRICT INSTRUCTIONS — MUST BE FOLLOWED:
1. Use ONLY the data provided below. Do not invent events, findings, techniques, counts, timestamps, or conclusions.
2. Cite the exact finding ID (e.g., F-01) for every factual claim about a specific finding.
3. Valid finding IDs are: {valid_finding_ids}. Do not reference any other finding ID.
4. Valid ATT&CK technique IDs for this project are: {valid_technique_ids}. Do not cite any other technique ID.
5. There are exactly {total_findings} findings in this dataset. Do not state a different count.
6. Findings with status "candidate" or "inconclusive" MUST be labelled as uncertain in the report.
7. Do NOT claim the system is compromised. Evidence shows suspicious activity consistent with attack techniques — this is not proof of a successful breach.
8. Do NOT present this report as a verified forensic conclusion. It is a draft.
9. Explain that this investigation covers only 6 small EVTX samples and no benign baseline is available.
10. Distinguish observed evidence (what Hayabusa detected) from analyst interpretation.
11. Do not fabricate network connections, exfiltration events, or lateral movement unless evidence is provided.

BEGIN your report with this EXACT heading on the first line:
# AI-generated draft - requires human review

Then write a concise security investigation summary covering:
- Executive overview (what was investigated, tool used, dataset scope)
- Key findings (cite finding IDs, be honest about candidate/inconclusive status)
- ATT&CK techniques observed (cite only techniques from the provided mapping)
- Limitations (six samples, no benign baseline, rule-based detection only)
- Recommended next steps

PROJECT DATA:
=== Metadata ===
{meta_text}

=== Findings ({total_findings} total) ===
{findings_text}

=== ATT&CK Mapping ===
{attack_text}

=== Evaluation ===
{eval_text}
"""
    return prompt


# ── Validation Functions ──────────────────────────────────────────────────────

def validate_finding_refs(text, valid_ids):
    """
    Extract F-NN references and verify each exists in valid_ids.
    Returns list of invalid IDs found.
    Deterministic — does not call any API.
    """
    # Match F- followed by digits, but not dates like 2026-10-01
    found = re.findall(r"\bF-\d{2,}\b", text)
    invalid = [fid for fid in set(found) if fid not in valid_ids]
    return invalid


def validate_technique_ids(text, valid_techniques):
    """
    Extract T####.### ATT&CK IDs and verify each exists in valid_techniques.
    Returns list of invalid IDs found.
    Deterministic — does not call any API.
    """
    # Match T followed by 4 digits, optionally .3digits
    found = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)
    invalid = [tid for tid in set(found) if tid not in valid_techniques]
    return invalid


def validate_numeric_claims(text, data):
    """
    Validate key numeric claims in the report text against approved data.
    Returns list of (claim_description, expected, found_in_text) tuples for violations.
    Deterministic — does not call any API.

    Checks:
    - Total finding count (exact number)
    - Total technique count
    Note: Does NOT reject all numbers — only checks specific verifiable facts.
    Known limitation: Cannot catch all possible numeric fabrications.
    """
    violations = []
    total_findings = len(data.get("findings", []))
    total_techniques = len(data.get("attack_mapping", []))

    # Check that the number of findings cited is not inflated beyond what exists
    # Look for patterns like "N findings" or "N documented findings"
    finding_count_matches = re.findall(
        r"(\d+)\s+(?:documented\s+)?findings?",
        text,
        re.IGNORECASE,
    )
    for match in finding_count_matches:
        stated = int(match)
        if stated != total_findings:
            violations.append((
                "Finding count mismatch",
                f"expected {total_findings}",
                f"report states {stated}",
            ))

    # Check technique count claims
    tech_count_matches = re.findall(
        r"(\d+)\s+(?:unique\s+)?(?:ATT&CK\s+)?techniques?",
        text,
        re.IGNORECASE,
    )
    for match in tech_count_matches:
        stated = int(match)
        if stated > total_techniques + 2:  # allow small rounding differences
            violations.append((
                "Technique count likely overstated",
                f"expected ~{total_techniques}",
                f"report states {stated}",
            ))

    return violations


def validate_status_labels(text, data):
    """
    Check that candidate/inconclusive findings are not mislabelled as confirmed.
    Returns list of finding IDs that appear to be overstated.
    Known limitation: Natural language heuristic; may miss subtle phrasing.
    """
    issues = []
    for f in data.get("findings", []):
        fid = f["finding_id"]
        status = f.get("status", "")
        if status in ("candidate", "inconclusive"):
            # Search for the finding ID appearing with confirmed language nearby
            # Simple heuristic: within 100 chars of the finding ID
            pattern = re.compile(rf"{re.escape(fid)}.{{0,100}}", re.DOTALL)
            for m in pattern.finditer(text):
                snippet = m.group(0).lower()
                confirmed_words = ["confirmed", "proven", "established", "verified breach", "compromised"]
                if any(w in snippet for w in confirmed_words):
                    issues.append(f"{fid} (status={status}) appears near confirmed language")
                    break
    return issues


def validate_report(text, data):
    """
    Run all validation checks on the generated report text.
    Returns (passed: bool, reasons: list[str]).
    """
    reasons = []

    # Check required header
    if not text.strip().startswith("# AI-generated draft"):
        reasons.append("Missing required header: '# AI-generated draft - requires human review'")

    # Validate finding references
    valid_ids = [f["finding_id"] for f in data.get("findings", [])]
    invalid_fids = validate_finding_refs(text, valid_ids)
    if invalid_fids:
        reasons.append(f"Invented finding IDs: {invalid_fids}")

    # Validate technique IDs
    valid_tids = [m["technique_id"] for m in data.get("attack_mapping", [])]
    invalid_tids = validate_technique_ids(text, valid_tids)
    if invalid_tids:
        reasons.append(f"Unmapped technique IDs: {invalid_tids}")

    # Validate numeric claims
    numeric_violations = validate_numeric_claims(text, data)
    for desc, expected, found in numeric_violations:
        reasons.append(f"Numeric claim issue — {desc}: {expected}, but {found}")

    # Validate status labels
    status_issues = validate_status_labels(text, data)
    for issue in status_issues:
        reasons.append(f"Status label issue: {issue}")

    passed = len(reasons) == 0
    return passed, reasons


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        print("[!] GEMINI_API_KEY is not set. Skipping AI report generation.")
        print("    To generate: set GEMINI_API_KEY=<your_key> then re-run this script.")
        print("    The project works normally without this optional feature.")
        sys.exit(0)

    # Load approved data
    print("[+] Loading approved project data...")
    try:
        data = load_approved_data()
    except Exception as e:
        print(f"[-] ERROR loading data: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Findings: {len(data.get('findings', []))}")
    print(f"[+] ATT&CK mappings: {len(data.get('attack_mapping', []))}")

    # Import SDK
    try:
        import google.generativeai as genai
    except ImportError:
        print("[-] google-generativeai not installed.", file=sys.stderr)
        print("    Install: pip install google-generativeai", file=sys.stderr)
        sys.exit(1)

    # Initialize client
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(MODEL_NAME)
    except Exception as e:
        err_msg = str(e)
        # Never log the API key itself
        if api_key in err_msg:
            err_msg = err_msg.replace(api_key, "<REDACTED>")
        print(f"[-] ERROR initializing Gemini client: {err_msg}", file=sys.stderr)
        sys.exit(1)

    # Build prompt and call API
    print(f"[+] Calling Gemini API (model: {MODEL_NAME})...")
    prompt = build_prompt(data)
    generated_text = None
    try:
        response = model.generate_content(prompt)
        generated_text = response.text
        print(f"[+] Received {len(generated_text)} characters from model")
    except Exception as e:
        err_msg = str(e)
        if api_key in err_msg:
            err_msg = err_msg.replace(api_key, "<REDACTED>")
        print(f"[-] ERROR calling Gemini API: {err_msg}", file=sys.stderr)
        print("    Check your API key, network connectivity, and quota.", file=sys.stderr)
        sys.exit(1)

    if not generated_text:
        print("[-] ERROR: Model returned empty response", file=sys.stderr)
        sys.exit(1)

    # Validate output
    print("[+] Validating generated report...")
    passed, reasons = validate_report(generated_text, data)

    if passed:
        print("[+] Validation PASSED — writing accepted report")
        REPORT_ACCEPTED.parent.mkdir(exist_ok=True)
        with open(REPORT_ACCEPTED, "w", encoding="utf-8") as f:
            f.write(generated_text)
        print(f"[+] Written: {REPORT_ACCEPTED}")
        print("[DONE] AI report draft accepted. HUMAN REVIEW IS REQUIRED before use.")
    else:
        print(f"[-] Validation FAILED — {len(reasons)} issues:")
        for r in reasons:
            print(f"    - {r}")
        print("[!] Saving rejected draft for review")
        REPORT_REJECTED.parent.mkdir(exist_ok=True)
        rejection_header = "<!-- REJECTED: Validation failed — do not use without correction -->\n"
        rejection_detail = "\n".join(f"<!-- ISSUE: {r} -->" for r in reasons)
        with open(REPORT_REJECTED, "w", encoding="utf-8") as f:
            f.write(rejection_header + rejection_detail + "\n\n" + generated_text)
        print(f"[!] Written: {REPORT_REJECTED}")
        print("    The accepted report has NOT been modified.")
        sys.exit(1)


if __name__ == "__main__":
    main()

