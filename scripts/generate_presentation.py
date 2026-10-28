#!/usr/bin/env python3
"""
generate_presentation.py — Windows Threat Hunting System
Part F: Six-slide PowerPoint presentation draft.

Generates report/presentation.pptx using data from the project outputs.
This deck is explicitly labelled as a DRAFT for human editing.

Usage:
    python scripts/generate_presentation.py

Requires: python-pptx (pip install python-pptx)
"""

import csv
import json
import sys
from pathlib import Path

try:
    from pptx import Presentation
    from pptx.util import Inches, Pt, Emu
    from pptx.dml.color import RGBColor
    from pptx.enum.text import PP_ALIGN
except ImportError:
    print("[-] python-pptx not installed. Run: pip install python-pptx", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent
PROCESSED_JSON = ROOT / "outputs" / "processed_data.json"
EVAL_JSON      = ROOT / "outputs" / "evaluation.json"
ATTACK_CSV     = ROOT / "outputs" / "attack_mapping.csv"
FINDINGS_CSV   = ROOT / "outputs" / "findings.csv"
OUT_PPTX       = ROOT / "report" / "presentation.pptx"

# Theme colours
C_DARK   = RGBColor(0x0a, 0x0e, 0x1a)   # bg-primary
C_CARD   = RGBColor(0x0f, 0x16, 0x28)   # bg-card
C_BLUE   = RGBColor(0x3b, 0x82, 0xf6)
C_CYAN   = RGBColor(0x06, 0xb6, 0xd4)
C_GREEN  = RGBColor(0x10, 0xb9, 0x81)
C_YELLOW = RGBColor(0xf5, 0x9e, 0x0b)
C_RED    = RGBColor(0xef, 0x44, 0x44)
C_WHITE  = RGBColor(0xe8, 0xed, 0xf5)
C_GREY   = RGBColor(0x94, 0xa3, 0xb8)


def load_project_data():
    data = {}
    if PROCESSED_JSON.exists():
        with open(PROCESSED_JSON, encoding="utf-8") as f:
            data["processed"] = json.load(f)
    else:
        data["processed"] = {"metadata": {}, "findings": [], "attack_mapping": []}

    if EVAL_JSON.exists():
        with open(EVAL_JSON, encoding="utf-8") as f:
            data["evaluation"] = json.load(f)
    else:
        data["evaluation"] = {"metadata": {}, "samples": [], "limitations": []}

    if ATTACK_CSV.exists():
        rows = []
        with open(ATTACK_CSV, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                rows.append(row)
        data["attack_rows"] = rows
    else:
        data["attack_rows"] = []

    if FINDINGS_CSV.exists():
        rows = []
        with open(FINDINGS_CSV, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                rows.append(row)
        data["findings_rows"] = rows
    else:
        data["findings_rows"] = []

    return data


def _set_bg(slide, prs, color):
    """Set slide background to a solid colour."""
    fill = slide.background.fill
    fill.solid()
    fill.fore_color.rgb = color


def _add_title_box(slide, text, left, top, width, height,
                   font_size=28, bold=True, color=C_WHITE, align=PP_ALIGN.LEFT):
    from pptx.util import Pt
    txb = slide.shapes.add_textbox(left, top, width, height)
    tf  = txb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.alignment = align
    run = p.add_run()
    run.text = text
    run.font.bold = bold
    run.font.size = Pt(font_size)
    run.font.color.rgb = color
    return txb


def _add_body_box(slide, lines, left, top, width, height, font_size=13, color=C_GREY):
    txb = slide.shapes.add_textbox(left, top, width, height)
    tf  = txb.text_frame
    tf.word_wrap = True
    first = True
    for line in lines:
        if first:
            p = tf.paragraphs[0]
            first = False
        else:
            p = tf.add_paragraph()
        run = p.add_run()
        run.text = str(line)
        run.font.size = Pt(font_size)
        run.font.color.rgb = color
    return txb


def _add_accent_bar(slide, top, color=C_BLUE):
    """Thin accent bar across the top of a slide."""
    from pptx.util import Inches, Emu
    bar = slide.shapes.add_shape(
        1,  # MSO_SHAPE_TYPE.RECTANGLE
        Inches(0), top, Inches(10), Emu(60000)
    )
    bar.fill.solid()
    bar.fill.fore_color.rgb = color
    bar.line.fill.background()


def build_presentation(data):
    prs = Presentation()
    prs.slide_width  = Inches(10)
    prs.slide_height = Inches(7.5)

    # Use blank layout
    blank_layout = prs.slide_layouts[6]

    meta     = data["processed"].get("metadata", {})
    findings = data["findings_rows"]
    attack   = data["attack_rows"]
    eval_m   = data["evaluation"].get("metadata", {})
    samples  = data["evaluation"].get("samples", [])
    evtx     = meta.get("evtx_files", [
        "babyshark_mimikatz_powershell.evtx",
        "CA_sysmon_hashdump_cmd_meterpreter.evtx",
        "Exec_sysmon_meterpreter_reversetcp_msipackage.evtx",
        "sysmon_10_11_lsass_memdump.evtx",
        "sysmon_local_account_creation_and_added_admingroup_12_13.evtx",
        "temp_scheduled_task_4698_4699.evtx",
    ])

    # ── Slide 1: Title & Scope ──────────────────────────────────────────────
    sl1 = prs.slides.add_slide(blank_layout)
    _set_bg(sl1, prs, C_DARK)
    _add_accent_bar(sl1, Inches(0), C_CYAN)

    _add_title_box(sl1, "DRAFT — REQUIRES HUMAN REVIEW",
                   Inches(0.5), Inches(0.3), Inches(9), Inches(0.5),
                   font_size=10, bold=True, color=C_YELLOW)

    _add_title_box(sl1, "Windows Threat Hunting System",
                   Inches(0.5), Inches(1.0), Inches(9), Inches(1.2),
                   font_size=34, bold=True, color=C_WHITE)

    _add_title_box(sl1, "Using Hayabusa and MITRE ATT&CK",
                   Inches(0.5), Inches(2.0), Inches(9), Inches(0.8),
                   font_size=20, bold=False, color=C_CYAN)

    scope_lines = [
        f"Dataset:  {len(evtx)} EVTX attack samples (EVTX-ATTACK-SAMPLES — public domain)",
        f"Tool:     Hayabusa {meta.get('hayabusa_version', 'v4.2.0')}  |  Rules: Sigma community",
        f"Findings: {len(findings)} documented (derived from {meta.get('total_detections', 94)} alerts)",
        "Analysis: 2026-10-01 UTC",
    ]
    _add_body_box(sl1, scope_lines, Inches(0.5), Inches(3.0), Inches(9), Inches(1.8),
                  font_size=14, color=C_GREY)

    _add_body_box(sl1,
                  ["LIMITATIONS: 6 small attack-only samples. No benign baseline. Not a benchmark."],
                  Inches(0.5), Inches(5.0), Inches(9), Inches(0.6),
                  font_size=11, color=C_YELLOW)

    # ── Slide 2: Data & Tools ───────────────────────────────────────────────
    sl2 = prs.slides.add_slide(blank_layout)
    _set_bg(sl2, prs, C_DARK)
    _add_accent_bar(sl2, Inches(0), C_BLUE)

    _add_title_box(sl2, "Data & Tools",
                   Inches(0.5), Inches(0.3), Inches(9), Inches(0.8),
                   font_size=26, color=C_WHITE)

    _add_title_box(sl2, "EVTX Sample Inventory (6 files)",
                   Inches(0.5), Inches(1.2), Inches(4.5), Inches(0.5),
                   font_size=13, bold=True, color=C_CYAN)
    evtx_lines = [f"• {f}" for f in evtx]
    _add_body_box(sl2, evtx_lines, Inches(0.5), Inches(1.7), Inches(4.5), Inches(3.0),
                  font_size=10, color=C_GREY)

    _add_title_box(sl2, "Tools & Provenance",
                   Inches(5.2), Inches(1.2), Inches(4.3), Inches(0.5),
                   font_size=13, bold=True, color=C_CYAN)
    tool_lines = [
        "Hayabusa v4.2.0 — dfir-timeline",
        "4,674 detection rules (Sigma + Hayabusa)",
        "Source: EVTX-ATTACK-SAMPLES (sbousseaden)",
        "License: Public domain / CC0",
        "Processing: 5.404s for 6 files (408 KB)",
        "73 events → 94 total alerts",
    ]
    _add_body_box(sl2, tool_lines, Inches(5.2), Inches(1.7), Inches(4.3), Inches(2.5),
                  font_size=11, color=C_GREY)

    _add_body_box(sl2,
                  ["Data provenance: All EVTX files are publicly available attack samples. "
                   "No production logs. No personal data. Authorisation documented in docs/lab_setup.md."],
                  Inches(0.5), Inches(5.2), Inches(9), Inches(0.8),
                  font_size=10, color=C_YELLOW)

    # ── Slide 3: Pipeline ───────────────────────────────────────────────────
    sl3 = prs.slides.add_slide(blank_layout)
    _set_bg(sl3, prs, C_DARK)
    _add_accent_bar(sl3, Inches(0), C_GREEN)

    _add_title_box(sl3, "Processing Pipeline",
                   Inches(0.5), Inches(0.3), Inches(9), Inches(0.8),
                   font_size=26, color=C_WHITE)

    stages = [
        ("1. Data Acquisition",  "6 EVTX samples → data/raw/working_copy/"),
        ("2. Hayabusa Scan",     "dfir-timeline → outputs/raw/hayabusa_real_output.csv (94 alerts)"),
        ("3. Processing",        "scripts/process_results.py → findings.csv, shortlist.csv,\n"
                                 "timeline.csv, attack_mapping.csv, processed_data.json"),
        ("4. Evaluation",        "scripts/evaluate_detection.py → evaluation.csv, evaluation.json"),
        ("5. Navigator Export",  "scripts/export_navigator_layer.py → attack_navigator_layer.json"),
        ("6. Dashboard",         "src/summary.html — live refresh (HTTP polling every 5s),\n"
                                 "Evaluation tab, download buttons"),
        ("7. Optional AI Report","scripts/generate_ai_report.py — requires GEMINI_API_KEY"),
    ]
    y = Inches(1.3)
    for label, detail in stages:
        _add_title_box(sl3, label, Inches(0.5), y, Inches(2.8), Inches(0.4),
                       font_size=11, bold=True, color=C_GREEN)
        _add_body_box(sl3, [detail], Inches(3.4), y, Inches(6.3), Inches(0.5),
                      font_size=10, color=C_GREY)
        y += Inches(0.72)

    # ── Slide 4: Findings & ATT&CK ──────────────────────────────────────────
    sl4 = prs.slides.add_slide(blank_layout)
    _set_bg(sl4, prs, C_DARK)
    _add_accent_bar(sl4, Inches(0), C_RED)

    _add_title_box(sl4, "Findings & ATT&CK Mapping",
                   Inches(0.5), Inches(0.3), Inches(9), Inches(0.8),
                   font_size=26, color=C_WHITE)

    # Status breakdown
    statuses = {}
    for f in findings:
        s = f.get("status", "unknown")
        statuses[s] = statuses.get(s, 0) + 1

    stat_lines = [
        f"Total findings: {len(findings)}",
        f"  validated_observation: {statuses.get('validated_observation', 0)}",
        f"  candidate:             {statuses.get('candidate', 0)}",
        f"  inconclusive:          {statuses.get('inconclusive', 0)}",
    ]
    _add_title_box(sl4, "Finding Status Breakdown",
                   Inches(0.5), Inches(1.2), Inches(4), Inches(0.5),
                   font_size=13, bold=True, color=C_RED)
    _add_body_box(sl4, stat_lines, Inches(0.5), Inches(1.7), Inches(4), Inches(1.5),
                  font_size=12, color=C_GREY)

    # ATT&CK mapping
    _add_title_box(sl4, "ATT&CK Techniques (from attack_mapping.csv)",
                   Inches(4.8), Inches(1.2), Inches(4.8), Inches(0.5),
                   font_size=13, bold=True, color=C_RED)
    attack_lines = []
    for row in attack:
        attack_lines.append(
            f"{row.get('technique_id','')} — {row.get('technique_name','')} "
            f"[{row.get('finding_id','')}] ({row.get('confidence','')})"
        )
    if not attack_lines:
        attack_lines = ["No ATT&CK mappings generated yet. Run scripts/process_results.py."]
    _add_body_box(sl4, attack_lines, Inches(4.8), Inches(1.7), Inches(4.8), Inches(2.5),
                  font_size=10, color=C_GREY)

    # Sample findings table (up to 4)
    _add_title_box(sl4, "Sample Findings",
                   Inches(0.5), Inches(3.3), Inches(9), Inches(0.4),
                   font_size=13, bold=True, color=C_WHITE)
    sample_lines = []
    for f in findings[:6]:
        sample_lines.append(
            f"{f.get('finding_id','')}  {f.get('status','')}  "
            f"{f.get('alert_name','')[:60]}  [{f.get('severity','')}]"
        )
    _add_body_box(sl4, sample_lines, Inches(0.5), Inches(3.7), Inches(9), Inches(2.5),
                  font_size=9, color=C_GREY)

    # ── Slide 5: Evaluation & Limitations ──────────────────────────────────
    sl5 = prs.slides.add_slide(blank_layout)
    _set_bg(sl5, prs, C_DARK)
    _add_accent_bar(sl5, Inches(0), C_YELLOW)

    _add_title_box(sl5, "Detection Evaluation & Limitations",
                   Inches(0.5), Inches(0.3), Inches(9), Inches(0.8),
                   font_size=26, color=C_WHITE)

    hits      = eval_m.get("samples_with_relevant_alerts", "—")
    missed    = eval_m.get("samples_missed", "—")
    uncertain = eval_m.get("samples_uncertain", "—")
    proc_t    = eval_m.get("processing_time_seconds", "—")

    eval_lines = [
        f"Total samples evaluated:  {eval_m.get('total_samples', 6)}",
        f"Samples with alerts (hit): {hits}",
        f"Samples missed:            {missed}",
        f"Samples uncertain:         {uncertain}",
        f"Hayabusa processing time:  {proc_t}s",
        "",
        "Note: attribution inferred from hostname patterns.",
        "NOT a precision/recall/benchmark measurement.",
    ]
    _add_title_box(sl5, "Evaluation Metrics (approximate)",
                   Inches(0.5), Inches(1.2), Inches(4.5), Inches(0.5),
                   font_size=13, bold=True, color=C_YELLOW)
    _add_body_box(sl5, eval_lines, Inches(0.5), Inches(1.7), Inches(4.5), Inches(3.5),
                  font_size=11, color=C_GREY)

    lim_lines = [
        "• 6 small attack-only EVTX samples",
        "• No benign baseline — cannot compute FPR",
        "• Results ≠ production detection performance",
        "• Hostname→EVTX attribution is approximate",
        "• Rule-based detection only (Sigma/Hayabusa)",
        "• No network telemetry available",
        "• Script block logging not in sample",
        "• Batch file content not captured (F-04)",
    ]
    _add_title_box(sl5, "Key Limitations",
                   Inches(5.2), Inches(1.2), Inches(4.4), Inches(0.5),
                   font_size=13, bold=True, color=C_YELLOW)
    _add_body_box(sl5, lim_lines, Inches(5.2), Inches(1.7), Inches(4.4), Inches(3.5),
                  font_size=11, color=C_GREY)

    _add_body_box(sl5,
                  ["Test coverage: 111 unit tests (27/27 validation checks PASS). "
                   "Selenium browser tests: NOT TESTED (ChromeDriver not installed). "
                   "Live Gemini API: NOT TESTED (key not set)."],
                  Inches(0.5), Inches(5.5), Inches(9), Inches(0.8),
                  font_size=10, color=C_YELLOW)

    # ── Slide 6: Dashboard Demonstration ───────────────────────────────────
    sl6 = prs.slides.add_slide(blank_layout)
    _set_bg(sl6, prs, C_DARK)
    _add_accent_bar(sl6, Inches(0), C_CYAN)

    _add_title_box(sl6, "Dashboard & Deliverables",
                   Inches(0.5), Inches(0.3), Inches(9), Inches(0.8),
                   font_size=26, color=C_WHITE)

    dash_lines = [
        "src/summary.html — interactive threat hunting dashboard",
        "",
        "Features implemented:",
        "  • Tab navigation: Findings tab + Evaluation tab",
        "  • Live refresh: polls outputs/processed_data.json every 5s (HTTP only)",
        "  • Compares run_timestamp to avoid redundant re-renders",
        "  • Pause/Resume toggle — stops/restarts polling",
        "  • Live status indicator: 'Live: last updated HH:MM:SS'",
        "  • Stale data warning on fetch failure",
        "  • file:// mode explained with clear fallback",
        "  • Download ATT&CK Navigator Layer button",
        "  • Download Findings CSV button (contract headers preserved)",
        "  • Evaluation tab: per-sample hit/miss/uncertain + limitations",
        "",
        "To serve: python -m http.server 8080",
        "Then open: http://localhost:8080/src/summary.html",
    ]
    _add_body_box(sl6, dash_lines, Inches(0.5), Inches(1.2), Inches(5.5), Inches(5.5),
                  font_size=10, color=C_GREY)

    deliverable_lines = [
        "Deliverables generated:",
        "  outputs/evaluation.csv / .json",
        "  outputs/attack_navigator_layer.json",
        "  scripts/validate_outputs.py (27 checks)",
        "  scripts/evaluate_detection.py",
        "  scripts/export_navigator_layer.py",
        "  scripts/generate_ai_report.py (optional)",
        "  tests/ — 111 unit tests",
        "  report/presentation.pptx (this file)",
        "  report/final_report.md (updated)",
        "  docs/architecture.md (new)",
        "",
        "⚠ No screenshots available",
        "  (file:// access; browser tests NOT TESTED)",
        "",
        "DRAFT — requires human review and editing",
    ]
    _add_body_box(sl6, deliverable_lines, Inches(6.2), Inches(1.2), Inches(3.5), Inches(5.5),
                  font_size=10, color=C_GREY)

    return prs


def main():
    print("[+] Loading project data...")
    data = load_project_data()
    print(f"[+] Findings: {len(data['findings_rows'])}, ATT&CK mappings: {len(data['attack_rows'])}")
    print(f"[+] Evaluation samples: {len(data['evaluation'].get('samples', []))}")

    print("[+] Building presentation (6 slides)...")
    prs = build_presentation(data)

    slide_count = len(prs.slides)
    if slide_count != 6:
        print(f"[-] ERROR: Expected 6 slides, got {slide_count}", file=sys.stderr)
        sys.exit(1)

    OUT_PPTX.parent.mkdir(exist_ok=True)
    prs.save(OUT_PPTX)
    print(f"[+] Written: {OUT_PPTX}")
    print(f"[+] Slides: {slide_count}")
    print("[DONE] Presentation generated. DRAFT — requires human editing.")


if __name__ == "__main__":
    main()

