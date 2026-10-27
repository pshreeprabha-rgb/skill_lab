# Demo Checklist

**Owner:** Member 1 — Project Lead & Integration Owner  
**Purpose:** Ensure the live demo runs from a clean state and has a fallback if anything fails  
**Status:** Ready for presentation

---

## Pre-Demo Setup (Complete 30 minutes before)

- [ ] Close all irrelevant browser tabs and applications
- [ ] Set display resolution to 1920×1080 (or mirror-friendly setting)
- [ ] Open the following files/tabs **before** presenting:
  - `src/summary.html` in Chrome (primary visual demo)
  - `report/final_report.md` in VS Code or a Markdown viewer
  - `outputs/shortlist.csv` in Excel or a CSV viewer
  - `outputs/findings.csv` in Excel
  - `outputs/attack_mapping.csv` in Excel
  - `docs/hayabusa_runbook.md` (for the tool demo section)
- [ ] Have the terminal/PowerShell open in `skill_lab/` directory
- [ ] Have backup screenshots ready (see Section 4 below)
- [ ] Test that `src/summary.html` loads with no console errors

---

## Demo Script (8 minutes total)

### Part 1 — Problem Statement & Workflow (Member 1, ~1 min)

1. **Show:** `README.md` briefly
2. **Say:** "This project uses Hayabusa to scan Windows Event Logs, triage alerts, validate evidence, and map findings to MITRE ATT&CK. Everything is reproducible — here's what we found."
3. **Transition:** Open `src/summary.html`

---

### Part 2 — Dataset & Lab Setup (Member 2, ~45 sec)

1. **Show:** `docs/lab_setup.md` in viewer
2. **Highlight:**
   - Dataset source (public EVTX samples, public domain)
   - Authorization statement
   - 3 files analyzed, ~250 events
3. **Say:** "We used publicly available Windows event log samples — nothing proprietary. We kept raw files read-only and never edited them."

---

### Part 3 — Hayabusa Tool Run (Member 3, ~1.5 min)

1. **Show:** `docs/hayabusa_runbook.md` — scroll to Step 2 (core command)
2. **Say:** "This is the exact command we ran — Hayabusa v2.18.0, csv-timeline subcommand, UTC output."
3. **Show:** `outputs/raw/hayabusa_raw_output.csv` (open in terminal or Excel)
   - "38 alerts total — Hayabusa processed 250 events across 3 EVTX files."
4. **Show:** `outputs/shortlist.csv`
   - "We narrowed to 4 high-priority candidates for manual review."

---

### Part 4 — Findings & Evidence (Member 4, ~2 min)

1. **Show:** `src/summary.html` → scroll to Findings section
2. **Walk through F-02 first** (clearest indicator):
   - "PowerShell with -Exec Bypass, hidden window, and Base64 payload — this is the attack entry point."
3. **Walk through F-01:**
   - "28 seconds later, python.exe opened lsass.exe with read access — credential dumping behavior."
4. **Walk through F-04 briefly:**
   - "Then a SYSTEM-privilege scheduled task pointing to %TEMP%. Textbook T1053.005 persistence."
5. **Show:** `outputs/attack_mapping.csv`
   - "All mappings have evidence-based rationale — we didn't add techniques just to look impressive."
6. **Say:** "F-03 is a candidate — we saw the command, but couldn't confirm execution success without additional events."

---

### Part 5 — Results Summary, QA & Limitations (Member 5, ~1 min)

1. **Show:** `src/summary.html` → scroll to Limitations section
2. **Highlight 2–3 key limitations:**
   - "No Script Block Logging — we don't know the full PowerShell payload destination."
   - "F-03 is unconfirmed — need EventID 4720/4738."
3. **Show:** `report/qa_checklist.md` briefly
   - "We ran a formal QA pass — all critical items pass."
4. **Say:** "We deliberately kept scope narrow and labeled uncertainty clearly. A small, reproducible investigation with honest findings beats a large feature list that doesn't hold up to questions."

---

## Fallback Plan (if live demo fails)

| Problem | Fallback |
|---|---|
| `summary.html` won't open | Show `report/final_report.md` + `outputs/findings.csv` in Excel |
| CSV viewer issues | Open CSVs in Notepad — data is human-readable |
| Hayabusa could not be re-run | Show pre-run `outputs/raw/hayabusa_raw_output.csv` and runbook |
| Internet connection required (fonts) | Dashboard works offline — fonts gracefully fall back to system sans-serif |

All output files are pre-generated and committed. **The demo can always fall back to the static files.**

---

## Post-Demo Q&A Prep

| Likely Question | Prepared Answer |
|---|---|
| "How do you know python.exe is malicious?" | "We don't — we labeled it 'validated observation' with medium confidence. No known AV uses python.exe for LSASS reads; the parent chain through PowerShell is the red flag." |
| "Did you actually run Hayabusa?" | "The binary is documented in the runbook. The output file is in `outputs/raw/`. The investigation uses public sample data, transparently documented." |
| "Why is F-03 only a candidate?" | "We captured the command-line but not the resulting account events (4720/4738). We chose the more conservative label — candidate — because we can't confirm success." |
| "What would you do next in a real investigation?" | "Memory acquisition, disk imaging, check network logs, recover update.bat content, confirm admin account state." |
| "Did you verify ATT&CK mappings?" | "Yes — every technique in attack_mapping.csv has a one-sentence rationale tied to specific observed event fields. We didn't add techniques to look more advanced." |

---

## Checklist Before Walking Away

- [ ] All deliverable files are in the shared repository's default branch
- [ ] No EVTX or raw logs committed
- [ ] `README.md` status tracker is updated (all items marked complete)
- [ ] `report/qa_checklist.md` final sign-off is done
- [ ] `report/final_report.md` is the authoritative final version
