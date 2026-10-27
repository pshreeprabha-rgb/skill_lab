# Team Integration Contract
Windows Threat Hunting System Using Hayabusa

Shared rules for deliverables, file formats, GitHub collaboration, and final integration.

---

## 1. Non-Negotiable Integration Rules
* **One owner per deliverable**: Others may review or help, but one person is responsible for submitting the final version and resolving comments.
* **Submit usable artifacts, not status messages**: Share the file, its path, a short description, and what is still missing[cite: 2]. "Almost done" is not a handoff[cite: 2].
* **Freeze shared formats early**: Agree on filenames, columns, timestamp format, status labels, and folder paths before analysis outputs are generated[cite: 2].
* **Keep raw evidence immutable**: Do not edit original EVTX files or overwrite raw Hayabusa output[cite: 2]. Work on copies and preserve provenance[cite: 2].
* **Every claim must point to evidence**: Alert output is a lead, not automatic proof of malicious activity[cite: 2].
* **No silent interface changes**: If a column, filename, function, command, or folder path changes, tell the team before merging and update the README/schema[cite: 2].
* **Small, reviewable changes**: Commit one logical change at a time; avoid huge commits containing unrelated files[cite: 2].
* **Never commit secrets or sensitive raw logs**: Do not push credentials, access tokens, private hostnames, personal data, or logs the team is not authorized to share[cite: 2].
* **One final source of truth**: The shared repository's default branch and the agreed final report folder are authoritative[cite: 2]. Personal copies are not final deliverables[cite: 2].
* **Stop scope creep**: A working pipeline, evidence-backed findings, reproducible documentation, and a clear report take priority over optional UI polish[cite: 2].

---

## 2. Canonical Repository and Folder Layout
Use this structure unless the team lead records an agreed change[cite: 2].

```text
hayabusa-threat-hunting/
├── README.md
├── .gitignore
├── docs/
│   ├── integration-contract.md
│   ├── lab_setup.md
│   ├── methodology.md
│   └── data_dictionary.md
├── data/
│   ├── README.md
│   └── sample/               # only approved, shareable sample data
├── outputs/
│   ├── raw/                  # generated outputs — do not hand-edit
│   ├── shortlist.csv
│   ├── findings.csv
│   ├── timeline.csv
│   └── attack_mapping.csv
├── src/                      # optional scripts/local summary interface
├── screenshots/              # genuine screenshots; redact sensitive details
└── report/
    ├── final_report.pdf
    ├── presentation.pptx
    ├── qa_checklist.md
    └── demo_checklist.md