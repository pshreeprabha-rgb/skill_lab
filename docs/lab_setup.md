# Member 2 — Lab Setup & Log Acquisition

## Status
Draft — repository sources identified; individual EVTX files have NOT yet been downloaded, parsed, or validated in this workspace. Do not describe the datasets as fully validated until the checks in this document are completed.

## Project purpose
Prepare authorized Windows Event Log (`.evtx`) input for the Hayabusa Windows Threat Hunting System. Hayabusa findings will later be normalized and reviewed; a finding or ATT&CK mapping is not, by itself, proof that a host was compromised.

## Proposed data sources

### Dataset 1 — Hayabusa Sample EVTX
- Repository: https://github.com/Yamato-Security/hayabusa-sample-evtx
- Download ZIP: https://github.com/Yamato-Security/hayabusa-sample-evtx/archive/refs/heads/main.zip
- Purpose stated by upstream: sample EVTX files for testing Hayabusa detection rules.
- Source notes: upstream README says the collection includes samples from DeepBlueCLI, EVTX-ATTACK-SAMPLES, EVTX-to-MITRE-Attack, and files created by Yamato Security.
- Caution: mixed upstream provenance; record the actual subfolder and original source for each selected file.

### Dataset 2 — EVTX-ATTACK-SAMPLES
- Repository: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- Download ZIP: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/archive/refs/heads/master.zip
- Purpose stated by upstream: Windows event samples associated with attack/post-exploitation techniques; ATT&CK mapping is at technique level, not procedure level.
- License shown by upstream: GPL-3.0. Review license obligations and project/institution requirements before redistributing files.
- Caution: attack-focused collection; it is not a complete balanced benign/malicious benchmark by itself.

## Local environment
- OS: Windows 11 (reported by project member; confirm exact edition/build on the machine used for analysis).
- Time zone: NOT YET VERIFIED. On Windows, check Settings > Time & language > Date & time; record the displayed time zone. Do not assume the EVTX timestamps use the local time zone.
- Hayabusa version: to be recorded by Member 3 after installation/verification.
- Prerequisites: coordinate exact release and command syntax with Member 3; do not guess command flags.

## Recommended local folder layout
Keep downloaded source archives and raw EVTX files outside Git unless redistribution is explicitly approved. Suggested local-only layout:

```text
local-data/
  dataset1_hayabusa_sample_evtx/
    ORIGINAL/       # untouched extracted source files
    WORKING/        # copies selected for analysis
  dataset2_evtx_attack_samples/
    ORIGINAL/
    WORKING/
```

The repository may contain documentation and inventory metadata, but do not commit raw EVTX files by default.

## Validation checklist
For each selected `.evtx` file:
1. Record exact filename, source repository, upstream subfolder, and source/license notes.
2. Preserve the original file; copy it to a working folder before analysis.
3. Record file size and calculate a SHA-256 hash for provenance.
4. Confirm it is readable by an approved EVTX parser/Hayabusa version; record errors instead of silently dropping files.
5. Extract the earliest and latest event timestamps using a suitable parser or Hayabusa output. Record timezone assumptions separately; do not infer the source timezone solely from a filename.
6. Record channel/log type and host label only when actually available. Use privacy-safe host labels.
7. Record any source-provided ATT&CK association and its granularity. Do not invent labels for files without metadata.
8. Include benign samples only when their benign status is supported by provenance or a documented test procedure.
9. Record all limitations and missing telemetry.
10. Ask the team lead before committing any raw log or file whose redistribution rights are unclear.

## Handoff to Member 3
Provide the exact local input directory, selected filenames, inventory CSV, time-zone caveats, parser/tool version, known parsing errors, and source/authorization note. Member 3 records the exact Hayabusa version and reproducible run command in `docs/hayabusa_runbook.md`.

## Current validation status
- Repository descriptions reviewed: YES.
- ZIP archives downloaded and extracted in this workspace: NO.
- Individual EVTX files parsed: NO.
- File-level timestamp coverage verified: NO.
- Benign/malicious labels validated: NO.
- Redistribution permissions assessed for every file: NO.

These are explicit gaps, not completed checks.
