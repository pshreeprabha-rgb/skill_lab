# Dataset Source and Authorization Note

## Scope
The project is a defensive Windows event-log analysis project. The listed repositories are public upstream sources; public availability does not automatically establish permission to redistribute every contained file.

## Source 1
- Name: Hayabusa Sample EVTX
- URL: https://github.com/Yamato-Security/hayabusa-sample-evtx
- Upstream purpose: sample EVTX files for testing Hayabusa detection rules.
- Provenance note: README describes samples from multiple upstream repositories as well as original Yamato Security samples.
- File-level license/redistribution review: PENDING.

## Source 2
- Name: EVTX-ATTACK-SAMPLES
- URL: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- Upstream purpose: Windows event samples associated with attack and post-exploitation techniques.
- Upstream license shown: GPL-3.0.
- File-level review and compliance with institution/team policy: PENDING.

## Handling rules
- Keep raw files outside the project Git repository by default.
- Preserve original files and use separate working copies.
- Do not include private logs, credentials, or unnecessary host/user identifiers.
- Do not claim a file is benign or malicious unless the label is supported by upstream metadata or a documented controlled test.
- Record source, license, file hash, file size, event time range, timezone assumptions, parser readability, and known gaps in `data/dataset_inventory.csv`.
- If redistribution permission is unclear, share the source URL and acquisition steps rather than the raw file.

## Approval status
This note documents candidate sources only. It is not a legal determination and does not claim that every file is approved for redistribution. Obtain team/institution approval before publishing raw data.
