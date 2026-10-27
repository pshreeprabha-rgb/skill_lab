
# Data Directory

## Authorization

All data in this project uses **publicly available, anonymized Windows Event Log samples** from:

1. **Hayabusa test corpus** — https://github.com/Yamato-Security/hayabusa (MIT licensed)
2. **EVTX-ATTACK-SAMPLES** — https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES (public domain / CC0)

No production logs, personal data, or logs from systems the team is not authorized to access are included.

## What Is Committed

The `data/sample/` directory contains **anonymized CSV representations** of the relevant Windows Event Log fields used in analysis. Full EVTX binary files are excluded from the repository (see `.gitignore`).

## Reproducing the Dataset

To reproduce the full EVTX dataset:
1. Download the EVTX-ATTACK-SAMPLES repository from GitHub
2. Select files corresponding to Event IDs 4688, 4698, and Sysmon event 10
3. Place them in `data/working_copy/` (gitignored)
4. Follow the runbook at `docs/hayabusa_runbook.md`

## Dataset Inventory

| Filename | Channel | Events | Coverage |
|---|---|---|---|
| `sample/events_4688.csv` | Security | ~150 | Process creation (simulated 2026-10-01) |
| `sample/events_4698.csv` | Security | ~20 | Scheduled task creation (2026-10-01) |
| `sample/events_sysmon10.csv` | Sysmon/Operational | ~80 | Process access events (2026-10-01) |
