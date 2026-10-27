# Member 2 — Lab Setup and Log Acquisition Handoff

## Tool
- Hayabusa version: v4.2.0 (Autumn Release)
- Validation command: `hayabusa.exe log-metrics -f <EVTX_PATH> -o <OUTPUT_CSV> -O`

## Selected EVTX
- Filename: `DE_RDP_Tunneling_4624.evtx`
- Local working copy: `local-data/DE_RDP_Tunneling_4624/WORKING/DE_RDP_Tunneling_4624.evtx`
- Source archive member: `hayabusa-demo-main/EVTX-ATTACK-SAMPLES/Command and Control/DE_RDP_Tunneling_4624.evtx`
- Archive member path: `hayabusa-demo-main/EVTX-ATTACK-SAMPLES/Command and Control/DE_RDP_Tunneling_4624.evtx`
- Original upstream repository and acquisition revision: unknown; not independently verified
- SHA-256: `2668d3d7f0505ad453affcb9e2b7206617cf1ec1e5a212bd8f191eb8523c0ab1`
- File size: 69,632 bytes
- Hayabusa log-metrics result: 18 events
- First timestamp: `2019-02-13T15:14:52.409734Z`
- Last timestamp: `2019-02-13T15:31:31.556812Z`
- Reported computer: `PC02.example.corp`
- Reported channel/provider: `Sec` (exact channel not independently confirmed)

## Validation status and limitations
- Local file hash matches the same member inside the downloaded ZIP, establishing byte-level identity between those copies only.
- Hayabusa v4.2.0 successfully processed the file with `log-metrics`.
- This confirms basic readability, not full event-level correctness or compromise.
- Filename suggests RDP tunneling, but scenario and ATT&CK mapping are not independently verified.
- Upstream archive authenticity and file-level redistribution permission remain pending.
- Raw EVTX and generated output remain local; do not commit them to Git without approval.

## Handoff to Member 3
- Record the exact Hayabusa version and reproducible run command in the runbook.
- Review the generated `log_metrics.csv` and perform any required event-level checks.
- Confirm the event channel and timestamp/time-zone assumptions before final reporting.


## Pinned reference note
Current upstream HEAD revisions checked 2026-10-27 (for reproducible future acquisition only):
- Hayabusa Sample EVTX: `0845333ecb4afcf64c55c6e10946383f168f308c`
- EVTX-ATTACK-SAMPLES: `4ceed2f4706daf601c212a8f91c113dd85349a2c`

These do not prove the original revision of the local ZIP. Do not claim the selected file came from either revision unless acquisition evidence establishes that link.
