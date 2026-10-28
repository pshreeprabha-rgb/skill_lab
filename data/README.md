# Data Directory

## Dataset Provenance & Authorization

All event log data in this project consists strictly of **authorized, publicly available Windows Event Log samples** from:

1. **EVTX-ATTACK-SAMPLES** — https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES (Public Domain / CC0)
2. **Hayabusa Sample EVTX** — https://github.com/Yamato-Security/hayabusa-sample-evtx (Yamato Security / MIT License)

No proprietary logs, production data, personal identity information, or unauthorized enterprise logs are included.

## Selected Genuine EVTX Datasets

Six genuine `.evtx` files demonstrating diverse adversary tactics were acquired from upstream revision `4ceed2f4706daf601c212a8f91c113dd85349a2c`:

| ID | Filename | Host | Events | Channel | Scenario / Technique |
|---|---|---|---|---|---|
| **D1** | `babyshark_mimikatz_powershell.evtx` | `IEWIN7` | 33 | Sysmon | BabyShark PowerShell LSASS credential access (`T1059.001`, `T1003.001`) |
| **D2** | `CA_sysmon_hashdump_cmd_meterpreter.evtx` | `IEWIN7` | 9 | Sysmon | Meterpreter hashdump & remote thread injection (`T1003.001`, `T1055`) |
| **D3** | `Exec_sysmon_meterpreter_reversetcp_msipackage.evtx` | `IEWIN7` | 8 | Sysmon | AlwaysInstallElevated MSI installer execution (`T1548.002`, `T1059.003`, `T1033`) |
| **D4** | `sysmon_10_11_lsass_memdump.evtx` | `PC04.example.corp` | 4 | Sysmon | ProcDump & Task Manager LSASS memory dump files (`T1003.001`) |
| **D5** | `temp_scheduled_task_4698_4699.evtx` | `WIN-77LTAPHIQ1R.example.corp` | 2 | Security | Ephemeral scheduled task creation & rapid deletion (`T1053.005`, `T1070.004`) |
| **D6** | `UACME_59_Sysmon.evtx` | `LAPTOP-JU4M3I0E` | 7 | Sysmon | UAC bypass using auto-elevating Taskmgr / UACME 59 (`T1548.002`) |

Total events processed across 6 files: **63 raw event records**, yielding **85 Hayabusa alerts** across High, Medium, Low, and Informational severities.

## File Hashes (SHA-256)

- `babyshark_mimikatz_powershell.evtx`: `3747c33a60a32142bf4e30bf023f155b2c0d6e7a018bce8b7bafbd5aa7ec109c`
- `CA_sysmon_hashdump_cmd_meterpreter.evtx`: `897206ca4c3c427753fde880970048494cd5a99be9aaba6154b4e3ac499e24c9`
- `Exec_sysmon_meterpreter_reversetcp_msipackage.evtx`: `328ec1b4b6c531af991a2de2221900ec93db1853f7446f61c7e3c9bf9bf052e3`
- `sysmon_10_11_lsass_memdump.evtx`: `915f0859251552b6c33efc32f6184d2c25419c5859852124a7f14ed6ec1a3723`
- `temp_scheduled_task_4698_4699.evtx`: `a7decf0fbabc340e37de7e7c39fddd5398a7106a4f6acded0ea1d2ffa6bf8b70`
- `UACME_59_Sysmon.evtx`: `1de3775180143fd5d956bae48f572367534ae8c10f6ffbe98dd4b4e0e47e0fa1`

## Reproduction

To reproduce the analysis from scratch:
1. Place the genuine `.evtx` files into `data/raw/` (gitignored).
2. Run `powershell -ExecutionPolicy Bypass -File scripts/run_hayabusa.ps1`.
3. Run `python scripts/process_results.py`.
4. Launch the dashboard via `python scripts/serve_dashboard.py`.
