# Forensic Dashboard Visual Evidence & Screenshots

This directory contains automated, genuine PNG screenshots captured directly from the live dashboard via Selenium headless Chrome running against `http://localhost:8080/src/summary.html`.

---

## Screenshot Inventory & Captions

### 1. `01_overview.png`
* **Caption:** Full dashboard overview displaying top metrics cards (85 Raw Alerts Processed, 19 Investigated Findings, 8 Mapped ATT&CK Techniques across 6 Tactics, 4 Analyzed Target Hosts). Also visible: the data honesty banner indicating live telemetry ingestion from `/outputs/processed_data.json` with pipeline generation timestamp.
* **Resolution:** 1440 x 900 PNG
* **File Size:** ~125 KB

---

### 2. `02_filtered_findings.png`
* **Caption:** Investigated findings table filtered dynamically by query string `"lsass"`, demonstrating responsive multi-column substring filtering against rule title, evidence details, and target hosts.
* **Resolution:** 1440 x 900 PNG
* **File Size:** ~119 KB

---

### 3. `03_evidence_modal.png`
* **Caption:** Forensic Detail Modal opened for Finding `F-01` (`LSASS Process Memory Dump Files`). Demonstrates deep telemetry traceability: EventID 11 (Sysmon), Target Computer `PC04.example.corp`, Raw Details showing `procdump.exe` writing dump file `lsass.exe_190317_120941.dmp`, Analyst Interpretation, Benign Hypotheses, Forensic Limitations, Recommended Next Steps, and mapped MITRE ATT&CK technique `T1003.001`.
* **Resolution:** 1440 x 900 PNG
* **File Size:** ~146 KB

---

### 4. `04_timeline.png`
* **Caption:** Chronological Forensic Timeline tab rendering all 85 event nodes with severity-coded status dots (High = Red, Med = Amber, Low = Blue, Info = Slate), clickable finding badges, host labels, and detailed event summaries.
* **Resolution:** 1440 x 900 PNG
* **File Size:** ~105 KB

---

## Automated Verification

These screenshots are captured programmatically by running:
```bash
python -m unittest tests/test_dashboard_browser.py -v
```
