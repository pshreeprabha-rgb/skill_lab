# Windows Threat Hunting System Using Hayabusa and MITRE ATT&CK

## Project Overview
A defensive security workflow that uses Hayabusa to scan Windows Event Logs, extract prioritized detections, validate findings against raw event evidence, and defensibly map observations to MITRE ATT&CK techniques.

## Team Roles & Owners
* **Member 1 (Project Lead & Integration Owner)**: Repository structure, schema freeze, final report, slides, demo coordination.
* **Member 2 (Lab Setup & Log Acquisition)**: Authorized lab VM/dataset, log provenance, `docs/lab_setup.md`, data inventory.
* **Member 3 (Hayabusa Engineer)**: Execution syntax, runbook, raw output preservation, `outputs/shortlist.csv`.
* **Member 4 (Threat Hunter & ATT&CK Mapper)**: Evidence validation, `outputs/findings.csv`, `outputs/timeline.csv`, ATT&CK mappings.
* **Member 5 (Reporting & QA Owner)**: Quality checks, screenshots, verification checklist, optional UI view.

## Deliverables Status Tracker
- [ ] Repository & contract frozen (Member 1)
- [ ] Lab dataset inventory & provenance documented (Member 2)
- [ ] Hayabusa runbook and shortlist exported (Member 3)
- [ ] Findings and timeline validated against evidence (Member 4)
- [ ] QA verification and screenshots completed (Member 5)
- [ ] Integrated report (PDF) and slide deck finalized (Member 1)