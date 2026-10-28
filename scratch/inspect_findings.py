import json
import csv

with open('outputs/processed_data.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

findings = data['findings']
with open('outputs/raw/hayabusa_raw_output.csv', 'r', encoding='utf-8') as f:
    raw_alerts = list(csv.DictReader(f))

# Map raw alerts by (RecordID, EventID) or similar
print(f"Total findings: {len(findings)}")
for f in findings:
    fid = f.get('finding_id')
    name = f.get('alert_name')
    ev_ref = f.get('evidence_reference')
    status = f.get('status')
    conf = f.get('confidence')
    interp = f.get('interpretation')
    benign = f.get('benign_explanation')
    limit = f.get('limitation')
    next_step = f.get('next_step')
    det = f.get('details')
    techs = f.get('techniques')
    print(f"=== {fid}: {name} ===")
    print(f"  Status: {status} | Confidence: {conf}")
    print(f"  Evidence Ref: {ev_ref}")
    print(f"  Techniques: {techs}")
    print(f"  Raw Details: {det}")
    print(f"  Interpretation: {interp}")
    print(f"  Benign Explanation: {benign}")
    print(f"  Limitation: {limit}")
    print(f"  Next Step: {next_step}")
    print("-" * 60)
