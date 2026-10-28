#!/usr/bin/env python3
"""
export_navigator_layer.py — Windows Threat Hunting System
Part D: MITRE ATT&CK Navigator Layer Export.

Reads outputs/attack_mapping.csv and generates a valid ATT&CK Navigator
layer JSON file at outputs/attack_navigator_layer.json.

Layer format: ATT&CK Navigator v4.9 / Layer v4.5 / ATT&CK Enterprise v14
Reference: https://github.com/mitre-attack/attack-navigator (checked 2026-10-28)

Usage:
    python scripts/export_navigator_layer.py
"""

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ATTACK_MAPPING_CSV = ROOT / "outputs" / "attack_mapping.csv"
OUTPUT_JSON        = ROOT / "outputs" / "attack_navigator_layer.json"

# Tactic ID → Navigator tactic slug mapping
# Source: ATT&CK Enterprise matrix tactic IDs (verified against attack-navigator)
TECHNIQUE_TO_TACTIC_SLUG = {
    "T1003":     "credential-access",
    "T1003.001": "credential-access",
    "T1027":     "defense-evasion",
    "T1027.010": "defense-evasion",
    "T1033":     "discovery",
    "T1053":     "persistence",
    "T1053.005": "persistence",
    "T1055":     "defense-evasion",
    "T1059":     "execution",
    "T1059.001": "execution",
    "T1059.003": "execution",
    "T1086":     "execution",
    "T1088":     "privilege-escalation",
    "T1136":     "persistence",
    "T1136.001": "persistence",
    "T1566":     "initial-access",
    "T1566.001": "initial-access",
}

# Severity color mapping (from mapping_status / confidence)
CONFIDENCE_COLOR = {
    "high":   "#ff6666",
    "medium": "#ff9966",
    "low":    "#ffcc66",
}


def load_attack_mapping(path):
    """Load attack_mapping.csv. Returns list of row dicts."""
    if not path.exists():
        raise FileNotFoundError(f"attack_mapping.csv not found: {path}")
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required = {"finding_id", "technique_id", "tactic", "confidence"}
        for i, row in enumerate(reader, start=2):
            tid = row.get("technique_id", "").strip()
            fid = row.get("finding_id", "").strip()
            if not tid or not fid:
                print(f"  [!] Skipping malformed row {i}: technique_id={tid!r}, finding_id={fid!r}")
                continue
            rows.append(row)
    return rows


def build_technique_entries(mapping_rows):
    """
    Build Navigator technique entries from mapping rows.
    Merge duplicate technique IDs by combining finding references.
    Returns list of technique entry dicts.
    """
    # Group by technique_id
    by_tid = defaultdict(list)
    for row in mapping_rows:
        tid = row["technique_id"].strip()
        by_tid[tid].append(row)

    entries = []
    for tid, rows in sorted(by_tid.items()):
        # Collect all finding IDs (deduplicated, sorted)
        finding_ids = sorted(set(r["finding_id"].strip() for r in rows))
        comment = f"Finding IDs: {', '.join(finding_ids)}"

        # Derive tactic slug
        tactic_slug = TECHNIQUE_TO_TACTIC_SLUG.get(tid, "")
        if not tactic_slug:
            # Try base technique
            base = tid.split(".")[0]
            tactic_slug = TECHNIQUE_TO_TACTIC_SLUG.get(base, "")

        # Derive color from highest confidence among rows
        confidences = [r.get("confidence", "").lower() for r in rows]
        if "high" in confidences:
            color = CONFIDENCE_COLOR["high"]
        elif "medium" in confidences:
            color = CONFIDENCE_COLOR["medium"]
        else:
            color = CONFIDENCE_COLOR["low"]

        # Build metadata list
        metadata = [
            {"name": "finding_ids", "value": ", ".join(finding_ids)},
            {"name": "source", "value": "outputs/attack_mapping.csv"},
        ]

        entry = {
            "techniqueID": tid,
            "tactic": tactic_slug,
            "color": color,
            "comment": comment,
            "enabled": True,
            "metadata": metadata,
            "links": [],
            "showSubtechniques": False,
        }
        entries.append(entry)

    return entries


def build_layer(technique_entries):
    """Build the full ATT&CK Navigator layer structure."""
    layer = {
        "name": "Windows Threat Hunting - Hayabusa Findings",
        "versions": {
            "attack": "14",
            "navigator": "4.9",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            "MITRE ATT&CK layer derived from Hayabusa-based threat hunting findings. "
            "Generated from outputs/attack_mapping.csv. "
            "Only techniques actually mapped in this project are included. "
            "Technique colors reflect analyst confidence (red=high, orange=medium, yellow=low)."
        ),
        "filters": {
            "platforms": [
                "Windows",
            ],
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": False,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
            "expandedSubtechniques": "none",
        },
        "hideDisabled": False,
        "techniques": technique_entries,
        "gradient": {
            "colors": ["#ffffff", "#ff6666"],
            "minValue": 0,
            "maxValue": 1,
        },
        "legendItems": [
            {"label": "High confidence finding", "color": "#ff6666"},
            {"label": "Medium confidence finding", "color": "#ff9966"},
            {"label": "Low confidence finding", "color": "#ffcc66"},
        ],
        "metadata": [
            {"name": "project", "value": "Windows Threat Hunting System Using Hayabusa"},
            {"name": "source_file", "value": "outputs/attack_mapping.csv"},
            {"name": "layer_format_reference",
             "value": "https://github.com/mitre-attack/attack-navigator (verified 2026-10-28)"},
        ],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": False,
        "selectSubtechniquesWithParent": False,
    }
    return layer


def validate_layer(layer):
    """Basic validation of the layer structure."""
    required_keys = {"name", "versions", "domain", "techniques"}
    missing = required_keys - layer.keys()
    if missing:
        raise ValueError(f"Layer missing required keys: {missing}")
    if not isinstance(layer["techniques"], list):
        raise ValueError("'techniques' must be a list")
    versions = layer.get("versions", {})
    for vk in ("attack", "navigator", "layer"):
        if vk not in versions:
            raise ValueError(f"Missing versions.{vk}")
    # Validate each technique entry
    for i, t in enumerate(layer["techniques"]):
        if "techniqueID" not in t:
            raise ValueError(f"Technique entry {i} missing techniqueID")
    print(f"[+] Layer validation passed ({len(layer['techniques'])} techniques)")


def main():
    print(f"[+] Loading: {ATTACK_MAPPING_CSV}")
    try:
        mapping_rows = load_attack_mapping(ATTACK_MAPPING_CSV)
    except FileNotFoundError as e:
        print(f"[-] ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    if not mapping_rows:
        print("[-] No valid mapping rows found. Generating empty layer.", file=sys.stderr)

    print(f"[+] Loaded {len(mapping_rows)} mapping rows")

    print("[+] Building technique entries...")
    technique_entries = build_technique_entries(mapping_rows)
    print(f"[+] Unique techniques: {len(technique_entries)}")

    print("[+] Building Navigator layer...")
    layer = build_layer(technique_entries)

    print("[+] Validating layer...")
    try:
        validate_layer(layer)
    except ValueError as e:
        print(f"[-] Validation FAILED: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Writing: {OUTPUT_JSON}")
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)

    print(f"[DONE] Navigator layer written to {OUTPUT_JSON}")
    print(f"       Techniques: {len(technique_entries)}")
    for entry in technique_entries:
        print(f"         {entry['techniqueID']} — {entry['comment']}")


if __name__ == "__main__":
    main()

