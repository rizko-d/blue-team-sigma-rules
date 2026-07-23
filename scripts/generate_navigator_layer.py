#!/usr/bin/env python3
"""
Generate MITRE ATT&CK Navigator Layer JSON — visual coverage heatmap.

Usage:
    python3 scripts/generate_navigator_layer.py > build/coverage-layer.json

Output can be loaded at https://mitre-attack.github.io/attack-navigator/
"""
import json
import re
import os
import sys
import yaml
from collections import defaultdict

RULES_DIR = os.path.join(os.path.dirname(__file__), '..', 'rules')

TACTIC_MAP = {
    'attack.initial-access': 'TA0001',
    'attack.execution': 'TA0002',
    'attack.persistence': 'TA0003',
    'attack.privilege-escalation': 'TA0004',
    'attack.defense-evasion': 'TA0005',
    'attack.credential-access': 'TA0006',
    'attack.discovery': 'TA0007',
    'attack.lateral-movement': 'TA0008',
    'attack.collection': 'TA0009',
    'attack.command-and-control': 'TA0011',
    'attack.exfiltration': 'TA0010',
    'attack.impact': 'TA0040',
}

TECHNIQUE_TACTICS = defaultdict(set)
TECHNIQUE_RULES = defaultdict(list)
ALL_TACTICS = set()

for root, dirs, files in os.walk(RULES_DIR):
    for f in files:
        if not f.endswith(('.yml', '.yaml')):
            continue
        with open(os.path.join(root, f)) as fh:
            rule = yaml.safe_load(fh)
        if not rule:
            continue
        tags = rule.get('tags', [])
        tactics_in_rule = set()
        for tag in tags:
            m = re.match(r'attack\.t(\d{4})(?:\.(\d+))?', tag, re.IGNORECASE)
            if m:
                tech_id = f"T{m.group(1).upper()}"
                TECHNIQUE_RULES[tech_id].append({
                    'title': rule.get('title', '?'),
                    'file': f,
                })
        for tag in tags:
            if tag in TACTIC_MAP:
                ALL_TACTICS.add(tag)
                tech_id = None
                # Find associated tech ID if it was already captured
                for t in re.findall(r'attack\.t(\d{4})', ' '.join(tags), re.IGNORECASE):
                    TECHNIQUE_TACTICS[f'T{t.upper()}'].add(TACTIC_MAP.get(tag, tag))


techniques = []
max_count = 1
counts = [len(rules) for rules in TECHNIQUE_RULES.values()]
if counts:
    max_count = max(counts)

# Color gradient: white → light orange → red → dark red
# Values interpolated between minValue=0 and maxValue=max_count
COLOR_LOW = '#ffffff'
COLOR_HIGH = '#b30000'

def interpolate_color(count):
    if count == 0:
        return COLOR_LOW
    ratio = min(count / max(2, max_count), 1.0)
    if ratio <= 0.33:
        return '#ffe6cc'
    elif ratio <= 0.66:
        return '#ff8c66'
    elif ratio <= 1.0:
        return '#d9381e'
    return COLOR_HIGH

for tid in sorted(TECHNIQUE_RULES.keys()):
    rules = TECHNIQUE_RULES[tid]
    count = len(rules)
    tactics = TECHNIQUE_TACTICS.get(tid, set())

    techniques.append({
        'techniqueID': tid,
        'score': count,
        'color': interpolate_color(count),
        'comment': f"{count} rule{'s' if count != 1 else ''} — {'; '.join(r['title'] for r in rules)}",
        'enabled': True,
        'metadata': [
            {'name': 'Rules', 'value': str(count)},
            {'name': 'Tactics', 'value': ', '.join(sorted(tactics)) if tactics else '-'},
        ]
    })

layer = {
    'name': 'Blue Team Sigma Rules - Coverage Heatmap',
    'version': '4.5',
    'domain': 'enterprise-attack',
    'description': (
        f"Detection coverage heatmap generated from {len(TECHNIQUE_RULES)} techniques "
        f"covered by {sum(len(v) for v in TECHNIQUE_RULES.values())} Sigma rules. "
        f"Covers Windows, Linux, macOS, AWS, Azure, and GCP platforms."
    ),
    'filters': {
        'platforms': [
            'Windows', 'Linux', 'macOS', 'AWS', 'Azure', 'GCP',
            'Office 365', 'Containers'
        ]
    },
    'sorting': 2,  # descending score
    'techniques': techniques,
    'gradient': {
        'colors': ['#ffffff', '#ffe6cc', '#ff8c66', '#d9381e', '#b30000'],
        'minValue': 0,
        'maxValue': max_count,
    },
    'legendItems': [
        {'label': 'No coverage', 'color': '#ffffff'},
        {'label': '1 rule', 'color': '#ffe6cc'},
        {'label': '2 rules', 'color': '#ff8c66'},
        {'label': '3+ rules', 'color': '#d9381e'},
        {'label': 'Dense coverage (5+)', 'color': '#b30000'},
    ],
    'showTacticRowBackground': True,
    'tacticRowBackground': '#f5f5f5',
    'selectTechniquesAcrossTactics': True,
}

print(json.dumps(layer, indent=2, ensure_ascii=False))
