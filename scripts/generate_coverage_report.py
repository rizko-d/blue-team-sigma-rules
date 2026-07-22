"""
Generate MITRE ATT&CK coverage report in markdown.
"""

import os
import yaml
from collections import defaultdict

RULES_DIR = os.path.join(os.path.dirname(__file__), '..', 'rules')

def main():
    tactic_rules = defaultdict(list)
    technique_rules = defaultdict(list)
    
    for root, dirs, files in os.walk(RULES_DIR):
        for f in files:
            if not f.endswith(('.yml', '.yaml')):
                continue
            path = os.path.join(root, f)
            with open(path) as fh:
                rule = yaml.safe_load(fh)
            
            rule_ref = f"{rule['title']} ({f})"
            for tag in rule.get('tags', []):
                if tag.startswith('attack.t'):
                    technique_rules[tag].append(rule_ref)
                elif tag.startswith('attack.') and not tag.startswith('attack.t') and '.' not in tag[7:]:
                    tactic_rules[tag].append(rule_ref)
    
    print("# MITRE ATT&CK Coverage Report")
    print()
    
    for tactic in sorted(tactic_rules.keys()):
        name = tactic.replace('attack.', '').replace('-', ' ').title()
        count = len(tactic_rules[tactic])
        severity_counts = defaultdict(int)
        
        for rule_ref in tactic_rules[tactic]:
            fname = rule_ref.split('(')[-1].rstrip(')')
            path = None
            for root, dirs, files in os.walk(RULES_DIR):
                if fname in files:
                    path = os.path.join(root, fname)
                    break
            if path:
                with open(path) as fh:
                    r = yaml.safe_load(fh)
                severity_counts[r.get('level', 'unknown')] += 1
        
        print(f"## {name} ({count} rules)")
        for level in ['critical', 'high', 'medium', 'low', 'informational']:
            if severity_counts[level]:
                print(f"  - {level.upper()}: {severity_counts[level]}")
        print()
    
    # Coverage gaps
    all_tactics = {
        'attack.initial-access', 'attack.execution', 'attack.persistence',
        'attack.privilege-escalation', 'attack.defense-evasion',
        'attack.credential-access', 'attack.discovery',
        'attack.lateral-movement', 'attack.collection',
        'attack.command-and-control', 'attack.exfiltration', 'attack.impact',
    }
    covered = set(tactic_rules.keys())
    missing = all_tactics - covered
    if missing:
        print("## Coverage Gaps")
        for t in sorted(missing):
            name = t.replace('attack.', '').replace('-', ' ').title()
            print(f"  - {name}")

if __name__ == '__main__':
    main()
