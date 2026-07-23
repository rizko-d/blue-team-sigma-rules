"""
Check MITRE ATT&CK tag coverage across all Sigma rules.
"""

import os
import sys
import yaml
from collections import Counter

RULES_DIR = os.path.join(os.path.dirname(__file__), '..', 'rules')

def main():
    tactics = Counter()
    techniques = Counter()
    rule_count = 0
    
    for root, dirs, files in os.walk(RULES_DIR):
        for f in files:
            if not f.endswith(('.yml', '.yaml')):
                continue
            rule_count += 1
            with open(os.path.join(root, f)) as fh:
                rule = yaml.safe_load(fh)
            for tag in rule.get('tags', []):
                if tag.startswith('attack.t'):
                    # It's a technique (e.g., attack.t1059.001)
                    techniques[tag] += 1
                elif tag.startswith('attack.') and '.' not in tag[7:]:
                    # It's a tactic (e.g., attack.execution, but NOT attack.t1234)
                    tactics[tag] += 1
    
    print(f"Total rules: {rule_count}")
    print(f"\nTactic coverage ({len(tactics)}/{12}):")
    for tactic, count in sorted(tactics.items()):
        print(f"  {tactic}: {count} rules")
    
    print(f"\nTechnique coverage ({len(techniques)} techniques):")
    for technique, count in sorted(techniques.items()):
        print(f"  {technique}: {count} rules")
    
    missing = set([
        'attack.initial-access', 'attack.execution', 'attack.persistence',
        'attack.privilege-escalation', 'attack.defense-evasion',
        'attack.credential-access', 'attack.discovery',
        'attack.lateral-movement', 'attack.collection',
        'attack.command-and-control', 'attack.exfiltration', 'attack.impact',
        'attack.resource-development',
    ]) - set(tactics.keys())
    
    if missing:
        print(f"\nWARNING: Missing tactics: {missing}")
        sys.exit(1)
    
    print(f"\nAll 12 MITRE tactics covered!")
    sys.exit(0)

if __name__ == '__main__':
    main()
