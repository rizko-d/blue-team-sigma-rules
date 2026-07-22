"""
Validate MITRE ATT&CK tags against known valid values.
"""

import os
import sys
import yaml

RULES_DIR = os.path.join(os.path.dirname(__file__), '..', 'rules')

KNOWN_TACTICS = {
    'attack.initial-access', 'attack.execution', 'attack.persistence',
    'attack.privilege-escalation', 'attack.defense-evasion',
    'attack.credential-access', 'attack.discovery', 'attack.lateral-movement',
    'attack.collection', 'attack.command-and-control', 'attack.exfiltration',
    'attack.impact',
}

def main():
    errors = 0
    for root, dirs, files in os.walk(RULES_DIR):
        for f in files:
            if not f.endswith(('.yml', '.yaml')):
                continue
            path = os.path.join(root, f)
            with open(path) as fh:
                rule = yaml.safe_load(fh)
            
            tags = rule.get('tags', [])
            for tag in tags:
                if tag.startswith('attack.'):
                    if tag.startswith('attack.t'):
                        # Simple technique format check
                        parts = tag.split('.')
                        if len(parts) >= 3 and not parts[1].startswith('t'):
                            print(f"WARN {f}: invalid technique tag: {tag}")
                            errors += 1
                    elif tag not in KNOWN_TACTICS:
                        print(f"WARN {f}: unknown tag: {tag}")
                        errors += 1
    
    if errors:
        print(f"\n{errors} validation errors found")
        sys.exit(1)
    print("All MITRE tags valid.")
    sys.exit(0)

if __name__ == '__main__':
    main()
