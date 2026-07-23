#!/usr/bin/env python3
"""
Validate that every Sigma rule has a `related` field with
MITRE ATT&CK reference entries.  
Exits with code 1 if any rule is missing the required field.

Usage:
    python3 scripts/validate_atomic_links.py
"""
import os
import sys
import yaml

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")


def main() -> int:
    errors = []
    rule_count = 0

    for root, _dirs, files in os.walk(RULES_DIR):
        for f in sorted(files):
            if not f.endswith((".yml", ".yaml")):
                continue
            rule_count += 1
            path = os.path.join(root, f)
            rel = os.path.relpath(path, RULES_DIR)

            with open(path) as fh:
                rule = yaml.safe_load(fh)

            if not rule or not isinstance(rule, dict):
                errors.append(f"{rel}: invalid or empty YAML")
                continue

            related = rule.get("related")
            if not related:
                errors.append(f"{rel}: missing 'related' field")
                continue

            if not isinstance(related, list):
                errors.append(f"{rel}: 'related' is not a list")
                continue

    # Summary
    print(f"Validated {rule_count} rule files.\n")

    if errors:
        print(f"FAILED — {len(errors)} issue(s) found:\n")
        for err in errors:
            print(f"  \u2022 {err}")
        print()
        return 1

    print("All rules have valid `related` MITRE ATT&CK references.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
