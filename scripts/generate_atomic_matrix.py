#!/usr/bin/env python3
"""
generate_atomic_matrix.py

Generate a Markdown matrix table showing Atomic Red Team test coverage across
all Sigma rules.  Output is written to build/atomic-matrix.md.

Usage:
    python3 scripts/generate_atomic_matrix.py
"""

import os
import re
import sys
from typing import Optional

import yaml

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "..", "build", "atomic-matrix.md")

ATOMIC_PATTERN = re.compile(
    r"https://github\.com/redcanaryco/atomic-red-team/blob/master/atomics/([^/]+)/",
    re.IGNORECASE,
)
TECHNIQUE_PATTERN = re.compile(r"attack\.(t\d{4}(?:\.\d+)?)", re.IGNORECASE)

# Friendly names for well-known MITRE technique IDs
TECHNIQUE_NAMES: dict[str, str] = {
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1003.002": "Security Account Manager (SAM)",
    "T1003.003": "NTDS.dit",
    "T1003.008": "/etc/shadow",
    "T1005": "Data from Local System",
    "T1018": "Remote System Discovery",
    "T1027": "Obfuscated Files or Information",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1048.003": "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol",
    "T1053": "Scheduled Task/Job",
    "T1053.005": "Scheduled Task",
    "T1055": "Process Injection",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.004": "Unix Shell",
    "T1059.005": "Visual Basic",
    "T1059.006": "Python",
    "T1078": "Valid Accounts",
    "T1078.004": "Cloud Accounts",
    "T1098": "Account Manipulation",
    "T1098.002": "Exchange Email Delegate Permissions",
    "T1098.003": "Additional Cloud Roles",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1110.002": "Password Cracking",
    "T1134": "Access Token Manipulation",
    "T1134.001": "Token Impersonation/Theft",
    "T1136": "Create Account",
    "T1136.001": "Local Account",
    "T1136.003": "Cloud Account",
    "T1190": "Exploit Public-Facing Application",
    "T1204.002": "Malicious File",
    "T1208": "Kerberoasting",
    "T1218": "System Binary Proxy Execution",
    "T1218.005": "Mshta",
    "T1218.010": "Regsvr32",
    "T1218.011": "Rundll32",
    "T1482": "Domain Trust Discovery",
    "T1485": "Data Destruction",
    "T1490": "Inhibit System Recovery",
    "T1505.005": "Terminal Services DLL",
    "T1518": "Software Discovery",
    "T1525": "Implant Internal Image",
    "T1530": "Data from Cloud Storage Object",
    "T1543.003": "Windows Service",
    "T1546.003": "Windows Management Instrumentation (WMI)",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1547.006": "Launch Agent",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1548.003": "Sudo and Sudo Caching",
    "T1550.002": "Pass the Hash",
    "T1552": "Unsecured Credentials",
    "T1552.001": "Credentials In Files",
    "T1555": "Credentials from Password Stores",
    "T1555.003": "Keychain",
    "T1556.006": "Multi-Factor Authentication",
    "T1558.003": "Kerberoasting",
    "T1559": "Inter-Process Communication",
    "T1562": "Impair Defenses",
    "T1562.001": "Disable or Modify Tools",
    "T1562.002": "Disable Windows Event Logging",
    "T1562.008": "Disable Cloud Logs",
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1568": "Dynamic Resolution",
    "T1572": "Protocol Tunneling",
    "T1574.002": "DLL Side-Loading",
    "T1583": "Acquire Infrastructure",
    "T1583.001": "Domains",
    "T1611": "Escape to Host",
}

# Tactic slug → display name
TACTIC_NAMES = {
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "credential-access": "Credential Access",
    "defense-evasion": "Defense Evasion",
    "discovery": "Discovery",
    "execution": "Execution",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "initial-access": "Initial Access",
    "lateral-movement": "Lateral Movement",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
}


def determine_platform(logsource: dict) -> str:
    """Extract a short platform label from the logsource."""
    product = (logsource or {}).get("product", "") or ""
    if "windows" in product:
        return "windows"
    if "linux" in product:
        return "linux"
    if "macos" in product or "mac" in product:
        return "macos"
    if product.startswith(("aws", "azure", "gcp")):
        return product
    return product or "generic"


def extract_tactic(tags: list) -> Optional[str]:
    """Return the tactic display name from tags, or None."""
    for tag in tags or []:
        tag = str(tag)
        parts = tag.split(".")
        if len(parts) == 2 and parts[1] in TACTIC_NAMES:
            return TACTIC_NAMES[parts[1]]
    return None


def main() -> int:
    rows: list[dict] = []  # Each row represents one (technique-id, rule-file) pair

    for root, _dirs, files in os.walk(RULES_DIR):
        for f in sorted(files):
            if not f.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(root, f)
            with open(path) as fh:
                rule = yaml.safe_load(fh)
            if not rule or not isinstance(rule, dict):
                continue

            title = rule.get("title", f)
            tags = rule.get("tags", [])
            references = rule.get("references") or []
            logsource = rule.get("logsource", {})
            platform = determine_platform(logsource)
            tactic = extract_tactic(tags) or os.path.basename(os.path.dirname(f)).replace("-", " ").title()

            # Extract MITRE technique ID(s) from tags
            tech_ids: list[str] = []
            for tag in tags:
                m = TECHNIQUE_PATTERN.match(str(tag))
                if m:
                    tid = m.group(1).upper()
                    # Normalise: t1059.001 → T1059.001 (already uppercased)
                    tech_ids.append(tid)

            # Check for Atomic Red Team reference
            has_atomic = False
            atomic_technique = None
            for ref in references:
                m = ATOMIC_PATTERN.search(str(ref))
                if m:
                    has_atomic = True
                    atomic_technique = m.group(1)
                    break

            for tid in tech_ids:
                rows.append({
                    "tid": tid,
                    "rule_file": f,
                    "rule_title": title,
                    "platform": platform,
                    "tactic": tactic,
                    "has_atomic": has_atomic,
                    "atomic_technique": atomic_technique,
                })

    if not rows:
        print("No rules with MITRE technique tags found — output not written.", file=sys.stderr)
        return 1

    # ---- Aggregate by technique ID ----
    from collections import defaultdict

    tech_info: dict[str, dict] = {}
    for r in rows:
        tid = r["tid"]
        if tid not in tech_info:
            tech_info[tid] = {
                "tid": tid,
                "name": TECHNIQUE_NAMES.get(tid, tid),
                "platforms": set(),
                "tactics": set(),
                "rule_count": 0,
                "rule_files": [],
                "has_atomic": False,
            }
        info = tech_info[tid]
        info["platforms"].add(r["platform"])
        info["tactics"].add(r["tactic"])
        info["rule_count"] += 1
        info["rule_files"].append(r["rule_file"])
        if r["has_atomic"]:
            info["has_atomic"] = True

    sorted_tids = sorted(tech_info.keys(), key=_sort_key)

    # ---- Build Markdown ----
    lines: list[str] = []
    lines.append("# Atomic Red Team Coverage Matrix")
    lines.append("")
    lines.append(
        f"Coverage summary for {len(sorted_tids)} MITRE ATT&CK techniques "
        f"across {sum(v['rule_count'] for v in tech_info.values())} rule-technique mappings "
        f"({len(set(r['rule_file'] for r in rows))} unique rule files)."
    )
    lines.append("")
    lines.append("| Technique ID | Technique | Platform | Rules | Atomic Test | Rule Files |")
    lines.append("|---|---|---|---|---|---|")

    for tid in sorted_tids:
        info = tech_info[tid]
        platforms = ", ".join(sorted(info["platforms"]))
        atomic_badge = "✅" if info["has_atomic"] else "❌"
        rule_files = ", ".join(info["rule_files"])

        lines.append(
            f"| {info['tid']} | {info['name']} | {platforms} "
            f"| {info['rule_count']} | {atomic_badge} | {rule_files} |"
        )

    # ---- Counts ----
    total = len(sorted_tids)
    with_atomic = sum(1 for v in tech_info.values() if v["has_atomic"])
    without_atomic = total - with_atomic

    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Techniques covered**: {total}")
    lines.append(f"- **With Atomic Red Team test**: {with_atomic}")
    lines.append(f"- **Missing Atomic Red Team test**: {without_atomic}")
    lines.append(f"- **Total rule files**: {len(set(r['rule_file'] for r in rows))}")
    lines.append(f"- **Rule-technique associations**: {sum(v['rule_count'] for v in tech_info.values())}")
    lines.append("")

    # ---- Missing Atomic tests ----
    if without_atomic:
        lines.append("### Techniques Missing Atomic Red Team Tests")
        lines.append("")
        for tid in sorted_tids:
            info = tech_info[tid]
            if not info["has_atomic"]:
                lines.append(f"- [{info['tid']}] {info['name']} — {', '.join(info['rule_files'])}")
        lines.append("")

    # ---- Write ----
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as fh:
        fh.write("\n".join(lines))

    print(f"Wrote {OUTPUT_FILE} ({len(sorted_tids)} techniques, {with_atomic} with Atomic tests)")
    return 0


def _sort_key(tid: str) -> tuple:
    """Sort TIDs numerically, e.g. T1059.001 sorts after T1059."""
    tid = tid.lstrip("T")
    parts = tid.split(".")
    return tuple(int(p) for p in parts)


if __name__ == "__main__":
    sys.exit(main())
