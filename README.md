# Blue Team Sigma Rules Pack

> **Author:** Rizko Febri Rachmayadi  
> **Status:** Active Development  
> **36 Sigma Rules** | **12/12 MITRE ATT&CK Tactic Coverage** | **35 Unique Techniques**  
> **Not for production deployment** — educational/demonstration use only

---

## Objective

A self-contained detection engineering portfolio demonstrating:
- **Sigma rule authoring** across the full MITRE ATT&CK kill chain
- **Unit testing framework** for detection logic validation
- **CI/CD pipeline** (GitHub Actions) for syntax validation, compilation, and coverage reporting
- **Detection engineering methodology**: threat-informed, tested, documented

---

## Project Structure

```
blue-team-sigma-rules/
├── .github/workflows/
│   └── sigma-test.yml          # GitHub Actions CI pipeline
├── rules/                      # 36 Sigma detection rules
│   ├── initial-access/         # 4 rules (T1204, T1547)
│   ├── execution/              # 8 rules (T1059, T1047, T1218, T1105, T1197)
│   ├── persistence/            # 5 rules (T1053, T1543, T1546, T1547)
│   ├── privilege-escalation/   # 3 rules (T1068, T1548, T1053)
│   ├── defense-evasion/        # 11 rules (T1218, T1027, T1197)
│   ├── credential-access/      # 5 rules (T1003, T1557, T1558)
│   ├── discovery/              # 2 rules (T1087, T1057)
│   ├── lateral-movement/       # 4 rules (T1047, T1021, T1550)
│   ├── collection/             # 1 rule (T1119, T1560)
│   ├── command-and-control/    # 2 rules (T1071, T1055)
│   ├── exfiltration/           # 3 rules (T1048)
│   └── impact/                 # 1 rule (T1490)
├── tests/
│   └── test_rules.py           # 261 unit tests (7 tests per rule)
├── scripts/
│   ├── check_mitre_coverage.py # Coverage analysis
│   ├── validate_mitre_tags.py  # Tag validation
│   └── generate_coverage_report.py
├── .yamllint.yml
└── README.md
```

---

## MITRE ATT&CK Coverage Heatmap

| Tactic | Rules | Severity Spread | Key Techniques |
|--------|-------|-----------------|----------------|
| **Initial Access** | 4 | HIGH(3), MEDIUM(1) | T1204.002, T1547.009 |
| **Execution** | 8 | HIGH(4), MEDIUM(4) | T1059.001, T1047, T1218.003 |
| **Persistence** | 5 | HIGH(4), MEDIUM(1) | T1053.005, T1543.003, T1546.003, T1547.001 |
| **Privilege Escalation** | 3 | CRITICAL(1), HIGH(1), MEDIUM(1) | T1068, T1548.002 |
| **Defense Evasion** | 11 | HIGH(7), MEDIUM(4) | T1218(.003/.005/.010/.011), T1027 |
| **Credential Access** | 5 | CRITICAL(2), HIGH(2), MEDIUM(1) | T1003(.001/.002/.003), T1557.001, T1558.003 |
| **Discovery** | 2 | MEDIUM(1), LOW(1) | T1087.002, T1057 |
| **Lateral Movement** | 4 | HIGH(2), MEDIUM(2) | T1047, T1021.003, T1550.002 |
| **Collection** | 1 | MEDIUM(1) | T1119, T1560 |
| **Command & Control** | 2 | HIGH(1), MEDIUM(1) | T1071.004, T1055 |
| **Exfiltration** | 3 | MEDIUM(3) | T1048, T1048.001 |
| **Impact** | 1 | CRITICAL(1) | T1490 |

---

## Highlighted Rules

### Critical Severity (4 rules)
| Rule | Technique | Description |
|------|-----------|-------------|
| **LSASS Memory Dump** | T1003.001 | Detects LSASS credential dumping via comsvcs.dll, procdump, sqldumper |
| **SAM Registry Dump** | T1003.002 | Detects SAM/SYSTEM/SECURITY hive export via reg.exe |
| **NTDS.dit Extraction** | T1003.003 | Detects Active Directory database extraction via VSSAdmin or NinjaCopy |
| **Volume Shadow Copy Deletion** | T1490 | Detects VSS deletion — ransomware precursor |

### Defense Evasion Coverage (11 rules)
The most heavily covered tactic. Rules detect:
- **LOLBins**: MSHTA (T1218.005), Regsvr32 (T1218.010), Rundll32 (T1218.011), CMSTP (T1218.003), Certutil, BITSAdmin
- **Obfuscation**: Caret insertion, string reversal, environment variable expansion (T1027)
- **AMSI Bypass**: PowerShell AMSI initfailed detection

### C2 Detection
| Rule | Technique | Indicator |
|------|-----------|-----------|
| **DNS Tunneling** | T1071.004 | High-entropy subdomain queries |
| **Cobalt Strike Pipes** | T1055 | Default named pipe patterns (MSSE-, postex_, beacon_) |

---

## CI/CD Pipeline

The GitHub Actions workflow (`sigma-test.yml`) runs on every push/PR:

1. **Syntax Validation** — Validates YAML for all 36 rules
2. **Schema Validation** — Checks required fields, UUID format, severity levels
3. **Sigmac Compilation** — Compiles rules to Elastic DSL JSON
4. **Unit Tests** — 261 parametrized tests (7 assertion classes per rule)
5. **MITRE Coverage Check** — Ensures all 12 tactics covered
6. **Artifact Publishing** — Compiled rules + coverage report available for download

---

## Local Usage

```bash
# Run all tests
python3 -m pytest tests/ -v

# Check MITRE coverage
python3 scripts/check_mitre_coverage.py

# Validate MITRE tags
python3 scripts/validate_mitre_tags.py

# Generate coverage report
python3 scripts/generate_coverage_report.py > coverage-report.md

# Compile to Elastic DSL (requires sigmac)
pip install sigmatools
sigmac -t elastic --format json rules/initial-access/suspicious-office-child-process.yml
```

---

## Design Decisions & Methodology

### Detection Engineering Principles Applied
1. **Threat-Informed**: Every rule maps to a specific MITRE ATT&CK technique and real-world adversary behavior
2. **Layered Detection**: Multiple log sources (process_creation, security_event, dns_query)
3. **False Positive Consideration**: Every rule includes `falsepositives` and severity justification
4. **Sigmac-Compatible**: All rules compile with the official `sigmac` toolchain
5. **Test-Driven**: 7 test assertions per rule ensure quality and consistency

### Why Sigma?
- **Vendor-agnostic**: Rules compile to Elastic, Splunk, Azure Sentinel, QRadar, etc.
- **Community standard**: Backed by SigmaHQ and 300+ contributors
- **Portable**: Same rule works across SIEM platforms
- **CI-friendly**: YAML format enables automated testing

---

## Limitations & Educational Scope

- **Lab-validated only on public datasets**: These rules have NOT been tested against real production telemetry
- **No tuning**: Real detection engineering requires iterative false-positive tuning
- **Windows-focused**: Rules target Windows only (Linux/macOS/cloud rules are separate scope)
- **Standalone rules**: No correlation logic, no risk scoring, no SOAR integration
- **Not production-ready**: Intended for portfolio demonstration and educational reference

---

## Future Roadmap

- [ ] Add Linux/macOS detection rules (T1059.004, T1543.002, T1548.003)
- [ ] Add cloud detection rules (AWS CloudTrail, Azure Activity Logs)
- [ ] Add correlation rules (multi-event sequences)
- [ ] Add ATT&CK Navigator Layer JSON export
- [ ] Add Sigma correlation detection rules
- [ ] Performance benchmarking against real event volumes

---

## References

- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [SigmaHQ Rules Repository](https://github.com/SigmaHQ/sigma)
