# R3 — Vulnerability Correlator

Correlates vulnerability-scanner JSON findings with an asset-inventory JSON fixture and emits a prioritized risk report. Retains CVE/CVSS/attack-chain logic from the legacy `vuln_correlate.py` plus a working, tested join-and-prioritize pipeline.

## Overview

This project implements a vulnerability correlation engine that:
- Joins a vuln-scanner JSON report with an asset-inventory JSON fixture
- Computes a context-aware risk score per finding (CVSS + exploitability + asset criticality/exposure/business value + patch status)
- Emits a prioritized risk report (ranked findings + per-asset rollup)
- Manages a CVE database with severity/product/year indexing
- Calculates CVSS v3.1 scores from vector strings
- Models and analyzes attack chains (kill chains)
- Writes JSON and Markdown reports (gitignored)

## Features

- **Scanner/Inventory Join**: deterministic `fixtures/scan_results.json` + `fixtures/asset_inventory.json`
- **Risk Prioritization**: context-aware risk scoring considering assets and exploitability
- **CVSS Calculator**: Full CVSS v3.1 score calculation from vector components
- **CVE Database**: Store, search, and index CVEs by severity, product, and year
- **Attack Chain Analysis**: Model multi-phase attack chains with complexity assessment
- **CLI**: argparse with `--help`, `-o` report directory, `--json-only`
- **Standard Library Only**: json, re, datetime

## Usage

```bash
# Run on the fixtures (default)
python3 run_demo.py

# Custom scanner JSON + inventory
python3 run_demo.py /path/scan.json --inventory /path/assets.json

# Custom report directory / JSON only
python3 run_demo.py -o ./out --json-only

# Help
python3 run_demo.py --help

# Run unit tests
python3 -m unittest discover -s tests -v
```

Programmatic use:

```python
from run_demo import correlate

report = correlate("fixtures/scan_results.json", "fixtures/asset_inventory.json")
for f in report["prioritized_findings"]:
    print(f["rank"], f["asset_id"], f["cve_id"], f["risk_score"], f["priority"])
```

## Output

The correlator writes:
- `reports/r3_report.json`
- `reports/r3_report.md`

Both are gitignored.

## Live Lab Test Plan

| Phase | Description | Go / No-Go Criteria | Status |
|-------|-------------|---------------------|--------|
| Phase 0 | Fixture join validation (this tool) | Demo exits 0, tests pass, 5 findings joined to 3 assets | DONE |
| Phase 1 | Real scanner output ingestion | Parse real vuln-scanner JSON (e.g. Trivy/OpenVAS export) | PENDING |
| Phase 2 | Real asset inventory ingestion | Join real CMDB/asset inventory with scanner output | PENDING |
| Phase 3 | Risk model calibration | Risk scores align with security-team priorities on real data | PENDING |

## Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Fixture findings joined | 5 | 5 |
| Fixture assets | 3 | 3 |
| Prioritized ranking | Sorted by risk desc | Verified |
| Test pass rate | 100% | 100% |
| Demo exit code | 0 | 0 |

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the asset owner before scanning or analyzing vulnerabilities
- Only run against systems you own or have written authorization to test
- Do not use scanner data from systems you are not authorized to assess

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and data-protection statutes
- **GDPR/CCPA**: Vulnerability and asset data may be subject to privacy regulations

### Acceptable Use
- Vulnerability prioritization on systems you own or are authorized to assess
- Authorized penetration testing with written scope
- Academic security research in controlled lab environments
- Security education and training

### Prohibited Use
- Scanning or assessing systems you do not own or lack authorization for
- Exploiting vulnerabilities against production or third-party systems
- Using the tool to violate any applicable law or regulation
- Storing unauthorized scan data

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
