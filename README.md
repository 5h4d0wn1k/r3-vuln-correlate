# R3 — Vulnerability Correlation Engine

CVE mapping, CVSS scoring, attack chain analysis, and risk prioritization for security research.

## Overview

This project implements a vulnerability correlation engine that:
- Manages a CVE database with severity/product/year indexing
- Calculates CVSS v3.1 scores from vector strings
- Models and analyzes attack chains (kill chains)
- Prioritizes risks based on CVSS, exploitability, and asset context

## Features

- **CVSS Calculator**: Full CVSS v3.1 score calculation from vector components
- **CVE Database**: Store, search, and index CVEs by severity, product, and year
- **Attack Chain Analysis**: Model multi-phase attack chains with complexity assessment
- **Risk Prioritization**: Context-aware risk scoring considering assets and exploitability
- **Standard Library Only**: Uses json, re, datetime — no external dependencies

## Usage

```python
from vuln_correlate import VulnCorrelator, CVSSCalculator

# Calculate a CVSS score
result = CVSSCalculator.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

# Build a correlator
engine = VulnCorrelator()
engine.cve_database.add_cve("CVE-2024-1234", "RCE in web server", cvss_vector=result['vector'])
engine.risk_prioritizer.add_asset("web-01", "Web Server", "server", 9, 9, 8)
engine.risk_prioritizer.add_vulnerability("vuln-001", "CVE-2024-1234", 9.8, "weaponized", ["web-01"])
top = engine.risk_prioritizer.get_top_risks()
```

```bash
# Run built-in demo
python3 vuln_correlate.py
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
