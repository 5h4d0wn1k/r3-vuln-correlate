#!/usr/bin/env python3
"""R3 — Vulnerability Correlation Engine: CVE mapping, CVSS scoring, attack chain analysis, risk prioritization."""

import json
import re
import math
import collections
from datetime import datetime


class CVSSCalculator:
    """Calculate and parse CVSS v3.1 scores."""

    METRICS = {
        'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20},
        'AC': {'L': 0.77, 'H': 0.44},
        'PR': {
            'none': {'N': 0.85, 'L': 0.85, 'H': 0.85},
            'low': {'N': 0.85, 'L': 0.62, 'H': 0.68},
            'high': {'N': 0.85, 'L': 0.27, 'H': 0.50},
        },
        'UI': {'N': 0.85, 'R': 0.62},
        'S': {'U': None, 'C': None},
        'C': {'N': 0.00, 'L': 0.22, 'H': 0.56},
        'I': {'N': 0.00, 'L': 0.22, 'H': 0.56},
        'A': {'N': 0.00, 'L': 0.22, 'H': 0.56},
    }

    SEVERITY_RANGES = [
        (0.0, 0.0, 'None'),
        (0.1, 3.9, 'Low'),
        (4.0, 6.9, 'Medium'),
        (7.0, 8.9, 'High'),
        (9.0, 10.0, 'Critical'),
    ]

    @classmethod
    def calculate(cls, av, ac, pr, ui, s, c, i, a, scope_override=None):
        """Calculate CVSS v3.1 score from vector components."""
        if s == 'C':
            pr_val = cls.METRICS['PR'][pr]['H']
        else:
            pr_val = cls.METRICS['PR'][pr]['N']

        iss = 1 - ((1 - cls.METRICS['C'][c]) * (1 - cls.METRICS['I'][i]) * (1 - cls.METRICS['A'][a]))

        if s == 'U':
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        exploitability = 8.22 * cls.METRICS['AV'][av] * cls.METRICS['AC'][ac] * pr_val * cls.METRICS['UI'][ui]

        if impact <= 0:
            score = 0.0
        elif s == 'U':
            score = min(impact + exploitability, 10.0)
        else:
            score = min(1.4 * (impact + exploitability), 10.0)

        score = math.ceil(score * 10) / 10.0
        return score

    PR_MAP = {'N': 'none', 'L': 'low', 'H': 'high'}

    @classmethod
    def parse_vector(cls, vector_string):
        """Parse a CVSS v3.1 vector string."""
        pattern = r'CVSS:3\.1/AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/S:([UC])/C:([NLH])/I:([NLH])/A:([NLH])'
        match = re.match(pattern, vector_string)
        if not match:
            return None
        raw_pr = match.group(3)
        return {
            'AV': match.group(1), 'AC': match.group(2), 'PR': cls.PR_MAP.get(raw_pr, raw_pr),
            'UI': match.group(4), 'S': match.group(5),
            'C': match.group(6), 'I': match.group(7), 'A': match.group(8),
        }

    @classmethod
    def from_vector(cls, vector_string):
        """Calculate score from CVSS vector string."""
        metrics = cls.parse_vector(vector_string)
        if not metrics:
            return None
        params = {k.lower(): v for k, v in metrics.items()}
        score = cls.calculate(**params)
        severity = cls.get_severity(score)
        return {'score': score, 'severity': severity, 'vector': vector_string, 'metrics': metrics}

    @classmethod
    def get_severity(cls, score):
        """Map score to severity label."""
        for low, high, label in cls.SEVERITY_RANGES:
            if low <= score <= high:
                return label
        return 'Unknown'

    @classmethod
    def to_vector_string(cls, av, ac, pr, ui, s, c, i, a):
        """Generate CVSS vector string from components."""
        return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


class CVEDatabase:
    """Store and query CVE vulnerability entries."""

    def __init__(self):
        self.cves = {}
        self.severity_index = collections.defaultdict(set)
        self.year_index = collections.defaultdict(set)
        self.product_index = collections.defaultdict(set)

    def add_cve(self, cve_id, description, cvss_vector=None, cvss_score=None,
                severity=None, affected_products=None, references=None, published=None):
        """Add a CVE entry to the database."""
        if cvss_vector:
            cvss_data = CVSSCalculator.from_vector(cvss_vector)
            if cvss_data:
                cvss_score = cvss_data['score']
                severity = cvss_data['severity']
        elif cvss_score is not None:
            severity = CVSSCalculator.get_severity(cvss_score)

        entry = {
            'id': cve_id,
            'description': description,
            'cvss_vector': cvss_vector,
            'cvss_score': cvss_score,
            'severity': severity,
            'affected_products': affected_products or [],
            'references': references or [],
            'published': published or datetime.now().isoformat(),
            'added_time': datetime.now().isoformat(),
        }

        self.cves[cve_id] = entry
        if severity:
            self.severity_index[severity].add(cve_id)
        year_match = re.match(r'CVE-(\d{4})-', cve_id)
        if year_match:
            self.year_index[year_match.group(1)].add(cve_id)
        for product in (affected_products or []):
            self.product_index[product.lower()].add(cve_id)

    def get_cve(self, cve_id):
        """Look up a CVE by ID."""
        return self.cves.get(cve_id)

    def search_by_severity(self, severity):
        """Find all CVEs with a given severity."""
        return [self.cves[cid] for cid in self.severity_index.get(severity, set()) if cid in self.cves]

    def search_by_product(self, product):
        """Find CVEs affecting a product."""
        return [self.cves[cid] for cid in self.product_index.get(product.lower(), set()) if cid in self.cves]

    def search_by_year(self, year):
        """Find CVEs from a given year."""
        return [self.cves[cid] for cid in self.year_index.get(str(year), set()) if cid in self.cves]

    def search_by_score_range(self, min_score, max_score):
        """Find CVEs within a CVSS score range."""
        return [c for c in self.cves.values() if c['cvss_score'] is not None and min_score <= c['cvss_score'] <= max_score]

    def get_stats(self):
        """Return database statistics."""
        return {
            'total': len(self.cves),
            'by_severity': {s: len(ids) for s, ids in self.severity_index.items()},
            'by_year': {y: len(ids) for y, ids in sorted(self.year_index.items())},
            'avg_cvss': round(sum(c['cvss_score'] for c in self.cves.values() if c['cvss_score'] is not None) /
                              max(1, sum(1 for c in self.cves.values() if c['cvss_score'] is not None)), 2),
        }

    def export_db(self, filepath):
        """Export database to JSON."""
        data = {
            'cves': self.cves,
            'export_time': datetime.now().isoformat(),
            'stats': self.get_stats(),
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def import_db(self, filepath):
        """Import database from JSON."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        for cve_id, entry in data.get('cves', {}).items():
            self.cves[cve_id] = entry
            if entry.get('severity'):
                self.severity_index[entry['severity']].add(cve_id)
            year_match = re.match(r'CVE-(\d{4})-', cve_id)
            if year_match:
                self.year_index[year_match.group(1)].add(cve_id)
            for product in entry.get('affected_products', []):
                self.product_index[product.lower()].add(cve_id)


class AttackChain:
    """Model and analyze attack chains (kill chains)."""

    PHASES = [
        'reconnaissance',
        'weaponization',
        'delivery',
        'exploitation',
        'installation',
        'command_and_control',
        'actions_on_objectives',
    ]

    def __init__(self, name, description=""):
        self.name = name
        self.description = description
        self.steps = []
        self.created_time = datetime.now().isoformat()

    def add_step(self, phase, technique, cve_ids=None, tools=None, description=""):
        """Add a step to the attack chain."""
        if phase not in self.PHASES:
            raise ValueError(f"Invalid phase: {phase}. Valid phases: {self.PHASES}")
        step = {
            'step_id': len(self.steps) + 1,
            'phase': phase,
            'technique': technique,
            'cve_ids': cve_ids or [],
            'tools': tools or [],
            'description': description,
        }
        self.steps.append(step)
        return step

    def get_phases_coverage(self):
        """Return which phases have steps."""
        covered = set(s['phase'] for s in self.steps)
        return {phase: phase in covered for phase in self.PHASES}

    def get_phase_steps(self, phase):
        """Get all steps in a specific phase."""
        return [s for s in self.steps if s['phase'] == phase]

    def get_all_cves(self):
        """Get all CVEs referenced in this chain."""
        cves = set()
        for step in self.steps:
            cves.update(step['cve_ids'])
        return list(cves)

    def get_chain_complexity(self):
        """Assess chain complexity."""
        phases_covered = len(set(s['phase'] for s in self.steps))
        total_steps = len(self.steps)
        unique_cves = len(self.get_all_cves())
        unique_tools = len(set(t for s in self.steps for t in s['tools']))

        if phases_covered >= 5 and total_steps >= 7:
            level = 'ADVANCED'
        elif phases_covered >= 3 and total_steps >= 4:
            level = 'INTERMEDIATE'
        else:
            level = 'BASIC'

        return {
            'level': level,
            'phases_covered': phases_covered,
            'total_steps': total_steps,
            'unique_cves': unique_cves,
            'unique_tools': unique_tools,
            'completeness': round(phases_covered / len(self.PHASES) * 100, 1),
        }

    def to_dict(self):
        """Serialize to dict."""
        return {
            'name': self.name,
            'description': self.description,
            'steps': self.steps,
            'complexity': self.get_chain_complexity(),
            'created_time': self.created_time,
        }

    @classmethod
    def from_dict(cls, data):
        """Deserialize from dict."""
        chain = cls(data['name'], data.get('description', ''))
        chain.steps = data.get('steps', [])
        chain.created_time = data.get('created_time', datetime.now().isoformat())
        return chain


class AttackChainAnalyzer:
    """Analyze and correlate attack chains."""

    def __init__(self):
        self.chains = {}

    def add_chain(self, chain):
        """Add an attack chain."""
        self.chains[chain.name] = chain

    def remove_chain(self, name):
        """Remove a chain by name."""
        return self.chains.pop(name, None) is not None

    def find_chains_with_cve(self, cve_id):
        """Find chains that reference a specific CVE."""
        return [c for c in self.chains.values() if cve_id in c.get_all_cves()]

    def find_chains_with_phase(self, phase):
        """Find chains containing a specific phase."""
        return [c for c in self.chains.values() if any(s['phase'] == phase for s in c.steps)]

    def find_common_techniques(self):
        """Find techniques common across multiple chains."""
        technique_chains = collections.defaultdict(set)
        for chain in self.chains.values():
            for step in chain.steps:
                technique_chains[step['technique']].add(chain.name)
        return {tech: list(chains) for tech, chains in technique_chains.items() if len(chains) > 1}

    def merge_chains(self, chain_names, new_name):
        """Merge multiple chains into one."""
        all_steps = []
        for name in chain_names:
            if name in self.chains:
                all_steps.extend(self.chains[name].steps)
        all_steps.sort(key=lambda s: self.PHASES.index(s['phase']) if s['phase'] in self.PHASES else 0)
        merged = AttackChain(new_name, f"Merged from: {', '.join(chain_names)}")
        merged.steps = all_steps
        return merged

    def generate_report(self):
        """Generate attack chain analysis report."""
        chains_data = []
        for chain in self.chains.values():
            chains_data.append(chain.to_dict())
        common_techs = self.find_common_techniques()
        all_cves = collections.Counter()
        for chain in self.chains.values():
            for cve in chain.get_all_cves():
                all_cves[cve] += 1
        return {
            'total_chains': len(self.chains),
            'chains': chains_data,
            'common_techniques': common_techs,
            'most_referenced_cves': [{'cve': c, 'count': n} for c, n in all_cves.most_common(20)],
        }


class RiskPrioritizer:
    """Prioritize risks based on vulnerability data and context."""

    def __init__(self):
        self.assets = {}
        self.vulnerabilities = {}
        self.risk_scores = {}

    def add_asset(self, asset_id, name, asset_type, criticality, exposure, business_value):
        """Register an asset for risk assessment."""
        self.assets[asset_id] = {
            'name': name,
            'type': asset_type,
            'criticality': criticality,
            'exposure': exposure,
            'business_value': business_value,
        }

    def add_vulnerability(self, vuln_id, cve_id, cvss_score, exploitability, asset_ids=None, patch_available=False):
        """Register a vulnerability."""
        self.vulnerabilities[vuln_id] = {
            'cve_id': cve_id,
            'cvss_score': cvss_score,
            'exploitability': exploitability,
            'asset_ids': asset_ids or [],
            'patch_available': patch_available,
        }

    def calculate_risk_score(self, vuln_id):
        """Calculate risk score for a vulnerability considering context."""
        vuln = self.vulnerabilities.get(vuln_id)
        if not vuln:
            return None

        cvss = vuln['cvss_score']
        exploit_factor = {
            'none': 0.0,
            'low': 0.2,
            'medium': 0.5,
            'high': 0.8,
            'weaponized': 1.0,
        }.get(vuln['exploitability'], 0.5)

        asset_criticality = 5.0
        asset_exposure = 5.0
        asset_business_value = 5.0

        if vuln['asset_ids']:
            crit_scores = []
            exp_scores = []
            val_scores = []
            for aid in vuln['asset_ids']:
                if aid in self.assets:
                    crit_scores.append(self.assets[aid]['criticality'])
                    exp_scores.append(self.assets[aid]['exposure'])
                    val_scores.append(self.assets[aid]['business_value'])
            if crit_scores:
                asset_criticality = max(crit_scores)
                asset_exposure = max(exp_scores)
                asset_business_value = max(val_scores)

        patch_penalty = 0.2 if vuln['patch_available'] else 0.0

        risk = (
            (cvss / 10.0) * 0.35 +
            exploit_factor * 0.25 +
            (asset_criticality / 10.0) * 0.15 +
            (asset_exposure / 10.0) * 0.10 +
            (asset_business_value / 10.0) * 0.15
        ) * (1.0 - patch_penalty)

        risk = min(round(risk * 100, 2), 100.0)

        if risk >= 80:
            priority = 'CRITICAL'
        elif risk >= 60:
            priority = 'HIGH'
        elif risk >= 40:
            priority = 'MEDIUM'
        elif risk >= 20:
            priority = 'LOW'
        else:
            priority = 'INFO'

        self.risk_scores[vuln_id] = {
            'risk_score': risk,
            'priority': priority,
            'cvss_contribution': round(cvss / 10.0 * 0.35 * 100, 2),
            'exploit_contribution': round(exploit_factor * 0.25 * 100, 2),
            'asset_contribution': round((asset_criticality / 10.0 * 0.15 + asset_exposure / 10.0 * 0.10 + asset_business_value / 10.0 * 0.15) * 100, 2),
            'patch_available': vuln['patch_available'],
        }
        return self.risk_scores[vuln_id]

    def prioritize_all(self):
        """Calculate and rank all vulnerability risk scores."""
        for vuln_id in self.vulnerabilities:
            self.calculate_risk_score(vuln_id)

        ranked = sorted(self.risk_scores.items(), key=lambda x: x[1]['risk_score'], reverse=True)
        return [
            {
                'rank': i + 1,
                'vuln_id': vid,
                **data,
                'cve_id': self.vulnerabilities[vid]['cve_id'],
                'cvss_score': self.vulnerabilities[vid]['cvss_score'],
            }
            for i, (vid, data) in enumerate(ranked)
        ]

    def get_top_risks(self, count=10):
        """Return top N risks."""
        prioritized = self.prioritize_all()
        return prioritized[:count]

    def generate_risk_report(self):
        """Generate comprehensive risk report."""
        prioritized = self.prioritize_all()
        priority_counts = collections.Counter(r['priority'] for r in prioritized)
        return {
            'report_time': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'total_assets': len(self.assets),
            'priority_distribution': dict(priority_counts),
            'top_risks': prioritized[:20],
            'prioritized_full': prioritized,
        }


class VulnCorrelator:
    """Main vulnerability correlation engine."""

    def __init__(self):
        self.cve_database = CVEDatabase()
        self.attack_chain_analyzer = AttackChainAnalyzer()
        self.risk_prioritizer = RiskPrioritizer()
        self.correlations = []

    def correlate_cve_chain(self, cve_id, chain_name):
        """Link a CVE to an attack chain."""
        cve = self.cve_database.get_cve(cve_id)
        chain = self.attack_chain_analyzer.chains.get(chain_name)
        if cve and chain:
            self.correlations.append({
                'type': 'cve_chain',
                'cve_id': cve_id,
                'chain_name': chain_name,
                'cve_severity': cve.get('severity'),
                'created': datetime.now().isoformat(),
            })
            return True
        return False

    def analyze_threat_landscape(self):
        """Analyze overall threat landscape from all data."""
        cve_stats = self.cve_database.get_stats()
        chain_report = self.attack_chain_analyzer.generate_report()
        risk_report = self.risk_prioritizer.generate_risk_report()
        return {
            'analysis_time': datetime.now().isoformat(),
            'cve_database': cve_stats,
            'attack_chains': chain_report,
            'risk_assessment': {
                'total_assets': risk_report['total_assets'],
                'total_vulnerabilities': risk_report['total_vulnerabilities'],
                'priority_distribution': risk_report['priority_distribution'],
                'top_critical_risks': [r for r in risk_report['top_risks'] if r['priority'] == 'CRITICAL'][:10],
            },
            'correlations': self.correlations,
        }

    def export_report(self, filepath):
        """Export full analysis report to JSON."""
        report = self.analyze_threat_landscape()
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)


if __name__ == '__main__':
    print("=== R3 — Vulnerability Correlation Engine ===")

    engine = VulnCorrelator()

    engine.cve_database.add_cve(
        "CVE-2024-1234", "Remote code execution via buffer overflow in web server",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        affected_products=["Apache HTTP Server", "Nginx"],
    )
    engine.cve_database.add_cve(
        "CVE-2024-5678", "SQL injection in login form allows authentication bypass",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        affected_products=["WordPress", "Drupal"],
    )
    engine.cve_database.add_cve(
        "CVE-2024-9012", "Privilege escalation through misconfigured sudo permissions",
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        affected_products=["Linux Kernel", "Ubuntu"],
    )

    print(f"CVEs loaded: {len(engine.cve_database.cves)}")
    crits = engine.cve_database.search_by_severity('Critical')
    print(f"Critical CVEs: {len(crits)}")
    apache = engine.cve_database.search_by_product('Apache HTTP Server')
    print(f"Apache vulns: {len(apache)}")

    chain1 = AttackChain("APT-WebAttack", "Web application exploitation chain")
    chain1.add_step('reconnaissance', 'Port scanning', tools=['nmap'])
    chain1.add_step('reconnaissance', 'Web fingerprinting', tools=['whatweb'])
    chain1.add_step('weaponization', 'Craft payload', cve_ids=['CVE-2024-1234'], tools=['msfvenom'])
    chain1.add_step('delivery', 'Send exploit', tools=['curl'])
    chain1.add_step('exploitation', 'Execute RCE', cve_ids=['CVE-2024-1234'])
    chain1.add_step('installation', 'Deploy backdoor', tools=['webshell'])
    chain1.add_step('command_and_control', 'C2 callback')
    chain1.add_step('actions_on_objectives', 'Data exfiltration')
    engine.attack_chain_analyzer.add_chain(chain1)

    print(f"\nAttack chain: {chain1.name}")
    print(f"Complexity: {chain1.get_chain_complexity()}")
    print(f"Chain CVEs: {chain1.get_all_cves()}")

    engine.risk_prioritizer.add_asset("web-01", "Production Web Server", "server", 9, 9, 8)
    engine.risk_prioritizer.add_asset("db-01", "Database Server", "database", 10, 5, 9)
    engine.risk_prioritizer.add_asset("dev-01", "Dev Workstation", "workstation", 3, 4, 2)

    engine.risk_prioritizer.add_vulnerability("vuln-001", "CVE-2024-1234", 9.8, "weaponized", ["web-01"])
    engine.risk_prioritizer.add_vulnerability("vuln-002", "CVE-2024-5678", 8.1, "high", ["web-01", "db-01"])
    engine.risk_prioritizer.add_vulnerability("vuln-003", "CVE-2024-9012", 7.8, "medium", ["dev-01"], patch_available=True)

    engine.correlate_cve_chain("CVE-2024-1234", "APT-WebAttack")

    top_risks = engine.risk_prioritizer.get_top_risks()
    print(f"\nRisk Prioritization:")
    for r in top_risks:
        print(f"  #{r['rank']} {r['vuln_id']} ({r['cve_id']}): {r['risk_score']} [{r['priority']}]")

    landscape = engine.analyze_threat_landscape()
    print(f"\nThreat Landscape:")
    print(f"  Total CVEs: {landscape['cve_database']['total']}")
    print(f"  Total Chains: {landscape['attack_chains']['total_chains']}")
    print(f"  Total Assets: {landscape['risk_assessment']['total_assets']}")
    print(f"  Priority Distribution: {landscape['risk_assessment']['priority_distribution']}")
    print(f"  Correlations: {len(landscape['correlations'])}")

    print("\nAnalysis complete.")
