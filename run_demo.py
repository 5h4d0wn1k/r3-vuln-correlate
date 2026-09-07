#!/usr/bin/env python3
"""R3 — Vulnerability Correlator CLI.

Joins a vulnerability-scanner JSON report + asset-inventory JSON fixture and
emits a prioritized risk report. Preservation and use of the CVSS / risk
engine from the legacy `vuln_correlate.py`.
"""
import argparse
import json
import os
import sys

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

from vuln_correlate import CVSSCalculator, VulnCorrelator  # noqa: E402

FIXTURE_DIR = os.path.join(script_dir, "fixtures")


def load_json(path):
    with open(path) as f:
        return json.load(f)


def correlate(scan_path, inventory_path):
    """Join scanner findings with asset inventory, compute prioritized risk report.

    Returns dict with prioritized findings, per-asset rollups, and summary.
    """
    scan = load_json(scan_path)
    inventory = load_json(inventory_path)

    assets_by_id = {a["asset_id"]: a for a in inventory.get("assets", [])}

    findings = []
    for f in scan.get("findings", []):
        asset_id = f.get("asset_id")
        asset = assets_by_id.get(asset_id, {})
        cvss = f.get("cvss_score")

        # Recompute severity from CVSS if absent/unknown
        severity = f.get("severity")
        if not severity or severity.upper() == "UNKNOWN":
            severity = CVSSCalculator.get_severity(cvss) if cvss is not None else "Unknown"

        risk = _risk_score(
            cvss=cvss or 0.0,
            exploitability=f.get("exploitability", "medium"),
            criticality=asset.get("criticality", 5),
            exposure=asset.get("exposure", 5),
            business_value=asset.get("business_value", 5),
            patch_available=bool(f.get("patch_available", False)),
        )

        findings.append({
            "asset_id": asset_id,
            "asset_name": asset.get("name", asset_id),
            "asset_type": asset.get("type", "unknown"),
            "cve_id": f.get("cve_id"),
            "cvss_score": cvss,
            "severity": severity,
            "exploitability": f.get("exploitability", "medium"),
            "patch_available": bool(f.get("patch_available", False)),
            "criticality": asset.get("criticality", 5),
            "exposure": asset.get("exposure", 5),
            "business_value": asset.get("business_value", 5),
            "risk_score": round(risk["risk"], 2),
            "priority": risk["priority"],
        })

    findings.sort(key=lambda x: x["risk_score"], reverse=True)
    for i, f in enumerate(findings, 1):
        f["rank"] = i

    per_asset = {}
    for f in findings:
        a = per_asset.setdefault(f["asset_id"], {
            "asset_id": f["asset_id"],
            "name": f["asset_name"],
            "type": f["asset_type"],
            "criticality": f["criticality"],
            "findings": 0,
            "max_risk": 0.0,
            "max_priority": "INFO",
        })
        a["findings"] += 1
        a["max_risk"] = max(a["max_risk"], f["risk_score"])
        a["max_priority"] = max([a["max_priority"], f["priority"]], key=_priority_order)

    priority_counts = {}
    for f in findings:
        priority_counts[f["priority"]] = priority_counts.get(f["priority"], 0) + 1

    return {
        "report_time": str(__import__("datetime").datetime.now().isoformat()),
        "scanner": scan.get("scanner", "unknown"),
        "total_findings": len(findings),
        "total_assets": len(inventory.get("assets", [])),
        "priority_distribution": dict(sorted(priority_counts.items(), key=lambda kv: _priority_order(kv[0]))),
        "prioritized_findings": findings,
        "asset_rollup": sorted(per_asset.values(), key=lambda a: _priority_order(a["max_priority"]), reverse=True),
    }


_PRIORITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def _priority_order(p):
    return _PRIORITY_ORDER.get(str(p).upper(), 1)


def _risk_score(cvss, exploitability, criticality, exposure, business_value, patch_available):
    exploit_factor = {
        "none": 0.0, "low": 0.2, "medium": 0.5, "high": 0.8, "weaponized": 1.0,
    }.get(exploitability, 0.5)
    patch_penalty = 0.2 if patch_available else 0.0
    risk = (
        (cvss / 10.0) * 0.35 +
        exploit_factor * 0.25 +
        (criticality / 10.0) * 0.15 +
        (exposure / 10.0) * 0.10 +
        (business_value / 10.0) * 0.15
    ) * (1.0 - patch_penalty)
    risk = min(round(risk * 100, 2), 100.0)
    if risk >= 80:
        priority = "CRITICAL"
    elif risk >= 60:
        priority = "HIGH"
    elif risk >= 40:
        priority = "MEDIUM"
    elif risk >= 20:
        priority = "LOW"
    else:
        priority = "INFO"
    return {"risk": risk, "priority": priority}


def write_report(report_dir, report, markdown):
    os.makedirs(report_dir, exist_ok=True)
    jp = os.path.join(report_dir, "r3_report.json")
    mp = os.path.join(report_dir, "r3_report.md")
    with open(jp, "w") as f:
        json.dump(report, f, indent=2)
    with open(mp, "w") as f:
        f.write(markdown)
    return jp, mp


def to_markdown(report):
    lines = ["# R3 Vulnerability Correlation Report", ""]
    lines.append(f"- Scanner: {report['scanner']}")
    lines.append(f"- Total findings: {report['total_findings']}")
    lines.append(f"- Total assets: {report['total_assets']}")
    lines.append(f"- Priority distribution: {report['priority_distribution']}")
    lines.append("")
    lines.append("## Prioritized Findings")
    lines.append("| Rank | Asset | CVE | CVSS | Severity | Exploit | Risk | Priority |")
    lines.append("|------|-------|-----|------|----------|---------|------|----------|")
    for f in report["prioritized_findings"]:
        lines.append(
            f"| {f['rank']} | {f['asset_id']} ({f['asset_name']}) | {f['cve_id']} | "
            f"{f['cvss_score']} | {f['severity']} | {f['exploitability']} | "
            f"{f['risk_score']} | {f['priority']} |"
        )
    lines.append("")
    lines.append("## Asset Rollup")
    lines.append("| Asset | Type | Findings | Max Risk | Max Priority |")
    lines.append("|-------|------|----------|----------|--------------|")
    for a in report["asset_rollup"]:
        lines.append(f"| {a['asset_id']} | {a['type']} | {a['findings']} | {a['max_risk']} | {a['max_priority']} |")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="vuln_correlate",
        description="R3 — Vulnerability Correlator: joins scanner JSON + asset inventory, emits prioritized risk report.",
    )
    parser.add_argument("scan", nargs="?", default=os.path.join(FIXTURE_DIR, "scan_results.json"),
                        help="Vuln scanner JSON (default: fixtures/scan_results.json)")
    parser.add_argument("--inventory", default=os.path.join(FIXTURE_DIR, "asset_inventory.json"),
                        help="Asset inventory JSON (default: fixtures/asset_inventory.json)")
    parser.add_argument("-o", "--report-dir", default="reports",
                        help="Directory to write reports to (default: reports)")
    parser.add_argument("--json-only", action="store_true", help="Print JSON report only")
    args = parser.parse_args(argv)

    report = correlate(args.scan, args.inventory)

    print("=" * 70)
    print("  R3 — Vulnerability Correlator: prioritized risk report")
    print("=" * 70)
    print(f"  Scanner          : {report['scanner']}")
    print(f"  Total findings   : {report['total_findings']}")
    print(f"  Total assets     : {report['total_assets']}")
    print(f"  Priority dist    : {report['priority_distribution']}")
    print()
    print("  Prioritized findings (top 10):")
    hdr = f"  {'rank':<5} {'asset':<8} {'cve':<16} {'cvss':<6} {'severity':<9} {'risk':<7} {'prio'}"
    print(hdr)
    print("  " + "-" * (len(hdr) - 1))
    for f in report["prioritized_findings"][:10]:
        print(f"  {f['rank']:<5} {f['asset_id']:<8} {str(f['cve_id']):<16} {str(f['cvss_score']):<6} "
              f"{f['severity']:<9} {f['risk_score']:<7} {f['priority']}")
    print()
    print("  Asset rollup:")
    for a in report["asset_rollup"]:
        print(f"    {a['asset_id']}: {a['findings']} findings, max risk {a['max_risk']} [{a['max_priority']}]")

    jp, mp = write_report(args.report_dir, report, to_markdown(report))
    print()
    print("  Reports written to:")
    print(f"    {jp}")
    print(f"    {mp}")

    if args.json_only:
        print(json.dumps(report, indent=2))

    print("\n  Analysis complete — exit 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
