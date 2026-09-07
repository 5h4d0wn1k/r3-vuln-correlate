#!/usr/bin/env python3
"""R3 — Vulnerability Correlator: unit tests."""
import json
import os
import sys
import tempfile
import unittest

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(script_dir, ".."))

from run_demo import (  # noqa: E402
    FIXTURE_DIR,
    _priority_order,
    _risk_score,
    correlate,
    to_markdown,
    write_report,
)


class TestRiskScore(unittest.TestCase):
    def test_critical_weaponized_high_asset(self):
        r = _risk_score(9.8, "weaponized", 9, 9, 8, patch_available=False)
        self.assertGreaterEqual(r["risk"], 80)
        self.assertEqual(r["priority"], "CRITICAL")

    def test_patch_penalty(self):
        patched = _risk_score(9.8, "weaponized", 9, 9, 8, patch_available=True)
        unpatched = _risk_score(9.8, "weaponized", 9, 9, 8, patch_available=False)
        self.assertLess(patched["risk"], unpatched["risk"])

    def test_low_risk_is_low(self):
        r = _risk_score(2.0, "none", 2, 2, 2, patch_available=True)
        self.assertIn(r["priority"], {"LOW", "INFO"})

    def test_risk_range(self):
        for cvss in (1.0, 5.0, 10.0):
            r = _risk_score(cvss, "medium", 5, 5, 5, patch_available=False)
            self.assertLessEqual(r["risk"], 100.0)
            self.assertGreaterEqual(r["risk"], 0.0)


class TestCorrelate(unittest.TestCase):
    def test_joins_fixtures(self):
        report = correlate(
            os.path.join(FIXTURE_DIR, "scan_results.json"),
            os.path.join(FIXTURE_DIR, "asset_inventory.json"),
        )
        self.assertEqual(report["total_findings"], 5)
        self.assertEqual(report["total_assets"], 3)

    def test_prioritized_sorted(self):
        report = correlate(
            os.path.join(FIXTURE_DIR, "scan_results.json"),
            os.path.join(FIXTURE_DIR, "asset_inventory.json"),
        )
        risks = [f["risk_score"] for f in report["prioritized_findings"]]
        self.assertEqual(risks, sorted(risks, reverse=True))

    def test_findings_have_asset_join(self):
        report = correlate(
            os.path.join(FIXTURE_DIR, "scan_results.json"),
            os.path.join(FIXTURE_DIR, "asset_inventory.json"),
        )
        for f in report["prioritized_findings"]:
            self.assertIn("asset_name", f)
            self.assertIn("rank", f)
            self.assertIn("priority", f)

    def test_patch_penalty_lowers_rank(self):
        report = correlate(
            os.path.join(FIXTURE_DIR, "scan_results.json"),
            os.path.join(FIXTURE_DIR, "asset_inventory.json"),
        )
        patched = [f for f in report["prioritized_findings"] if f["patch_available"]]
        for f in patched:
            self.assertIs(f["patch_available"], True)

    def test_asset_rollup(self):
        report = correlate(
            os.path.join(FIXTURE_DIR, "scan_results.json"),
            os.path.join(FIXTURE_DIR, "asset_inventory.json"),
        )
        self.assertEqual(len(report["asset_rollup"]), 3)
        for a in report["asset_rollup"]:
            self.assertIn("max_risk", a)
            self.assertIn("findings", a)

    def test_cve_present(self):
        report = correlate(
            os.path.join(FIXTURE_DIR, "scan_results.json"),
            os.path.join(FIXTURE_DIR, "asset_inventory.json"),
        )
        cves = {f["cve_id"] for f in report["prioritized_findings"]}
        self.assertIn("CVE-2024-1234", cves)


class TestPriorityOrder(unittest.TestCase):
    def test_ordering(self):
        self.assertGreater(_priority_order("CRITICAL"), _priority_order("HIGH"))
        self.assertGreater(_priority_order("HIGH"), _priority_order("MEDIUM"))
        self.assertEqual(_priority_order("INFO"), 1)


class TestReport(unittest.TestCase):
    def setUp(self):
        self.report = correlate(
            os.path.join(FIXTURE_DIR, "scan_results.json"),
            os.path.join(FIXTURE_DIR, "asset_inventory.json"),
        )

    def test_write_report_files(self):
        with tempfile.TemporaryDirectory() as td:
            jp, mp = write_report(td, self.report, to_markdown(self.report))
            self.assertTrue(os.path.exists(jp))
            self.assertTrue(os.path.exists(mp))
            with open(jp) as f:
                self.assertEqual(json.load(f)["total_findings"], 5)

    def test_markdown(self):
        md = to_markdown(self.report)
        self.assertIn("R3 Vulnerability Correlation", md)
        self.assertIn("Prioritized Findings", md)


class TestMainCLI(unittest.TestCase):
    def test_help(self):
        from run_demo import main
        with self.assertRaises(SystemExit) as ctx:
            main(["--help"])
        self.assertEqual(ctx.exception.code, 0)

    def test_demo_runs(self):
        from run_demo import main
        with tempfile.TemporaryDirectory() as td:
            ret = main(["-o", td])
            self.assertEqual(ret, 0)
            self.assertTrue(os.path.exists(os.path.join(td, "r3_report.json")))


if __name__ == "__main__":
    unittest.main()
