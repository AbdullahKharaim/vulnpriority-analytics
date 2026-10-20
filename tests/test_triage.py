import tempfile
import unittest
from datetime import date

from vulnprio.ingest import parse_findings_csv
from vulnprio.models import Finding, REASON_CODES, TriageConfig
from vulnprio.storage import connect
from vulnprio.triage import run_triage
from .helpers import SAMPLES, cve, kev, memory_database, sample_database, snapshot


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_database()
        self.addCleanup(self.conn.close)

    def test_tier_conditions_reasons_and_escalation(self):
        names = [cve(self.conn, i, score=score) for i, score in enumerate((9, 9, 9, 7, 6, 0, 0, None), 1)]
        snapshot(self.conn, scores=dict(zip(names, (.1, .0, .0, .01, .01, .0, .0, .0))))
        kev(self.conn, names[0], "2024-12-31", ransomware=True)
        findings = [Finding("kev", names[0], "high", True), Finding("critical-internet", names[1], internet_facing=True),
                    Finding("critical", names[2]), Finding("high-escalated", names[3], "high"),
                    Finding("medium", names[4]), Finding("low-escalated", names[5], "high"),
                    Finding("low", names[6]), Finding("known-unscored", names[7]), Finding("unknown", "CVE-2000-9999")]
        result = run_triage(self.conn, findings, rows_skipped=3)
        items = {item["asset_id"]: item for item in result["items"]}
        self.assertEqual(items["kev"]["reasons"], ["KEV", "RANSOMWARE", "EPSS_HIGH", "CRITICAL_INTERNET_FACING", "CVSS_CRITICAL"])
        self.assertEqual(items["critical-internet"]["tier"], "P2")
        self.assertEqual(items["critical"]["tier"], "P3")
        self.assertEqual(items["high-escalated"]["tier"], "P2")
        self.assertEqual(items["high-escalated"]["reasons"], ["CVSS_HIGH", "EPSS_MEDIUM", "ESCALATED_ASSET_CRITICALITY"])
        self.assertEqual(items["medium"]["tier"], "P3")
        self.assertEqual(items["low-escalated"]["tier"], "P3")
        self.assertEqual(items["low"]["tier"], "P4")
        self.assertEqual(items["unknown"]["reasons"], ["UNKNOWN_CVE"])
        self.assertEqual(items["known-unscored"]["reasons"], [])
        self.assertEqual(result["summary"], {"findings": 9, "rows_skipped": 3,
                                             "tiers": {"P1": 1, "P2": 2, "P3": 3, "P4": 3},
                                             "kev": 1, "ransomware": 1, "unknown_cves": 1})
        for item in result["items"]:
            self.assertEqual(item["reasons"], sorted(item["reasons"], key=REASON_CODES.index))

    def test_as_of_snapshot_and_future_kev_ignored(self):
        name = cve(self.conn, 1, score=6)
        snapshot(self.conn, "2025-01-01", {name: .01})
        snapshot(self.conn, "2025-04-01", {name: .9})
        kev(self.conn, name, "2025-03-01", ransomware=True)
        findings = [Finding("a", name)]
        early = run_triage(self.conn, findings, date(2024, 12, 31))
        self.assertIsNone(early["epss_snapshot"])
        self.assertIsNone(early["items"][0]["epss"])
        result = run_triage(self.conn, findings, date(2025, 2, 1))
        self.assertEqual(result["epss_snapshot"], "2025-01-01")
        self.assertEqual(result["items"][0]["tier"], "P3")
        self.assertFalse(result["items"][0]["kev"])
        self.assertFalse(result["items"][0]["ransomware"])
        self.assertIsNone(result["items"][0]["kev_date_added"])
        self.assertEqual(run_triage(self.conn, findings, date(2025, 3, 1))["items"][0]["tier"], "P1")
        self.assertEqual(run_triage(self.conn, findings)["epss_snapshot"], "2025-04-01")

    def test_raw_epss_sort_before_rounding_and_tie_breaks(self):
        names = [cve(self.conn, i, score=score) for i, score in enumerate((0, 0, 0, None), 1)]
        snapshot(self.conn, scores={names[0]: .00000011, names[1]: .00000012, names[2]: 0})
        findings = [Finding("z", names[0]), Finding("a", names[0]), Finding("z", names[1]),
                    Finding("a", names[2]), Finding("a", names[3]), Finding("a", "CVE-2000-9999")]
        result = run_triage(self.conn, findings)
        self.assertEqual([(i["asset_id"], i["cve_id"]) for i in result["items"]],
                         [("z", names[1]), ("a", names[0]), ("z", names[0]), ("a", names[2]),
                          ("a", "CVE-2000-9999"), ("a", names[3])])
        self.assertEqual([i["rank"] for i in result["items"]], list(range(1, 7)))
        self.assertEqual(result["items"][0]["epss"], 0.0)

    def test_custom_config_and_unknown_with_reference_data(self):
        name = cve(self.conn, 1, score=8)
        snapshot(self.conn, scores={"CVE-2000-9999": .3})
        kev(self.conn, "CVE-2000-9998", "2025-01-01")
        result = run_triage(self.conn, [Finding("a", name, internet_facing=True),
                                       Finding("a", "CVE-2000-9999"), Finding("a", "CVE-2000-9998")],
                            config=TriageConfig(.2, .1, 8, 6))
        self.assertEqual(result["summary"]["unknown_cves"], 0)
        self.assertEqual(result["summary"]["tiers"], {"P1": 1, "P2": 2, "P3": 0, "P4": 0})

    def test_empty_and_sample(self):
        result = run_triage(self.conn, [])
        self.assertIsNone(result["epss_snapshot"])
        self.assertEqual(result["summary"]["tiers"], dict.fromkeys(("P1", "P2", "P3", "P4"), 0))
        with tempfile.TemporaryDirectory() as directory:
            path, _ = sample_database(directory)
            conn = connect(path)
            try:
                findings, skipped = parse_findings_csv(str(SAMPLES / "findings-sample.csv"))
                result = run_triage(conn, findings, rows_skipped=skipped)
                self.assertEqual(result["summary"]["tiers"], {"P1": 1, "P2": 1, "P3": 2, "P4": 2})
                items = {i["asset_id"] + i["cve_id"]: i for i in result["items"]}
                self.assertEqual(items["core-dbCVE-2024-0105"]["reasons"], ["ESCALATED_ASSET_CRITICALITY"])
                self.assertEqual(items["hr-appCVE-2023-9999"]["reasons"], ["UNKNOWN_CVE"])
            finally:
                conn.close()
