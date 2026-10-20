import unittest
from datetime import date, timedelta

from vulnprio.insights import compute_insights
from vulnprio.models import CVSS_BANDS
from .helpers import cve, kev, memory_database


class InsightsTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_database()
        self.addCleanup(self.conn.close)
        self.start = date(2025, 1, 1)
        self.end = date(2025, 2, 1)

    def test_lag_boundaries_bands_and_top_list_ties(self):
        lags = [-1, 0, 1, 7, 8, 30, 31, 90, 91, 365, 366]
        scores = [9, 7, 4, .1, 0, None, 10, 8, 5, 3, None]
        for i, (lag, score) in enumerate(zip(lags, scores), 1):
            name = cve(self.conn, i, (self.start - timedelta(days=lag)).isoformat(), score)
            kev(self.conn, name, self.start.isoformat(), "B" if i % 2 else "A", i % 2 == 0,
                ("CWE-100",) if i % 2 else ("CWE-2",))
        # Unknown NVD entries still contribute to KEV/vendor/CWE denominators.
        kev(self.conn, "CVE-2000-9999", self.end.isoformat(), "A", True, ("CWE-2",))
        kev(self.conn, "CVE-2000-9998", "2025-02-02", "Outside", True, ("CWE-999",))
        result = compute_insights(self.conn, self.start, self.end)
        self.assertEqual(result["kev_entries"], 12)
        self.assertEqual(result["with_nvd"], 11)
        self.assertEqual(result["ransomware"], {"count": 6, "share": .5})
        self.assertEqual(result["lag_days"]["count"], 11)
        self.assertEqual(result["lag_days"]["median"], 30.0)
        self.assertEqual(result["lag_days"]["mean"], round(sum(lags) / 11, 1))
        self.assertEqual([b["count"] for b in result["lag_days"]["buckets"]], [2, 2, 2, 2, 2, 1])
        self.assertEqual([b["band"] for b in result["cvss_bands"]], list(CVSS_BANDS))
        self.assertEqual([b["count"] for b in result["cvss_bands"]], [2, 2, 2, 2, 1, 2])
        self.assertEqual(result["below_critical_share"], round(7 / 9, 6))
        self.assertEqual(result["below_high_share"], round(5 / 9, 6))
        self.assertEqual(result["top_vendors"], [{"vendor": "A", "count": 6, "ransomware": 6},
                                                 {"vendor": "B", "count": 6, "ransomware": 0}])
        self.assertEqual(result["top_cwes"], [{"cwe": "CWE-2", "count": 6}, {"cwe": "CWE-100", "count": 6}])
        self.assertEqual(len(compute_insights(self.conn, self.start, self.end, 1)["top_vendors"]), 1)

    def test_empty_and_unscored_denominators(self):
        result = compute_insights(self.conn, self.start, self.end)
        self.assertIsNone(result["ransomware"]["share"])
        self.assertIsNone(result["lag_days"]["median"])
        self.assertIsNone(result["lag_days"]["mean"])
        for bucket in result["lag_days"]["buckets"]:
            self.assertEqual((bucket["count"], bucket["share"]), (0, None))
        for band in result["cvss_bands"]:
            self.assertEqual((band["count"], band["share"]), (0, None))
        name = cve(self.conn, 1, score=None)
        kev(self.conn, name, self.start.isoformat())
        result = compute_insights(self.conn, self.start, self.end)
        self.assertIsNone(result["below_critical_share"])
        self.assertIsNone(result["below_high_share"])
        self.assertEqual(result["cvss_bands"][-1]["share"], 1.0)
