import math
import random
import tempfile
import unittest
from datetime import date

from vulnprio.backtest import run_backtest
from vulnprio.models import BacktestConfig, STRATEGIES, VulnprioError
from vulnprio.storage import connect
from .helpers import cve, kev, memory_database, sample_database, snapshot


class BacktestTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_database()
        self.addCleanup(self.conn.close)
        self.d = date(2025, 1, 1)
        self.config = BacktestConfig(10, 30, .8, 40, 17, .8)

    def populate(self):
        scores = {}
        a = cve(self.conn, 1, "2024-12-22", 9)
        b = cve(self.conn, 2, score=9)
        c = cve(self.conn, 3, score=7)
        d = cve(self.conn, 4, score=6)
        scores.update({a: .8, b: .8, c: .9, d: .01})
        kev(self.conn, a, "2025-01-31")
        kev(self.conn, b, "2025-02-01")
        kev(self.conn, c, "2025-01-02")
        kev(self.conn, cve(self.conn, 5, score=None), "2025-01-03")
        kev(self.conn, cve(self.conn, 6, score=None), "2025-01-01")
        kev(self.conn, cve(self.conn, 7), "2025-01-01")
        known = cve(self.conn, 8)
        scores[known] = .99
        kev(self.conn, known, "2025-01-01")
        for number, published, status in ((9, "2025-01-01", "Analyzed"),
                                           (10, "2024-12-21", "Analyzed"),
                                           (11, "2024-12-25", "Rejected")):
            name = cve(self.conn, number, published, status=status)
            scores[name] = 1
            kev(self.conn, name, "2025-01-02")
        snapshot(self.conn, scores=scores)

    def test_population_boundaries_filters_and_metrics(self):
        self.populate()
        result = run_backtest(self.conn, config=self.config)
        row = result["per_date"][0]
        self.assertEqual(result["decision_dates"], ["2025-01-01"])
        self.assertEqual((row["population"], row["positives"], row["base_rate"]), (4, 2, .5))
        self.assertEqual((row["excluded_no_cvss"], row["excluded_no_epss"],
                          row["excluded_known_exploited"], row["positives_without_cvss"]), (2, 1, 1, 1))
        self.assertEqual(row["window_end"], "2025-01-31")
        expected = [
            (2, 1, .5, .5, .5, 1.0), (3, 2, .75, 1.0, .666667, 1.333333),
            (2, 2, .5, 1.0, 1.0, 2.0), (3, 2, .75, 1.0, .666667, 1.333333),
        ]
        self.assertEqual([m["strategy"] for m in row["strategies"]], list(STRATEGIES))
        for metrics, values in zip(row["strategies"], expected):
            self.assertEqual(tuple(metrics[key] for key in
                                   ("flagged", "true_positives", "effort", "coverage", "efficiency", "lift")), values)
        self.assertEqual(result["pooled"]["strategies"], row["strategies"])
        self.assertEqual(result["effort_curve"]["EPSS"], [.5, .5, .5, .5, .5, 1.0, 1.0, 1.0])
        self.assertEqual(result["effort_curve"]["CVSS"], [.5, .5, .5, .5, .5, .5, .5, 1.0])

    def test_bootstrap_exact_draws_and_determinism(self):
        self.populate()
        result = run_backtest(self.conn, config=self.config)
        rng = random.Random(17)
        # Positive instances in CVE order have differences 0 and 1.
        draws = sorted(sum([0, 1][int(rng.random() * 2)] for _ in range(2)) / 2 for _ in range(40))
        low = int(math.floor(40 * (1 - .8) / 2 + 1e-9))
        self.assertEqual(result["bootstrap"], {
            "compare": ["EPSS_EFFORT_MATCHED", "CVSS_CRITICAL"], "metric": "coverage_difference",
            "positives": 2, "iterations": 40, "confidence": .8, "seed": 17,
            "point_estimate": .5, "ci_low": draws[low], "ci_high": draws[39 - low],
            "significant": draws[low] > 0 or draws[39 - low] < 0,
        })
        self.assertEqual(result, run_backtest(self.conn, config=self.config))

    def test_empty_population_no_positives_and_no_flags(self):
        kev(self.conn, "CVE-2000-9999", "2025-02-01")
        snapshot(self.conn)
        result = run_backtest(self.conn, config=self.config)
        self.assertIsNone(result["pooled"]["base_rate"])
        self.assertIsNone(result["bootstrap"])
        self.assertEqual(result["effort_curve"]["EPSS"], [None] * 8)
        for metrics in result["pooled"]["strategies"]:
            self.assertEqual(metrics["effort"], 0.0)
            for key in ("coverage", "efficiency", "lift"):
                self.assertIsNone(metrics[key])
        name = cve(self.conn, 1, score=5)
        self.conn.execute("INSERT INTO epss VALUES (?, ?, ?, ?)", ("2025-01-01", name, .001, None))
        result = run_backtest(self.conn, config=self.config)
        self.assertEqual(result["pooled"]["base_rate"], 0.0)
        self.assertIsNone(result["pooled"]["strategies"][0]["efficiency"])
        self.conn.execute("UPDATE cves SET cvss_score = ?", (9,))
        result = run_backtest(self.conn, config=self.config)
        critical = result["pooled"]["strategies"][0]
        self.assertEqual(critical["efficiency"], 0.0)
        self.assertIsNone(critical["coverage"])
        self.assertIsNone(critical["lift"])

    def test_positive_with_zero_critical_effort(self):
        a = cve(self.conn, 1, score=6)
        snapshot(self.conn, scores={a: .9})
        kev(self.conn, a, "2025-01-31")
        result = run_backtest(self.conn, config=self.config)
        self.assertEqual(result["pooled"]["strategies"][2]["flagged"], 0)
        self.assertEqual(result["pooled"]["strategies"][2]["coverage"], 0.0)
        self.assertEqual(result["bootstrap"]["point_estimate"], 0.0)
        self.assertFalse(result["bootstrap"]["significant"])

    def test_effort_curve_integer_ceiling(self):
        scores = {}
        for number in range(1, 102):
            name = cve(self.conn, number, score=5)
            scores[name] = 1 - number / 1000
            if number == 2:
                kev(self.conn, name, "2025-01-31")
        snapshot(self.conn, scores=scores)
        result = run_backtest(self.conn, config=self.config)
        # At 1% of N=101, the budget is two findings, which catches #2.
        self.assertEqual(result["pooled"]["population"], 101)
        self.assertEqual(result["effort_curve"]["EPSS"][0], 1.0)
        self.assertEqual(result["effort_curve"]["CVSS"][0], 1.0)

    def test_cvss_curve_ties_use_cve_id_without_epss(self):
        a = cve(self.conn, 1, score=9)
        b = cve(self.conn, 2, score=9)
        snapshot(self.conn, scores={a: .01, b: .9})
        kev(self.conn, a, "2025-01-31")
        result = run_backtest(self.conn, config=self.config)
        # A one-finding budget selects a by CVE ID, even though b has higher EPSS.
        self.assertEqual(result["effort_curve"]["CVSS"][0], 1.0)
        self.assertEqual(result["effort_curve"]["EPSS"][0], 0.0)

    def test_pooled_counts_are_not_mean_of_date_ratios(self):
        a = cve(self.conn, 1, "2024-12-25", 9)
        b = cve(self.conn, 2, "2024-12-25", 5)
        c = cve(self.conn, 3, "2024-12-25", 5)
        kev(self.conn, a, "2025-01-03")
        kev(self.conn, b, "2025-01-04")
        kev(self.conn, "CVE-2000-9999", "2025-02-10")
        snapshot(self.conn, "2025-01-01", {a: .1})
        snapshot(self.conn, "2025-01-02", {a: .1, b: .2, c: .3})
        result = run_backtest(self.conn, [date(2025, 1, 2), self.d, self.d], self.config)
        self.assertEqual(result["decision_dates"], ["2025-01-01", "2025-01-02"])
        pooled = result["pooled"]
        self.assertEqual((pooled["population"], pooled["positives"], pooled["base_rate"]), (4, 3, .75))
        self.assertEqual(pooled["strategies"][0]["effort"], .5)
        self.assertEqual(pooled["strategies"][0]["coverage"], .666667)

    def test_date_validation_exact_errors(self):
        with self.assertRaises(VulnprioError) as caught:
            run_backtest(self.conn)
        self.assertEqual(str(caught.exception), "KEV table is empty")
        kev(self.conn, "CVE-2000-9999", "2025-01-31")
        with self.assertRaises(VulnprioError) as caught:
            run_backtest(self.conn, config=self.config)
        self.assertEqual(str(caught.exception), "no EPSS snapshot has a complete outcome window")
        snapshot(self.conn)
        with self.assertRaises(VulnprioError) as caught:
            run_backtest(self.conn, [date(2024, 1, 1)], self.config)
        self.assertEqual(str(caught.exception), "no EPSS snapshot for 2024-01-01")
        snapshot(self.conn, "2025-01-02")
        with self.assertRaises(VulnprioError) as caught:
            run_backtest(self.conn, [date(2025, 1, 2)], self.config)
        self.assertEqual(str(caught.exception), "outcome window for 2025-01-02 ends after the KEV data (2025-01-31)")
        self.assertEqual(run_backtest(self.conn, config=self.config)["decision_dates"], ["2025-01-01"])

    def test_sample_positive_windows(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _ = sample_database(directory)
            conn = connect(path)
            try:
                rows = run_backtest(conn)["per_date"]
                self.assertEqual([(r["population"], r["positives"]) for r in rows], [(37, 6), (37, 6)])
            finally:
                conn.close()
