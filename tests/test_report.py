import csv
import io
import json
import tempfile
import unittest
from datetime import date
from html.parser import HTMLParser

from vulnprio.backtest import run_backtest
from vulnprio.insights import compute_insights
from vulnprio.models import Finding
from vulnprio.report import (build_analysis_report, render_analysis_html, render_analysis_markdown,
                             render_triage_csv, render_triage_markdown, to_json)
from vulnprio.storage import connect
from vulnprio.triage import run_triage
from .helpers import sample_database


class ChartParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.charts = []
        self.in_svg = False
        self.external = []

    def handle_starttag(self, tag, attrs):
        if tag == "svg":
            self.in_svg = True
            self.charts.append(0)
        if tag == "title" and self.in_svg:
            self.charts[-1] += 1
        if tag in {"script", "link"} or any(name == "src" for name, _ in attrs):
            self.external.append(tag)

    def handle_endtag(self, tag):
        if tag == "svg":
            self.in_svg = False


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path, self.summary = sample_database(self.tmp.name)
        self.conn = connect(path)
        self.addCleanup(self.conn.close)
        self.conn.execute("UPDATE kev SET vendor = ? WHERE vendor = ?", ('V|<b>&"', "Acme"))
        backtest = run_backtest(self.conn)
        insights = compute_insights(self.conn, date(2025, 1, 1), date(2026, 4, 1))
        self.report = build_analysis_report(self.conn, backtest, insights)

    def test_json_exact_and_report_envelope(self):
        obj = {"z": None, "é": [True], "a": 1}
        self.assertEqual(to_json(obj), json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        self.assertEqual(to_json(obj), to_json(dict(reversed(list(obj.items())))))
        self.assertEqual(set(self.report), {"schema_version", "tool", "version", "data", "backtest", "insights"})
        self.assertEqual(self.report["data"], self.summary)
        self.assertEqual(self.report["version"], "1.0.0")

    def test_markdown_sections_order_and_escaping(self):
        text = render_analysis_markdown(self.report)
        self.assertTrue(text.startswith("# Vulnerability Prioritization Report\n"))
        names = ("Data", "Pooled results", "Statistical comparison", "Per decision date", "Effort curve",
                 "Exploitation insights", "Limitations")
        offsets = [text.index("\n## " + name + "\n") for name in names]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn("| Strategy | Flagged | Effort | Coverage | Efficiency | Lift |", text)
        self.assertIn('V\\|<b>&"', text)
        self.assertIn("confidence interval", text)
        self.assertTrue(text.endswith("\n"))
        self.report["backtest"]["bootstrap"] = None
        self.assertIn("Not enough positives for a bootstrap.", render_analysis_markdown(self.report))

    def test_html_is_self_contained_escaped_and_deterministic(self):
        text = render_analysis_html(self.report)
        self.assertTrue(text.startswith("<!DOCTYPE html>"))
        for required in ('<html lang="en">', '<meta charset="utf-8">',
                         '<title>Vulnerability Prioritization Report</title>', '<style>'):
            self.assertIn(required, text)
        parser = ChartParser()
        parser.feed(text)
        self.assertGreaterEqual(len(parser.charts), 3)
        self.assertTrue(all(count >= 1 for count in parser.charts))
        self.assertEqual(parser.external, [])
        for forbidden in ("<script", "<link", "src="):
            self.assertNotIn(forbidden, text.lower())
        self.assertIn("V|&lt;b&gt;&amp;&quot;", text)
        self.assertNotIn("V|<b>", text)
        self.assertEqual(text, render_analysis_html(self.report))
        self.report["backtest"]["effort_curve"]["EPSS"] = [None] * 8
        self.assertIn('points=""', render_analysis_html(self.report))

    def test_triage_csv_and_markdown_formats(self):
        result = run_triage(self.conn, [Finding("pipe|asset", "CVE-2024-0103"),
                                         Finding("unknown", "CVE-2000-9999")])
        text = render_triage_csv(result)
        self.assertEqual(text.splitlines()[0],
                         "rank,tier,asset_id,cve_id,kev,ransomware,epss,cvss,asset_criticality,internet_facing,reasons")
        self.assertNotIn("\r", text)
        rows = list(csv.DictReader(io.StringIO(text)))
        self.assertEqual((rows[0]["kev"], rows[0]["ransomware"], rows[0]["internet_facing"]), ("yes", "yes", "no"))
        self.assertEqual(rows[0]["epss"], f"{result['items'][0]['epss']:.6f}")
        self.assertEqual(rows[0]["cvss"], f"{result['items'][0]['cvss']:.1f}")
        self.assertTrue(rows[0]["reasons"].startswith("KEV;RANSOMWARE"))
        self.assertEqual((rows[1]["epss"], rows[1]["cvss"]), ("", ""))
        markdown = render_triage_markdown(result)
        self.assertTrue(markdown.startswith("# Remediation Plan\n"))
        self.assertIn("| Tier | Findings |", markdown)
        self.assertIn("| Rank | Tier | Asset | CVE | EPSS | CVSS | Why |", markdown)
        self.assertIn("pipe\\|asset", markdown)
        self.assertIn("Listed in CISA KEV (known exploited); Known use in ransomware campaigns", markdown)
        result["items"][1]["reasons"] = []
        self.assertIn("| - |", render_triage_markdown(result))
