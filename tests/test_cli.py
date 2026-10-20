import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from vulnprio.cli import main
from .helpers import ROOT, SAMPLES


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.db = str(self.directory / "db.sqlite")
        self.build_args = ["build", "--db", self.db, "--nvd", str(SAMPLES / "nvdcve-2.0-sample.json"),
                           "--kev", str(SAMPLES / "kev-sample.csv"), "--epss",
                           str(SAMPLES / "epss_scores-2025-01-01.csv"), str(SAMPLES / "epss_scores-2025-04-01.csv")]

    def run_cli(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = main(args)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_version_help_usage_and_entry_point(self):
        self.assertEqual(self.run_cli(["--version"]), (0, "vulnpriority-analytics 1.0.0\n", ""))
        code, out, err = self.run_cli([])
        self.assertEqual((code, out), (2, ""))
        self.assertIn("usage: vulnprio", err)
        self.assertEqual(self.run_cli(["--help"])[0], 0)
        for args in (["analyze"], ["triage", "--db", self.db, "--findings", "x", "--as-of", "2025-02-30"],
                     ["analyze", "--db", self.db, "--date", "invalid"],
                     ["analyze", "--db", self.db, "--bootstrap", "abc"],
                     ["analyze", "--db", self.db, "--format", "csv"]):
            code, out, err = self.run_cli(args)
            self.assertEqual((code, out), (2, ""))
            self.assertIn("error:", err)
        result = subprocess.run([sys.executable, "-m", "vulnprio", "--version"], cwd=ROOT,
                                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                                capture_output=True, text=True, check=False)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, "vulnpriority-analytics 1.0.0\n", ""))

    def test_numeric_validation_and_missing_db(self):
        for option, values, message in (
            ("--lookback-days", ("0", "-1"), "--lookback-days must be >= 1"),
            ("--horizon-days", ("0",), "--horizon-days must be >= 1"),
            ("--epss-threshold", ("0", "1.1", "nan", "inf"), "--epss-threshold must be > 0 and <= 1"),
            ("--bootstrap", ("0",), "--bootstrap must be >= 1"),
            ("--confidence", ("0", "1", "nan", "inf"), "--confidence must be > 0 and < 1"),
        ):
            for value in values:
                with self.subTest(option=option, value=value):
                    self.assertEqual(self.run_cli(["analyze", "--db", self.db, option, value]),
                                     (1, "", "error: " + message + "\n"))
        self.assertEqual(self.run_cli(["analyze", "--db", self.db]),
                         (1, "", f"error: database not found: {self.db}\n"))
        self.assertFalse(Path(self.db).exists())

    def test_build_analyze_triage_formats_and_output_determinism(self):
        code, out, err = self.run_cli(self.build_args)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out)["cves"], 49)
        self.assertEqual(self.run_cli(self.build_args)[0], 1)
        summary_output = str(self.directory / "summary.json")
        self.assertEqual(self.run_cli(self.build_args + ["--force", "--output", summary_output]), (0, "", ""))
        self.assertEqual(Path(summary_output).read_text(encoding="utf-8"), out)
        for command, formats in (("analyze", ("json", "markdown", "html")), ("triage", ("csv", "json", "markdown"))):
            for fmt in formats:
                args = [command, "--db", self.db, "--format", fmt]
                if command == "triage":
                    args.extend(["--findings", str(SAMPLES / "findings-sample.csv")])
                stdout_result = self.run_cli(args)
                self.assertEqual((stdout_result[0], stdout_result[2]), (0, ""))
                paths = [self.directory / f"{command}-{fmt}-{i}" for i in range(2)]
                for path in paths:
                    self.assertEqual(self.run_cli(args + ["--output", str(path)]), (0, "", ""))
                self.assertEqual(paths[0].read_bytes(), paths[1].read_bytes())
                self.assertEqual(paths[0].read_text(encoding="utf-8"), stdout_result[1])
        args = ["analyze", "--db", self.db, "--date", "2025-04-01", "--date", "2025-01-01", "--date", "2025-04-01"]
        self.assertEqual(json.loads(self.run_cli(args)[1])["backtest"]["decision_dates"], ["2025-01-01", "2025-04-01"])
        args = ["triage", "--db", self.db, "--findings", str(SAMPLES / "findings-sample.csv"),
                "--as-of", "2025-02-01", "--format", "json"]
        self.assertEqual(json.loads(self.run_cli(args)[1])["epss_snapshot"], "2025-01-01")

    def test_runtime_io_and_input_errors(self):
        self.assertEqual(self.run_cli(self.build_args)[0], 0)
        code, out, err = self.run_cli(["analyze", "--db", self.db, "--date", "2024-01-01"])
        self.assertEqual((code, out, err), (1, "", "error: no EPSS snapshot for 2024-01-01\n"))
        code, out, err = self.run_cli(["analyze", "--db", self.db, "--output", str(self.directory / "missing" / "report")])
        self.assertEqual((code, out), (1, ""))
        self.assertTrue(err.startswith("error: "))
        bad = self.directory / "bad.csv"
        bad.write_text("bad\n", encoding="utf-8")
        self.assertEqual(self.run_cli(["triage", "--db", self.db, "--findings", str(bad)]),
                         (1, "", f"error: findings file is missing column 'asset_id': {bad}\n"))
