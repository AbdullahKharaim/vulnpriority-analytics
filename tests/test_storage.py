import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from vulnprio.models import VulnprioError
from vulnprio.storage import SCHEMA, build_database, connect, load_summary
from .helpers import SAMPLES, nvd_item, sample_database


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)

    def test_sample_summary_and_views(self):
        path, summary = sample_database(self.directory)
        self.assertEqual(summary, {
            "schema_version": 1, "cves": 49, "cves_rejected": 1, "cves_without_cvss": 4,
            "nvd_files": 1, "nvd_items_skipped": 0, "nvd_duplicates": 0,
            "kev_entries": 11, "kev_rows_skipped": 0, "kev_as_of": "2026-04-15",
            "epss_snapshots": [
                {"snapshot_date": "2025-01-01", "model_version": "v2025.01.01", "rows": 43, "rows_skipped": 0},
                {"snapshot_date": "2025-04-01", "model_version": "v2025.03.14", "rows": 48, "rows_skipped": 0}],
        })
        self.assertFalse(Path(path + ".tmp").exists())
        conn = connect(path)
        self.addCleanup(conn.close)
        self.assertEqual(load_summary(conn), summary)
        self.assertEqual(dict(conn.execute("SELECT key, value FROM meta"))["tool_version"], "1.0.0")
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM v_kev_lag").fetchone()[0], 10)
        self.assertEqual(sum(r[0] for r in conn.execute("SELECT cve_count FROM v_cvss_bands")), 48)
        self.assertEqual(sum(r[0] for r in conn.execute("SELECT exploited FROM v_kev_vendors")), 11)

    def test_atomic_replacement_force_and_failed_build(self):
        path, summary = sample_database(self.directory)
        original = Path(path).read_bytes()
        args = ([str(SAMPLES / "nvdcve-2.0-sample.json")], str(SAMPLES / "kev-sample.csv"),
                [str(SAMPLES / "epss_scores-2025-01-01.csv")])
        with self.assertRaises(VulnprioError) as caught:
            build_database(path, *args)
        self.assertEqual(str(caught.exception), f"database already exists: {path} (use --force to replace it)")
        Path(path + ".tmp").write_text("stale", encoding="utf-8")
        duplicate = args[2][0]
        with self.assertRaises(VulnprioError) as caught:
            build_database(path, args[0], args[1], [duplicate, duplicate], force=True)
        self.assertEqual(str(caught.exception), f"duplicate EPSS snapshot date 2025-01-01: {duplicate}")
        self.assertEqual(Path(path).read_bytes(), original)
        self.assertFalse(Path(path + ".tmp").exists())
        replacement = build_database(path, *args, force=True)
        self.assertEqual(len(replacement["epss_snapshots"]), 1)
        self.assertNotEqual(Path(path).read_bytes(), original)

    def test_nvd_duplicates_last_wins_and_empty_kev(self):
        nvd = self.directory / "nvd.json"
        nvd.write_text(json.dumps({"vulnerabilities": [nvd_item(score=4), None, nvd_item(score=8)]}), encoding="utf-8")
        kev_path = self.directory / "kev.csv"
        kev_path.write_text("cveID,vendorProject,product,dateAdded,knownRansomwareCampaignUse\n", encoding="utf-8")
        epss = self.directory / "2025-01-01.csv"
        epss.write_text("cve,epss\nCVE-2024-0001,0.5\n", encoding="utf-8")
        path = str(self.directory / "db")
        summary = build_database(path, [str(nvd)], str(kev_path), [str(epss)])
        self.assertEqual((summary["nvd_duplicates"], summary["nvd_items_skipped"], summary["cves"]), (1, 1, 1))
        self.assertIsNone(summary["kev_as_of"])
        conn = connect(path)
        self.addCleanup(conn.close)
        self.assertEqual(conn.execute("SELECT cvss_score FROM cves").fetchone()[0], 8)

    def test_failed_new_build_cleans_up(self):
        path = str(self.directory / "db")
        with self.assertRaises(OSError):
            build_database(path, [str(self.directory / "missing")], "missing", [])
        self.assertFalse(Path(path).exists())
        self.assertFalse(Path(path + ".tmp").exists())

    def test_connect_errors_no_files_created(self):
        path = str(self.directory / "missing.db")
        with self.assertRaises(VulnprioError) as caught:
            connect(path)
        self.assertEqual(str(caught.exception), f"database not found: {path}")
        self.assertFalse(Path(path).exists())
        Path(path).write_text("not sqlite", encoding="utf-8")
        for kind in ("text", "empty_sqlite", "missing_version", "wrong_version"):
            if kind != "text":
                Path(path).unlink()
                conn = sqlite3.connect(path)
                if kind in {"missing_version", "wrong_version"}:
                    conn.executescript(SCHEMA)
                if kind == "wrong_version":
                    conn.execute("INSERT INTO meta VALUES (?, ?)", ("schema_version", "2"))
                    conn.commit()
                conn.close()
            with self.assertRaises(VulnprioError) as caught:
                connect(path)
            self.assertEqual(str(caught.exception), f"not a vulnprio database: {path}")
