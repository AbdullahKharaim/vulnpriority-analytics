import gzip
import io
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

from vulnprio import ingest
from vulnprio.models import VulnprioError
from .helpers import nvd_item


class IngestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)

    def write(self, text, name="input.csv"):
        path = self.directory / name
        path.write_text(text, encoding="utf-8")
        return str(path)

    def error(self, message, function, *args):
        with self.assertRaises(VulnprioError) as caught:
            function(*args)
        self.assertEqual(str(caught.exception), message)

    def test_nvd_tiny_chunks_plain_and_gzip(self):
        values = [nvd_item(), {"unicode": "é中", "array": [1, 2]}, None, True, False, "hello", 12345, -1.25e-10]
        text = '\ufeff{"format":"NVD", "vulnerabilities" : ' + json.dumps(values, ensure_ascii=False) + '} ignored'
        plain = self.write(text, "feed.json")
        compressed = self.directory / "feed.JSON.GZ"
        with gzip.open(compressed, "wt", encoding="utf-8") as fh:
            fh.write(text)
        for size in range(1, 8):
            for path in (plain, str(compressed)):
                with self.subTest(size=size, path=path), patch.object(ingest, "CHUNK_SIZE", size):
                    self.assertEqual(list(ingest.iter_nvd_items(path)), values)

    def test_read_sizes_streaming_and_call_time_global(self):
        class Tracked(io.StringIO):
            def __init__(self, text):
                super().__init__(text)
                self.sizes = []

            def read(self, size=-1):
                self.sizes.append(size)
                return super().read(size)

        stream = Tracked('x' * 100 + '"vulnerabilities": [1,2,3] ignored')
        with patch.object(ingest, "open_text", return_value=stream), \
                patch.object(ingest.json, "load", side_effect=AssertionError("whole-file load")), \
                patch.object(ingest.json, "loads", side_effect=AssertionError("whole-file loads")):
            iterator = ingest.iter_nvd_items("feed")
            with patch.object(ingest, "CHUNK_SIZE", 2):
                self.assertEqual(next(iterator), 1)
            with patch.object(ingest, "CHUNK_SIZE", 3):
                self.assertEqual(list(iterator), [2, 3])
        self.assertEqual(set(stream.sizes), {2, 3})
        self.assertTrue(stream.closed)

    def test_nvd_empty_and_trailing_garbage(self):
        for text, expected in [('"vulnerabilities":[] garbage', []),
                               ('"vulnerabilities": [1e+12, 0.0002, -12.34E-5]garbage', [1e12, .0002, -.0001234])]:
            with patch.object(ingest, "CHUNK_SIZE", 1):
                self.assertEqual(list(ingest.iter_nvd_items(self.write(text))), expected)

    def test_nvd_exact_errors(self):
        for text in ("", "{}", '"vulnerabilities"', '"vulnerabilities" []', '"vulnerabilities":{}'):
            path = self.write(text)
            self.error(f"not an NVD CVE 2.0 feed: {path}", lambda p: list(ingest.iter_nvd_items(p)), path)
        for text in ('"vulnerabilities":[', '"vulnerabilities":[{}', '"vulnerabilities":[oops]',
                     '"vulnerabilities":[1,]', '"vulnerabilities":[1 2]', '"vulnerabilities":[1e]'):
            path = self.write(text)
            with patch.object(ingest, "CHUNK_SIZE", 2):
                self.error(f"truncated or invalid NVD feed: {path}", lambda p: list(ingest.iter_nvd_items(p)), path)

    def test_nvd_validation_and_cwes(self):
        for item in (None, 2, [], {}, {"cve": []}, nvd_item(name="cve-2024-0001"),
                     nvd_item(published="bad"), nvd_item(published="2025-02-30")):
            self.assertIsNone(ingest.parse_nvd_item(item))
        item = nvd_item()
        item["cve"]["vulnStatus"] = None
        item["cve"]["weaknesses"] = [None, {}, {"description": None},
                                     {"description": [None, {}, {"value": 3},
                                                       {"value": "CWE-100 CWE-2 NVD-CWE-noinfo CWE-2"}]}]
        result = ingest.parse_nvd_item(item)
        self.assertEqual(result.published, date(2024, 1, 1))
        self.assertEqual(result.vuln_status, "")
        self.assertEqual(result.cwes, ("CWE-2", "CWE-100"))
        self.assertEqual(ingest.parse_cwe_list("NVD-CWE-noinfo"), ())

    def test_cvss_primary_and_version_precedence(self):
        item = nvd_item()
        metrics = item["cve"]["metrics"]
        metrics["cvssMetricV31"] = [None, {"cvssData": {"baseScore": True}},
                                  {"type": "Secondary", "cvssData": {"baseScore": 8}},
                                  {"type": "Primary", "cvssData": {"baseScore": 7.1}},
                                  {"type": "Primary", "cvssData": {"baseScore": 9.9}}]
        metrics["cvssMetricV30"] = [{"type": "Primary", "cvssData": {"baseScore": 10}}]
        result = ingest.parse_nvd_item(item)
        self.assertEqual((result.cvss_score, result.cvss_version, result.cvss_source_type), (7.1, "3.1", "Primary"))
        metrics["cvssMetricV31"] = [{"cvssData": {"baseScore": False}}, {"cvssData": {"baseScore": "9.0"}}]
        self.assertEqual(ingest.parse_nvd_item(item).cvss_version, "3.0")
        metrics["cvssMetricV30"] = [{"type": 9, "cvssData": {"baseScore": 4}}, {"cvssData": {"baseScore": 5}}]
        result = ingest.parse_nvd_item(item)
        self.assertEqual((result.cvss_score, result.cvss_source_type), (4.0, None))
        for malformed in (None, [], {"cvssMetricV31": {}}, {"cvssMetricV2": [{"baseScore": 10}]}):
            item["cve"]["metrics"] = malformed
            result = ingest.parse_nvd_item(item)
            self.assertEqual((result.cvss_score, result.cvss_version, result.cvss_source_type), (None, None, None))

    def test_kev_missing_columns_in_order(self):
        names = ["cveID", "vendorProject", "product", "dateAdded", "knownRansomwareCampaignUse"]
        for i, name in enumerate(names):
            path = self.write(",".join(names[:i]) + ("\n" if i else ""))
            self.error(f"KEV file is missing column '{name}': {path}", ingest.parse_kev_csv, path)

    def test_kev_rows_duplicates_and_sorting(self):
        path = self.write("cveID,vendorProject,product,dateAdded,knownRansomwareCampaignUse,cwes\n"
                          " cve-2024-0002 , First , P ,2025-01-03,KNOWN,CWE-79 CWE-2\n"
                          "CVE-2024-0002,Earliest,P,2025-01-01,Unknown,CWE-22\n"
                          "CVE-2024-0002,Tie,P,2025-01-01,Known,\n"
                          "CVE-2024-0001,B,P,2025-01-01,Known,\n"
                          "invalid,B,P,2025-01-01,Known,\n"
                          "CVE-2024-0003,B,P,2025-02-30,Known,\n"
                          "CVE-2024-0004\n")
        entries, skipped = ingest.parse_kev_csv(path)
        self.assertEqual(skipped, 3)
        self.assertEqual([e.cve_id for e in entries], ["CVE-2024-0001", "CVE-2024-0002"])
        self.assertEqual(entries[1].vendor, "Earliest")
        self.assertFalse(entries[1].ransomware)
        self.assertEqual(entries[1].cwes, ("CWE-22",))

    def test_epss_validation_duplicates_and_metadata(self):
        path = self.write("# model_version: v1,score_date:2025-04-01T00:00:00+0000\n"
                          " cve , epss , percentile \n"
                          "cve-2024-0001,0.2,0.9\nCVE-2024-0001,0.8,0.1\n"
                          "CVE-2024-0002,0.3,nan\nCVE-2024-0003,0,1\n"
                          "CVE-2024-0004,1,2\nCVE-2024-0005,0.5\n"
                          "bad,0.1,0.1\nCVE-2024-0006,nan,0.1\nCVE-2024-0007,inf,0\n"
                          "CVE-2024-0008,-0.1,0\nCVE-2024-0009,1.1,0\nCVE-2024-0010\n\n")
        result = ingest.parse_epss_csv(path)
        self.assertEqual(result.snapshot_date, date(2025, 4, 1))
        self.assertEqual(result.model_version, "v1")
        self.assertEqual(result.skipped_rows, 6)
        self.assertEqual(result.scores["CVE-2024-0001"], .2)
        self.assertEqual(result.percentiles, {"CVE-2024-0001": .9, "CVE-2024-0003": 1.0})
        self.assertEqual(ingest.parse_epss_csv(path, date(2024, 1, 1)).snapshot_date, date(2024, 1, 1))

    def test_epss_dates_gzip_and_errors(self):
        path = self.write("#score_date:bad\ncve,epss\nCVE-2024-0001,0.1\n", "2025-99-99-2025-02-01.csv")
        self.assertEqual(ingest.parse_epss_csv(path).snapshot_date, date(2025, 2, 1))
        gz = self.directory / "2025-03-01.csv.gz"
        with gzip.open(gz, "wt", encoding="utf-8-sig") as fh:
            fh.write("cve,epss\nCVE-2024-0001,0.5\n")
        self.assertEqual(ingest.parse_epss_csv(str(gz)).scores, {"CVE-2024-0001": .5})
        for text in ("", "#model_version:v1\n"):
            path = self.write(text)
            self.error(f"EPSS file is empty: {path}", ingest.parse_epss_csv, path)
        for text, missing in (("other,epss\n", "cve"), ("cve\n", "epss")):
            path = self.write(text)
            self.error(f"EPSS file is missing column '{missing}': {path}", ingest.parse_epss_csv, path)
        path = self.write("cve,epss\n")
        self.error(f"cannot determine EPSS snapshot date: {path}", ingest.parse_epss_csv, path)

    def test_findings_defaults_duplicates_and_missing_columns(self):
        path = self.write("asset_id,cve_id,asset_criticality,internet_facing\n"
                          " a ,cve-2024-0001,HIGH,yes\na,CVE-2024-0001,low,false\n"
                          "b,CVE-2024-0002,nonsense,y\nc,CVE-2024-0003\n"
                          ",CVE-2024-0004\nd,bad\n")
        findings, skipped = ingest.parse_findings_csv(path)
        self.assertEqual(skipped, 3)
        self.assertEqual([f.asset_id for f in findings], ["a", "b", "c"])
        self.assertEqual([f.asset_criticality for f in findings], ["high", "medium", "medium"])
        self.assertEqual([f.internet_facing for f in findings], [True, True, False])
        for text, name in (("", "asset_id"), ("asset_id\n", "cve_id")):
            path = self.write(text)
            self.error(f"findings file is missing column '{name}': {path}", ingest.parse_findings_csv, path)
