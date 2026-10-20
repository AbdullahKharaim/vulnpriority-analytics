"""Test fixtures; file-writing callers always supply a temporary directory."""

import json
import sqlite3
from pathlib import Path

from vulnprio.storage import SCHEMA, build_database, connect

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def sample_database(directory):
    path = str(Path(directory) / "sample.db")
    summary = build_database(path, [str(SAMPLES / "nvdcve-2.0-sample.json")],
                             str(SAMPLES / "kev-sample.csv"),
                             [str(SAMPLES / "epss_scores-2025-01-01.csv"),
                              str(SAMPLES / "epss_scores-2025-04-01.csv")])
    return path, summary


def memory_database():
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA)
    return conn


def cve(conn, number, published="2024-12-25", score=9.0, status="Analyzed"):
    name = f"CVE-2024-{number:04d}"
    conn.execute("INSERT INTO cves VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (name, published, status, score, "3.1" if score is not None else None, None, "[]"))
    return name


def kev(conn, name, added, vendor="Vendor", ransomware=False, cwes=()):
    conn.execute("INSERT INTO kev VALUES (?, ?, ?, ?, ?, ?)",
                 (name, vendor, "Product", added, int(ransomware), json.dumps(list(cwes))))


def snapshot(conn, d="2025-01-01", scores=None, model="v1"):
    scores = scores or {}
    conn.execute("INSERT INTO epss_snapshots VALUES (?, ?, ?)", (d, model, len(scores)))
    conn.executemany("INSERT INTO epss VALUES (?, ?, ?, ?)",
                     [(d, name, score, None) for name, score in scores.items()])


def nvd_item(name="CVE-2024-0001", published="2024-01-01T00:00:00", score=9.8):
    return {"cve": {"id": name, "published": published, "vulnStatus": "Analyzed",
                    "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": score}}]}}}
