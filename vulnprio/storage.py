"""Atomic SQLite builds and validation of existing databases."""

from __future__ import annotations

import json
import os
import sqlite3

from .ingest import iter_nvd_items, parse_epss_csv, parse_kev_csv, parse_nvd_item
from .models import VulnprioError

SCHEMA = """CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE cves (
    cve_id TEXT PRIMARY KEY,
    published TEXT NOT NULL,
    vuln_status TEXT NOT NULL,
    cvss_score REAL,
    cvss_version TEXT,
    cvss_source_type TEXT,
    cwes TEXT NOT NULL
);
CREATE INDEX idx_cves_published ON cves(published);
CREATE TABLE kev (
    cve_id TEXT PRIMARY KEY,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    date_added TEXT NOT NULL,
    ransomware INTEGER NOT NULL,
    cwes TEXT NOT NULL
);
CREATE TABLE epss_snapshots (
    snapshot_date TEXT PRIMARY KEY,
    model_version TEXT,
    row_count INTEGER NOT NULL
);
CREATE TABLE epss (
    snapshot_date TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    epss REAL NOT NULL,
    percentile REAL,
    PRIMARY KEY (snapshot_date, cve_id)
);
CREATE VIEW v_kev_lag AS
SELECT k.cve_id AS cve_id, c.published AS published, k.date_added AS date_added,
       CAST(julianday(k.date_added) - julianday(c.published) AS INTEGER) AS lag_days,
       c.cvss_score AS cvss_score, k.vendor AS vendor, k.ransomware AS ransomware
FROM kev k JOIN cves c ON c.cve_id = k.cve_id;
CREATE VIEW v_cvss_bands AS
SELECT CASE
         WHEN c.cvss_score IS NULL THEN 'unscored'
         WHEN c.cvss_score >= 9.0 THEN 'critical'
         WHEN c.cvss_score >= 7.0 THEN 'high'
         WHEN c.cvss_score >= 4.0 THEN 'medium'
         WHEN c.cvss_score > 0.0 THEN 'low'
         ELSE 'none' END AS band,
       COUNT(*) AS cve_count,
       SUM(CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS kev_count
FROM cves c LEFT JOIN kev k ON k.cve_id = c.cve_id
WHERE c.vuln_status <> 'Rejected'
GROUP BY band;
CREATE VIEW v_kev_vendors AS
SELECT vendor, COUNT(*) AS exploited, SUM(ransomware) AS ransomware
FROM kev GROUP BY vendor;
"""


def build_database(db_path, nvd_paths, kev_path, epss_paths, *, force=False) -> dict:
    db_path = os.fspath(db_path)
    if os.path.exists(db_path) and not force:
        raise VulnprioError(f"database already exists: {db_path} (use --force to replace it)")
    tmp = db_path + ".tmp"
    if os.path.exists(tmp):
        os.remove(tmp)
    conn = None
    try:
        conn = sqlite3.connect(tmp)
        conn.executescript(SCHEMA)
        records = {}
        skipped = duplicates = 0
        nvd_paths = list(nvd_paths)
        for path in nvd_paths:
            for item in iter_nvd_items(path):
                record = parse_nvd_item(item)
                if record is None:
                    skipped += 1
                else:
                    duplicates += int(record.cve_id in records)
                    records[record.cve_id] = record
        conn.executemany("INSERT INTO cves VALUES (?, ?, ?, ?, ?, ?, ?)",
                         ((r.cve_id, r.published.isoformat(), r.vuln_status, r.cvss_score,
                           r.cvss_version, r.cvss_source_type, json.dumps(list(r.cwes)))
                          for r in records.values()))
        kev, kev_skipped = parse_kev_csv(kev_path)
        conn.executemany("INSERT INTO kev VALUES (?, ?, ?, ?, ?, ?)",
                         ((k.cve_id, k.vendor, k.product, k.date_added.isoformat(),
                           int(k.ransomware), json.dumps(list(k.cwes))) for k in kev))
        snapshots, seen = [], set()
        for path in epss_paths:
            snapshot = parse_epss_csv(path)
            d = snapshot.snapshot_date.isoformat()
            if d in seen:
                raise VulnprioError(f"duplicate EPSS snapshot date {d}: {path}")
            seen.add(d)
            conn.executemany("INSERT INTO epss_snapshots VALUES (?, ?, ?)",
                             [(d, snapshot.model_version, len(snapshot.scores))])
            conn.executemany("INSERT INTO epss VALUES (?, ?, ?, ?)",
                             ((d, cve, score, snapshot.percentiles.get(cve))
                              for cve, score in snapshot.scores.items()))
            snapshots.append({"snapshot_date": d, "model_version": snapshot.model_version,
                              "rows": len(snapshot.scores), "rows_skipped": snapshot.skipped_rows})
        summary = {
            "schema_version": 1, "cves": len(records),
            "cves_rejected": sum(r.vuln_status == "Rejected" for r in records.values()),
            "cves_without_cvss": sum(r.vuln_status != "Rejected" and r.cvss_score is None
                                     for r in records.values()),
            "nvd_files": len(nvd_paths), "nvd_items_skipped": skipped, "nvd_duplicates": duplicates,
            "kev_entries": len(kev), "kev_rows_skipped": kev_skipped,
            "kev_as_of": max((k.date_added.isoformat() for k in kev), default=None),
            "epss_snapshots": sorted(snapshots, key=lambda s: s["snapshot_date"]),
        }
        conn.executemany("INSERT INTO meta VALUES (?, ?)",
                         [("schema_version", "1"), ("tool_version", "1.0.0"),
                          ("build_summary", json.dumps(summary, sort_keys=True))])
        conn.commit()
        conn.close()
        conn = None
        os.replace(tmp, db_path)
        return summary
    except BaseException:
        if conn is not None:
            conn.close()
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def connect(db_path) -> sqlite3.Connection:
    if not os.path.exists(db_path):
        raise VulnprioError(f"database not found: {db_path}")
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT value FROM meta WHERE key = ?", ("schema_version",)).fetchone()
        if row is None or row[0] != "1":
            raise sqlite3.DatabaseError("invalid schema version")
    except sqlite3.DatabaseError:
        if conn is not None:
            conn.close()
        raise VulnprioError(f"not a vulnprio database: {db_path}") from None
    return conn


def load_summary(conn) -> dict:
    return json.loads(conn.execute("SELECT value FROM meta WHERE key = ?", ("build_summary",)).fetchone()[0])
