"""Deterministic remediation tiers with auditable, ordered reason codes."""

from __future__ import annotations

from datetime import date

from .models import REASON_CODES, TIERS, TriageConfig


def run_triage(conn, findings, as_of: date | None = None,
               config: TriageConfig = TriageConfig(), rows_skipped: int = 0) -> dict:
    if as_of is None:
        snapshot = conn.execute("SELECT MAX(snapshot_date) FROM epss_snapshots").fetchone()[0]
    else:
        snapshot = conn.execute("SELECT MAX(snapshot_date) FROM epss_snapshots WHERE snapshot_date <= ?",
                                (as_of.isoformat(),)).fetchone()[0]
    epss = dict(conn.execute("SELECT cve_id, epss FROM epss WHERE snapshot_date = ?", (snapshot,)))
    cves = dict(conn.execute("SELECT cve_id, cvss_score FROM cves"))
    kev_entries = {cve: (added, bool(ransom)) for cve, added, ransom in
                   conn.execute("SELECT cve_id, date_added, ransomware FROM kev")}
    sortable = []
    for finding in findings:
        cve = finding.cve_id
        e, s = epss.get(cve), cves.get(cve)
        entry = kev_entries.get(cve)
        kev = entry is not None and (as_of is None or entry[0] <= as_of.isoformat())
        ransom = kev and entry[1]
        high_epss = e is not None and e >= config.epss_high
        critical = s is not None and s >= config.cvss_critical
        internet_critical = critical and finding.internet_facing
        high_cvss = s is not None and config.cvss_high <= s < config.cvss_critical
        medium_epss = e is not None and config.epss_medium <= e < config.epss_high
        if kev:
            tier = "P1"
        elif high_epss or internet_critical:
            tier = "P2"
        elif (s is not None and s >= config.cvss_high) or (e is not None and e >= config.epss_medium):
            tier = "P3"
        else:
            tier = "P4"
        escalated = finding.asset_criticality == "high" and tier in {"P3", "P4"}
        if escalated:
            tier = "P2" if tier == "P3" else "P3"
        conditions = (kev, ransom, high_epss, internet_critical, critical, high_cvss, medium_epss,
                      cve not in cves and e is None and not kev, escalated)
        item = {
            "asset_id": finding.asset_id, "cve_id": cve, "tier": tier, "kev": kev,
            "kev_date_added": entry[0] if kev else None, "ransomware": ransom,
            "epss": round(e, 6) if e is not None else None, "cvss": s,
            "asset_criticality": finding.asset_criticality, "internet_facing": finding.internet_facing,
            "reasons": [code for code, condition in zip(REASON_CODES, conditions) if condition],
        }
        key = (TIERS.index(tier), -(e if e is not None else -1.0), -(s if s is not None else -1.0),
               finding.asset_id, cve)
        sortable.append((key, item))
    items = [item for _, item in sorted(sortable, key=lambda pair: pair[0])]
    for rank, item in enumerate(items, 1):
        item["rank"] = rank
    return {
        "as_of": as_of.isoformat() if as_of is not None else None, "epss_snapshot": snapshot,
        "summary": {"findings": len(items), "rows_skipped": rows_skipped,
                    "tiers": {tier: sum(item["tier"] == tier for item in items) for tier in TIERS},
                    "kev": sum(item["kev"] for item in items),
                    "ransomware": sum("RANSOMWARE" in item["reasons"] for item in items),
                    "unknown_cves": sum("UNKNOWN_CVE" in item["reasons"] for item in items)},
        "items": items,
    }
