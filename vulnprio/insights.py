"""Descriptive exploitation statistics over an inclusive KEV date window."""

from __future__ import annotations

import json
import statistics
from collections import Counter
from datetime import date

from .models import CVSS_BANDS, LAG_BUCKETS, cvss_band


def compute_insights(conn, start: date, end: date, top_n: int = 10) -> dict:
    rows = conn.execute(
        "SELECT k.vendor, k.ransomware, k.cwes, k.date_added, c.cve_id, c.published, c.cvss_score "
        "FROM kev k LEFT JOIN cves c ON c.cve_id = k.cve_id "
        "WHERE k.date_added >= ? AND k.date_added <= ? ORDER BY k.date_added, k.cve_id",
        (start.isoformat(), end.isoformat())).fetchall()
    vendors, ransomware_vendors, cwes, bands = Counter(), Counter(), Counter(), Counter()
    lags, scores = [], []
    ransomware = 0
    for vendor, ransom, weaknesses, added, cve, published, score in rows:
        vendors[vendor] += 1
        ransomware_vendors[vendor] += ransom
        ransomware += ransom
        cwes.update(json.loads(weaknesses))
        if cve is not None:
            lags.append((date.fromisoformat(added) - date.fromisoformat(published)).days)
            bands[cvss_band(score)] += 1
            if score is not None:
                scores.append(score)
    count, with_nvd = len(rows), len(lags)
    buckets = []
    for label, low, high in LAG_BUCKETS:
        bucket_count = sum((low is None or lag >= low) and (high is None or lag <= high) for lag in lags)
        buckets.append({"label": label, "count": bucket_count,
                        "share": round(bucket_count / with_nvd, 6) if with_nvd else None})
    return {
        "window": {"start": start.isoformat(), "end": end.isoformat()}, "kev_entries": count,
        "ransomware": {"count": ransomware, "share": round(ransomware / count, 6) if count else None},
        "with_nvd": with_nvd,
        "lag_days": {"count": with_nvd,
                     "median": round(float(statistics.median(lags)), 1) if lags else None,
                     "mean": round(float(statistics.fmean(lags)), 1) if lags else None,
                     "buckets": buckets},
        "cvss_bands": [{"band": band, "count": bands[band],
                        "share": round(bands[band] / with_nvd, 6) if with_nvd else None}
                       for band in CVSS_BANDS],
        "below_critical_share": round(sum(s < 9 for s in scores) / len(scores), 6) if scores else None,
        "below_high_share": round(sum(s < 7 for s in scores) / len(scores), 6) if scores else None,
        "top_vendors": [{"vendor": vendor, "count": vendors[vendor], "ransomware": ransomware_vendors[vendor]}
                        for vendor in sorted(vendors, key=lambda v: (-vendors[v], v))[:top_n]],
        "top_cwes": [{"cwe": cwe, "count": cwes[cwe]} for cwe in
                     sorted(cwes, key=lambda c: (-cwes[c], int(c[4:]), c))[:top_n]],
    }
