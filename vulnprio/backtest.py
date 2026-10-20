"""Time-split strategy evaluation with pooled counts and paired bootstrap."""

from __future__ import annotations

import math
import random
from dataclasses import asdict
from datetime import date, timedelta

from .models import BacktestConfig, EFFORT_LEVELS_PCT, STRATEGIES, VulnprioError


def _metrics(strategy, flagged, true_positives, population, positives):
    return {
        "strategy": strategy, "flagged": flagged, "true_positives": true_positives,
        "effort": round(flagged / population, 6) if population else 0.0,
        "coverage": round(true_positives / positives, 6) if positives else None,
        "efficiency": round(true_positives / flagged, 6) if flagged else None,
        "lift": round((true_positives / flagged) / (positives / population), 6)
        if flagged and positives else None,
    }


def _bootstrap(instances, config):
    instances.sort(key=lambda row: (row[0], row[1]))
    n = len(instances)
    if not n:
        return None
    differences = [int(a) - int(b) for _, _, a, b in instances]
    rng = random.Random(config.seed)
    diffs = []
    for _ in range(config.bootstrap_iterations):
        diffs.append(sum(differences[int(rng.random() * n)] for _ in range(n)) / n)
    diffs.sort()
    lo = int(math.floor(config.bootstrap_iterations * (1 - config.confidence) / 2 + 1e-9))
    hi = config.bootstrap_iterations - 1 - lo
    low, high = diffs[lo], diffs[hi]
    return {
        "compare": ["EPSS_EFFORT_MATCHED", "CVSS_CRITICAL"], "metric": "coverage_difference",
        "positives": n, "iterations": config.bootstrap_iterations,
        "confidence": config.confidence, "seed": config.seed,
        "point_estimate": round(sum(differences) / n, 6),
        "ci_low": round(low, 6), "ci_high": round(high, 6),
        "significant": low > 0 or high < 0,
    }


def run_backtest(conn, dates: list[date] | None = None,
                 config: BacktestConfig = BacktestConfig()) -> dict:
    kev = {cve: date.fromisoformat(added) for cve, added in conn.execute("SELECT cve_id, date_added FROM kev")}
    if not kev:
        raise VulnprioError("KEV table is empty")
    kev_as_of = max(kev.values())
    snapshots = {date.fromisoformat(d): model for d, model in
                 conn.execute("SELECT snapshot_date, model_version FROM epss_snapshots")}
    horizon = timedelta(days=config.horizon_days)
    if dates is None:
        decision_dates = sorted(d for d in snapshots if d + horizon <= kev_as_of)
        if not decision_dates:
            raise VulnprioError("no EPSS snapshot has a complete outcome window")
    else:
        decision_dates = sorted(set(dates))
        for d in decision_dates:
            if d not in snapshots:
                raise VulnprioError(f"no EPSS snapshot for {d}")
            if d + horizon > kev_as_of:
                raise VulnprioError(f"outcome window for {d} ends after the KEV data ({kev_as_of})")
    cves = [(cve, date.fromisoformat(published), status, score) for cve, published, status, score in
            conn.execute("SELECT cve_id, published, vuln_status, cvss_score FROM cves")]
    per_date, positive_instances = [], []
    totals = {s: [0, 0] for s in STRATEGIES}
    curve_counts = {name: [0] * len(EFFORT_LEVELS_PCT) for name in ("EPSS", "CVSS")}
    for d in decision_dates:
        window_end = d + horizon
        lower = d - timedelta(days=config.lookback_days)
        epss = dict(conn.execute("SELECT cve_id, epss FROM epss WHERE snapshot_date = ?", (d.isoformat(),)))
        no_cvss = no_epss = known_exploited = positives_without_cvss = 0
        population = []
        for cve, published, status, score in cves:
            if status == "Rejected" or not lower <= published < d:
                continue
            added = kev.get(cve)
            positive = added is not None and d < added <= window_end
            if score is None:
                no_cvss += 1
                positives_without_cvss += int(positive)
                continue
            if cve not in epss:
                no_epss += 1
                continue
            if added is not None and added <= d:
                known_exploited += 1
                continue
            population.append((cve, score, epss[cve], positive))
        n = len(population)
        p = sum(row[3] for row in population)
        epss_ranked = sorted(population, key=lambda row: (-row[2], row[0]))
        cvss_ranked = sorted(population, key=lambda row: (-row[1], row[0]))
        critical = {row[0] for row in population if row[1] >= 9.0}
        selected = {
            "CVSS_CRITICAL": critical,
            "CVSS_HIGH_PLUS": {row[0] for row in population if row[1] >= 7.0},
            "EPSS_EFFORT_MATCHED": {row[0] for row in epss_ranked[:len(critical)]},
            "EPSS_THRESHOLD": {row[0] for row in population if row[2] >= config.epss_threshold},
        }
        strategies = []
        for strategy in STRATEGIES:
            f = len(selected[strategy])
            tp = sum(row[3] for row in population if row[0] in selected[strategy])
            strategies.append(_metrics(strategy, f, tp, n, p))
            totals[strategy][0] += f
            totals[strategy][1] += tp
        for cve, _, _, positive in population:
            if positive:
                positive_instances.append((d, cve, cve in selected["EPSS_EFFORT_MATCHED"], cve in critical))
        # Prefix sums avoid re-scanning large populations for every effort level.
        for name, ranking in (("EPSS", epss_ranked), ("CVSS", cvss_ranked)):
            prefix = [0]
            for row in ranking:
                prefix.append(prefix[-1] + int(row[3]))
            for i, pct in enumerate(EFFORT_LEVELS_PCT):
                curve_counts[name][i] += prefix[(pct * n + 99) // 100]
        per_date.append({
            "decision_date": d.isoformat(), "window_end": window_end.isoformat(),
            "epss_model_version": snapshots[d], "population": n, "positives": p,
            "base_rate": round(p / n, 6) if n else None,
            "excluded_no_cvss": no_cvss, "excluded_no_epss": no_epss,
            "excluded_known_exploited": known_exploited,
            "positives_without_cvss": positives_without_cvss, "strategies": strategies,
        })
    n = sum(row["population"] for row in per_date)
    p = sum(row["positives"] for row in per_date)
    pooled = {"population": n, "positives": p, "base_rate": round(p / n, 6) if n else None,
              "strategies": [_metrics(s, *totals[s], n, p) for s in STRATEGIES]}
    return {
        "config": asdict(config), "kev_as_of": kev_as_of.isoformat(),
        "decision_dates": [d.isoformat() for d in decision_dates], "per_date": per_date,
        "pooled": pooled,
        "effort_curve": {"levels_pct": list(EFFORT_LEVELS_PCT),
                         **{name: [round(count / p, 6) if p else None for count in counts]
                            for name, counts in curve_counts.items()}},
        "bootstrap": _bootstrap(positive_instances, config),
    }
