# vulnpriority-analytics — Specification v1.0

This document is **binding**. Implement every module, function, rule, ordering, output format,
CLI behaviour and exit code exactly as written. Where this document gives exact strings, keys or
formulas, use them verbatim.

## 0. Purpose and global rules

`vulnpriority-analytics` answers a question every security team faces: *"We cannot patch
everything — which vulnerabilities should we patch first?"* It ingests three public datasets into
SQLite, **backtests** prioritisation strategies with a leakage-free time-split design across
several decision dates, measures how well each strategy would have caught vulnerabilities that were
later exploited, adds exploitation insights, and **triages** an organisation's own findings into a
prioritised remediation plan.

Data sources (downloaded by the user; the tool never uses the network):

| Source | File | Meaning |
|---|---|---|
| NVD CVE JSON 2.0 yearly feeds | `nvdcve-2.0-YYYY.json.gz` | every published CVE, publication date, CVSS |
| CISA Known Exploited Vulnerabilities | `known_exploited_vulnerabilities.csv` | CVEs proven exploited, with the date added |
| FIRST EPSS daily scores | `epss_scores-YYYY-MM-DD.csv.gz` | probability of exploitation in the next 30 days, per CVE, per day |

Global rules:

- Python >= 3.10, **standard library only**, no network access at runtime or in tests.
- Package name `vulnprio`; CLI entry `python3 -m vulnprio`.
- All files are read and written as UTF-8. Input files ending in `.gz` (case-insensitive) are
  read with `gzip`; every other file is read as plain text.
- Output is deterministic: identical inputs give byte-identical outputs. No wall-clock times,
  absolute paths or host names in any output.
- All dates in outputs are ISO strings `YYYY-MM-DD`.
- `round(x, 6)` is applied to every ratio (effort, coverage, efficiency, lift, share, base rate,
  EPSS values and curve values) placed in a result dictionary. Ratios are always computed from the
  exact integer counts and the result is rounded once.
- Unit tests live under `tests/` (with `tests/__init__.py`) and run with
  `python3 -m unittest discover -s tests -t .`. **Tests must only write to temporary
  directories** (never into the repository).

## 1. Repository layout (required)

```
vulnprio/__init__.py        __version__ = "1.0.0"            (provided, keep)
vulnprio/__main__.py        from vulnprio.cli import main; raise SystemExit(main())   (provided, keep)
vulnprio/models.py          constants, dataclasses, VulnprioError (provided, keep unchanged)
vulnprio/ingest.py          parsers for NVD, KEV, EPSS and findings files
vulnprio/storage.py         SQLite schema, build, connect
vulnprio/backtest.py        time-split backtest, effort curve, bootstrap
vulnprio/insights.py        exploitation insights
vulnprio/triage.py          remediation plan
vulnprio/report.py          JSON / Markdown / HTML / CSV rendering
vulnprio/cli.py             argparse CLI
tests/__init__.py           (empty) and tests/test_*.py
samples/nvdcve-2.0-sample.json          (provided, keep unchanged)
samples/kev-sample.csv                  (provided, keep unchanged)
samples/epss_scores-2025-01-01.csv      (provided, keep unchanged)
samples/epss_scores-2025-04-01.csv      (provided, keep unchanged)
samples/findings-sample.csv             (provided, keep unchanged)
docs/DATA_SOURCES.md                    (provided, keep unchanged)
docs/METHODOLOGY.md
README.md
```

Files marked *provided* are already in the repository; do not modify them.

## 2. Models (`vulnprio/models.py`, provided — do not change)

`models.py` is supplied with the specification. It defines:

- `class VulnprioError(Exception)` — every user-facing input/data error raises this.
- `CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")`
- `STRATEGIES = ("CVSS_CRITICAL", "CVSS_HIGH_PLUS", "EPSS_EFFORT_MATCHED", "EPSS_THRESHOLD")`
- `EFFORT_LEVELS_PCT = (1, 2, 5, 10, 20, 30, 50, 100)`
- `TIERS = ("P1", "P2", "P3", "P4")`
- `REASON_CODES` (ordered tuple) and `REASON_TEXT` (dict code → English sentence), see §7.
- `LAG_BUCKETS` and `CVSS_BANDS`, see §6.
- Frozen dataclasses `CveRecord`, `KevEntry`, `EpssSnapshot`, `Finding`, `BacktestConfig`,
  `TriageConfig` with the fields and defaults shown in the file.
- `cvss_band(score) -> str` helper, see §6.

## 3. Ingestion (`vulnprio/ingest.py`)

Module constant `CHUNK_SIZE = 1 << 20`. Functions must read the **module global at call time**
(`ingest.CHUNK_SIZE`), not capture it as a default argument — tests lower it to force tiny chunks.

`open_text(path: str)` returns a text stream: `gzip.open(path, "rt", encoding="utf-8-sig",
newline="")` for `.gz`, else `open(path, "r", encoding="utf-8-sig", newline="")`.

`parse_cwe_list(text: str) -> tuple[str, ...]`: all matches of `CWE-\d+` in `text`, unique, sorted
by the integer after `CWE-` ascending. (`"NVD-CWE-noinfo"` therefore yields nothing.)

### 3.1 `iter_nvd_items(path: str) -> Iterator[object]`

Yields, in order, every element (any JSON value) of the top-level `"vulnerabilities"` array of an
NVD CVE JSON 2.0 file, **streaming**:

- Read the file with `fh.read(ingest.CHUNK_SIZE)` repeatedly; never read the whole file at once
  and never call `json.load`/`json.loads` on the whole content. Decode elements one by one with
  `json.JSONDecoder().raw_decode`, discarding consumed text so memory stays bounded by roughly one
  element plus one chunk.
- Locate the first occurrence of the text `"vulnerabilities"`; after it, optional whitespace, `:`,
  optional whitespace, `[` must follow. Then elements separated by `,` and whitespace until the
  closing `]`. Anything after the closing `]` is ignored.
- Errors (raise `VulnprioError`):
  - end of file before the array start, or the key is not followed by `:` and `[`:
    `"not an NVD CVE 2.0 feed: <path>"`
  - end of file before the closing `]`, or an element that is not valid JSON:
    `"truncated or invalid NVD feed: <path>"`

### 3.2 `parse_nvd_item(item: object) -> CveRecord | None`

Returns `None` (the item is "skipped") unless all of these hold: `item` is a dict, `item["cve"]` is a
dict, `cve["id"]` is a str matching `CVE_RE`, and `cve["published"]` is a str whose first 10
characters parse with `date.fromisoformat`.

- `cve_id` = `cve["id"]`; `published` = that date.
- `vuln_status` = `cve["vulnStatus"]` if it is a str, else `""`.
- CVSS: `metrics = cve.get("metrics")` (use `{}` if not a dict). For `key` in
  `("cvssMetricV31", "cvssMetricV30")` in that order: take the list (ignore if not a non-empty list);
  candidates = its entries that are dicts whose `"cvssData"` is a dict whose `"baseScore"` is an
  `int` or `float` (not `bool`). If there are candidates: chosen = the first candidate with
  `"type" == "Primary"`, otherwise the first candidate. Then `cvss_score = float(baseScore)`,
  `cvss_version = "3.1"` for `cvssMetricV31` or `"3.0"` for `cvssMetricV30`, `cvss_source_type =
  chosen["type"]` if it is a str else `None`; stop. If no key yields a candidate, all three are
  `None` (CVSS v2 and v4 are ignored).
- `cwes`: concatenate every `"value"` str found in `cve["weaknesses"][*]["description"][*]`
  (skip anything malformed), then apply `parse_cwe_list` to the values joined by `" "`.

### 3.3 `parse_kev_csv(path: str) -> tuple[list[KevEntry], int]`

Reads the CISA KEV CSV with `csv.DictReader(open_text(path))`.

- Required columns, checked in this order: `cveID`, `vendorProject`, `product`, `dateAdded`,
  `knownRansomwareCampaignUse`. The first missing one raises
  `VulnprioError(f"KEV file is missing column '{name}': {path}")`. A file with no header row is
  treated as missing `cveID`. `cwes` is optional. Extra columns are ignored.
- Per data row (treat `None` values as `""`): `cve_id = cveID.strip().upper()`; skip the row if it
  does not match `CVE_RE`. `date_added = date.fromisoformat(dateAdded.strip())`; skip the row on
  `ValueError`. `vendor = vendorProject.strip()`, `product = product.strip()`,
  `ransomware = knownRansomwareCampaignUse.strip().lower() == "known"`,
  `cwes = parse_cwe_list(row.get("cwes") or "")`.
- The second return value counts skipped rows. Duplicate `cve_id`s are not counted as skipped:
  keep the entry with the earliest `date_added` (on a tie keep the first one read).
- Return the entries sorted by `(date_added, cve_id)`.

### 3.4 `parse_epss_csv(path: str, snapshot_date: date | None = None) -> EpssSnapshot`

- Lines come from `open_text(path)`. A file with no lines (or only a comment line) raises
  `VulnprioError(f"EPSS file is empty: {path}")`.
- If the first line starts with `#`, it is metadata: remove the `#`, split on `,`, split each part
  at the first `:` into key/value (both stripped). `model_version` = the value for key
  `model_version` (else `None`). `score_date` = `date.fromisoformat(value[:10])` for key
  `score_date` (ignored if missing or invalid).
- The next line is the header, parsed with `csv`. It must contain `cve` and `epss` (checked in that
  order, exact names after stripping) else
  `VulnprioError(f"EPSS file is missing column '{name}': {path}")`. `percentile` is optional.
- Each data row: `cve = value.strip().upper()` must match `CVE_RE`; `epss = float(value)` must be
  finite and `0 <= epss <= 1`; otherwise the row is skipped and counted in `skipped_rows`.
  `percentile` is stored only when it parses as a finite float in `[0, 1]` (an invalid percentile
  does not skip the row). For a duplicate `cve`, the first valid row wins (not counted as skipped).
- Snapshot date, first available of: the `snapshot_date` argument; the metadata `score_date`; the
  first `\d{4}-\d{2}-\d{2}` match in `os.path.basename(path)` that is a valid date. If none:
  `VulnprioError(f"cannot determine EPSS snapshot date: {path}")`.
- Returns `EpssSnapshot(snapshot_date, model_version, scores, percentiles, skipped_rows)` where
  `scores: dict[str, float]` and `percentiles: dict[str, float]`.

### 3.5 `parse_findings_csv(path: str) -> tuple[list[Finding], int]`

An organisation's vulnerability findings (for example a scanner export).

- Required columns in this order: `asset_id`, `cve_id`; else
  `VulnprioError(f"findings file is missing column '{name}': {path}")`. Optional columns:
  `asset_criticality`, `internet_facing`.
- Per row: `asset_id = strip()`, `cve_id = strip().upper()`. Skip (and count) the row if `asset_id`
  is empty or `cve_id` does not match `CVE_RE`. `asset_criticality = strip().lower()`; values other
  than `high`, `medium`, `low` (including empty/missing) become `"medium"`.
  `internet_facing = strip().lower() in {"true", "yes", "y", "1"}`.
- A row whose `(asset_id, cve_id)` was already accepted is skipped and counted.
- Returns the accepted findings in file order and the skipped count.

## 4. Storage (`vulnprio/storage.py`, sqlite3)

`SCHEMA` (module constant, run with `executescript`) — exactly:

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
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
```

`cwes` columns hold `json.dumps(list(cwes))`; dates are ISO strings; `ransomware` is 0/1.
Always use `?` placeholders.

### 4.1 `build_database(db_path, nvd_paths, kev_path, epss_paths, *, force=False) -> dict`

- If `db_path` exists and `force` is false:
  `VulnprioError(f"database already exists: {db_path} (use --force to replace it)")`.
- Build into `db_path + ".tmp"` (remove a stale one first), then `os.replace` it onto `db_path`
  only after everything succeeded. On any exception the temporary file is removed and the
  exception propagates; an existing database is left byte-for-byte unchanged.
- NVD: for each path in order, for each item of `iter_nvd_items`: `parse_nvd_item`; `None` counts in
  `nvd_items_skipped`; a `cve_id` already loaded in this build counts in `nvd_duplicates` and the
  later record replaces the earlier one.
- KEV: `parse_kev_csv(kev_path)`, insert all entries.
- EPSS: for each path in order, `parse_epss_csv(path)`; a snapshot date already loaded raises
  `VulnprioError(f"duplicate EPSS snapshot date {d}: {path}")`. Insert every score (with its
  percentile or NULL) and one `epss_snapshots` row (`row_count = len(scores)`).
- Insert in batches with `executemany`; commit once at the end.
- Returns (and stores as `meta` key `build_summary`, `json.dumps(..., sort_keys=True)`; also store
  `schema_version` = `"1"` and `tool_version` = `"1.0.0"`):

```json
{"schema_version": 1, "cves": <rows in cves incl. rejected>, "cves_rejected": <vuln_status == "Rejected">,
 "cves_without_cvss": <non-rejected with NULL cvss_score>, "nvd_files": <len(nvd_paths)>,
 "nvd_items_skipped": n, "nvd_duplicates": n, "kev_entries": n, "kev_rows_skipped": n,
 "kev_as_of": "<max date_added>" or null,
 "epss_snapshots": [{"snapshot_date": "...", "model_version": str or null, "rows": n, "rows_skipped": n}, ...]}
```

`epss_snapshots` is sorted by `snapshot_date`.

### 4.2 `connect(db_path) -> sqlite3.Connection`

Opens an existing database. Missing file: `VulnprioError(f"database not found: {db_path}")` (no
file is created). If the file is not an SQLite database or has no `meta` row
`schema_version = "1"`: `VulnprioError(f"not a vulnprio database: {db_path}")` (catch
`sqlite3.DatabaseError`).

`load_summary(conn) -> dict` returns the stored `build_summary`.

## 5. Backtest (`vulnprio/backtest.py`)

`run_backtest(conn, dates: list[date] | None = None, config: BacktestConfig = BacktestConfig()) -> dict`

### 5.1 Decision dates

- `kev_as_of` = max `date_added` in `kev`; empty table: `VulnprioError("KEV table is empty")`.
- A snapshot date `D` has a **complete outcome window** when `D + horizon_days <= kev_as_of`.
- `dates is None`: use every `epss_snapshots.snapshot_date` with a complete window, ascending. None:
  `VulnprioError("no EPSS snapshot has a complete outcome window")`.
- Explicit `dates`: remove duplicates, sort ascending. A date that is not a snapshot:
  `VulnprioError(f"no EPSS snapshot for {D}")`. A snapshot without a complete window:
  `VulnprioError(f"outcome window for {D} ends after the KEV data ({kev_as_of})")`.

### 5.2 Population for decision date D (leakage-free)

Apply these filters in order to `cves`; counts of removed CVEs are diagnostics:

1. `vuln_status != "Rejected"` and `D - lookback_days <= published < D` → *candidates*
   (rejected or out-of-window CVEs are not counted anywhere).
2. `cvss_score IS NULL` → removed, counted in `excluded_no_cvss`. Among these, those with a KEV
   `date_added` in `(D, D + horizon_days]` are counted in `positives_without_cvss`.
3. no EPSS score in snapshot D → removed, `excluded_no_epss`.
4. a KEV entry with `date_added <= D` (already known exploited at decision time) → removed,
   `excluded_known_exploited`.

The remaining CVEs are the **population** (size N). A population CVE is **positive** when it has a
KEV entry with `D < date_added <= D + horizon_days`. P = number of positives.

### 5.3 Strategies (each selects a subset of the population)

| name | rule |
|---|---|
| `CVSS_CRITICAL` | `cvss_score >= 9.0` |
| `CVSS_HIGH_PLUS` | `cvss_score >= 7.0` |
| `EPSS_EFFORT_MATCHED` | the first K CVEs when ordered by `(-epss, cve_id)`, K = number selected by `CVSS_CRITICAL` (same effort) |
| `EPSS_THRESHOLD` | `epss >= config.epss_threshold` |

Metrics for a strategy (F = selected, TP = selected positives):

```
effort     = F / N              (0.0 when N == 0)
coverage   = TP / P             (None when P == 0)
efficiency = TP / F             (None when F == 0)
lift       = (TP / F) / (P / N) (None when F == 0 or P == 0)
```

Metric dict (key order irrelevant):
`{"strategy", "flagged": F, "true_positives": TP, "effort", "coverage", "efficiency", "lift"}`.

### 5.4 Result

```json
{
  "config": {"lookback_days", "horizon_days", "epss_threshold", "bootstrap_iterations", "seed", "confidence"},
  "kev_as_of": "YYYY-MM-DD",
  "decision_dates": ["YYYY-MM-DD", ...],
  "per_date": [ {
      "decision_date", "window_end" (D + horizon_days), "epss_model_version" (str or null),
      "population": N, "positives": P, "base_rate" (P / N, null when N == 0),
      "excluded_no_cvss", "excluded_no_epss", "excluded_known_exploited", "positives_without_cvss",
      "strategies": [metric dicts in STRATEGIES order] }, ... ],
  "pooled": {"population": ΣN, "positives": ΣP, "base_rate", "strategies": [...]},
  "effort_curve": {"levels_pct": [1, 2, 5, 10, 20, 30, 50, 100], "EPSS": [...], "CVSS": [...]},
  "bootstrap": {...} or null
}
```

- `pooled` strategies use ΣF, ΣTP, ΣN, ΣP over all decision dates with the §5.3 formulas.
- **Effort curve.** For each date, rank the population by EPSS (`(-epss, cve_id)`) and separately by
  CVSS (`(-cvss_score, cve_id)` — no EPSS tie-break). For each level `pct`, take the top
  `k = (pct * N + 99) // 100` (integer arithmetic) of each ranking. The curve value is
  Σ(positives in the top k over dates) / ΣP, rounded; `null` when ΣP == 0.
- **Bootstrap** (paired, compares `EPSS_EFFORT_MATCHED` against `CVSS_CRITICAL`):
  - Positive instances = every (decision_date, cve_id) positive, sorted by (decision_date, cve_id),
    each with flags `a` = selected by `EPSS_EFFORT_MATCHED`, `b` = selected by `CVSS_CRITICAL`.
    n = their number; if n == 0 the value is `null`.
  - `rng = random.Random(config.seed)`. For each of `bootstrap_iterations` iterations draw n indices,
    each `int(rng.random() * n)`, in sequence; `diff = (Σa − Σb over the draws) / n`.
  - Sort the diffs; `lo = int(math.floor(B * (1 - confidence) / 2 + 1e-9))`, `hi = B - 1 - lo`
    (B = iterations).
  - Value: `{"compare": ["EPSS_EFFORT_MATCHED", "CVSS_CRITICAL"], "metric": "coverage_difference",
    "positives": n, "iterations": B, "confidence", "seed", "point_estimate": (Σa − Σb) / n,
    "ci_low": diffs[lo], "ci_high": diffs[hi], "significant": ci_low > 0 or ci_high < 0}` —
    `point_estimate`, `ci_low`, `ci_high` rounded; `significant` computed before rounding.

## 6. Insights (`vulnprio/insights.py`)

`compute_insights(conn, start: date, end: date, top_n: int = 10) -> dict` over the **window
entries**: KEV entries with `start <= date_added <= end`.

```json
{"window": {"start", "end"}, "kev_entries": n,
 "ransomware": {"count", "share"},
 "with_nvd": n,
 "lag_days": {"count", "median", "mean", "buckets": [{"label", "count", "share"}, ...]},
 "cvss_bands": [{"band", "count", "share"}, ...],
 "below_critical_share": x, "below_high_share": x,
 "top_vendors": [{"vendor", "count", "ransomware"}, ...],
 "top_cwes": [{"cwe", "count"}, ...]}
```

- `ransomware.share` = count / kev_entries (null when 0).
- `with_nvd` = window entries whose CVE exists in `cves` (any status). `lag_days`, `cvss_bands` and
  the two shares use only these entries. `lag = (date_added - published).days` (may be negative).
- `lag_days.count` = with_nvd; `median` = `round(float(statistics.median(lags)), 1)`, `mean` =
  `round(float(statistics.fmean(lags)), 1)`, both null when there are no lags.
- `LAG_BUCKETS` (models.py) in order: `"<=0"` (lag <= 0), `"1-7"`, `"8-30"`, `"31-90"`,
  `"91-365"` (inclusive integer ranges), `">365"`. Share = count / with_nvd (null when 0). All six
  buckets always present.
- `CVSS_BANDS` in order `critical, high, medium, low, none, unscored`, using `cvss_band(score)`:
  None → `unscored`; >= 9.0 `critical`; >= 7.0 `high`; >= 4.0 `medium`; > 0.0 `low`; else `none`.
  All six always present; share = count / with_nvd (null when 0).
- `below_critical_share` / `below_high_share`: among with_nvd entries with a non-null score, the
  share with score < 9.0 / < 7.0 (null when none are scored).
- `top_vendors`: group window entries by vendor; `count` and `ransomware` (number with ransomware);
  sort by `(-count, vendor)`, first `top_n`.
- `top_cwes`: count each CWE in the window entries' KEV `cwes`; sort by
  `(-count, integer CWE number)`, first `top_n`.

## 7. Triage (`vulnprio/triage.py`)

`run_triage(conn, findings, as_of: date | None = None, config: TriageConfig = TriageConfig(),
rows_skipped: int = 0) -> dict`

Reference data per finding:

- EPSS snapshot used: the latest `snapshot_date <= as_of` (the latest overall when `as_of` is None);
  if none exists every EPSS value is None. `e` = the CVE's EPSS in that snapshot or None.
- `kev` = the CVE has a KEV entry and (`as_of` is None or `date_added <= as_of`).
- `s` = `cvss_score` from `cves` (None if absent); `known` = the CVE exists in `cves`.

Tier (first match wins):

1. `P1` if `kev`.
2. `P2` if (`e` is not None and `e >= epss_high`) or (`s` is not None and `s >= cvss_critical` and
   `internet_facing`).
3. `P3` if (`s` is not None and `s >= cvss_high`) or (`e` is not None and `e >= epss_medium`).
4. `P4` otherwise.

Escalation: if `asset_criticality == "high"` and the tier is `P3` or `P4`, raise it one level
(`P3→P2`, `P4→P3`).

`reasons`: every code whose condition holds, in `REASON_CODES` order:

| code | condition |
|---|---|
| `KEV` | `kev` |
| `RANSOMWARE` | `kev` and the KEV entry has ransomware |
| `EPSS_HIGH` | `e >= epss_high` |
| `CRITICAL_INTERNET_FACING` | `s >= cvss_critical` and internet_facing |
| `CVSS_CRITICAL` | `s >= cvss_critical` |
| `CVSS_HIGH` | `cvss_high <= s < cvss_critical` |
| `EPSS_MEDIUM` | `epss_medium <= e < epss_high` |
| `UNKNOWN_CVE` | not `known` and `e` is None and not `kev` |
| `ESCALATED_ASSET_CRITICALITY` | escalation applied |

Items are sorted by `(tier index, -(e if e is not None else -1.0), -(s if s is not None else -1.0),
asset_id, cve_id)`. Result:

```json
{"as_of": "YYYY-MM-DD" or null, "epss_snapshot": "YYYY-MM-DD" or null,
 "summary": {"findings": n, "rows_skipped": n, "tiers": {"P1": n, "P2": n, "P3": n, "P4": n},
             "kev": n, "ransomware": n, "unknown_cves": n},
 "items": [{"rank": 1.., "asset_id", "cve_id", "tier", "kev", "kev_date_added" (or null),
            "ransomware", "epss" (rounded or null), "cvss" (or null), "asset_criticality",
            "internet_facing", "reasons": [codes]}, ...]}
```

`summary.ransomware` counts items with reason `RANSOMWARE`; `unknown_cves` counts items with
`UNKNOWN_CVE`; `ransomware` in an item is true only when `kev` is true and the entry has ransomware;
`kev_date_added` is the entry's `date_added` when `kev` is true, else null (a KEV entry added after
`as_of` is ignored completely). `cvss` is the stored score unchanged.

## 8. Reports (`vulnprio/report.py`)

- `to_json(obj) -> str`: `json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"`.
- `build_analysis_report(conn, backtest, insights) -> dict`:
  `{"schema_version": 1, "tool": "vulnpriority-analytics", "version": "1.0.0",
  "data": load_summary(conn), "backtest": backtest, "insights": insights}`.
- Formatting helpers used by Markdown and HTML: percentage `f"{x * 100:.2f}%"`, lift `f"{x:.2f}x"`,
  `None` → `n/a`.
- `render_analysis_markdown(report) -> str` — starts with `# Vulnerability Prioritization Report`
  and contains, in order, the sections `## Data`, `## Pooled results` (a table with header
  `| Strategy | Flagged | Effort | Coverage | Efficiency | Lift |` and one row per strategy),
  `## Statistical comparison` (states the point estimate and confidence interval, or
  `Not enough positives for a bootstrap.`), `## Per decision date`, `## Effort curve`,
  `## Exploitation insights` (lag buckets, CVSS bands, top vendors, top CWEs) and `## Limitations`.
  Escape `|` in table cells as `\|`. Ends with a newline.
- `render_analysis_html(report) -> str` — a self-contained page: starts with `<!DOCTYPE html>`,
  contains `<html lang="en">`, `<meta charset="utf-8">` and
  `<title>Vulnerability Prioritization Report</title>`, an inline `<style>`, the same sections as
  the Markdown (as HTML headings and tables), and **at least three inline `<svg>` charts**: pooled
  coverage per strategy (bars), the effort curve (EPSS and CVSS lines) and the lag buckets (bars).
  Every `<svg>` contains a `<title>` element. No `<script`, no `<link`, no `src=` attributes. Every
  piece of data text is escaped with `html.escape`.
- `render_triage_csv(result) -> str` — `csv.writer(..., lineterminator="\n")`, header
  `rank,tier,asset_id,cve_id,kev,ransomware,epss,cvss,asset_criticality,internet_facing,reasons`;
  booleans `yes`/`no`; epss `f"{e:.6f}"`, cvss `f"{s:.1f}"`, empty when None; reasons joined by `;`.
- `render_triage_markdown(result) -> str` — starts with `# Remediation Plan`, a summary table of
  the four tiers, then a table `| Rank | Tier | Asset | CVE | EPSS | CVSS | Why |` where Why is the
  `REASON_TEXT` sentences joined by `"; "` (`-` when there are none). Escape `|`.

## 9. CLI (`vulnprio/cli.py`)

`main(argv: list[str] | None = None) -> int`, argparse `prog="vulnprio"`.

- `--version` prints `vulnpriority-analytics 1.0.0` and returns 0.
- No command: print help to stderr, return 2. argparse usage errors keep exit code 2 (catch
  `SystemExit` around `parse_args` and return its code; `--help` returns 0).
- Date arguments use a type function based on `date.fromisoformat`; invalid → argparse error (2).
- Runtime errors (`VulnprioError`, `OSError`, `sqlite3.Error`, invalid numeric options): print
  `error: <message>` to stderr and return 1.
- Output: with `--output FILE` write the rendered text to FILE
  (`open(FILE, "w", encoding="utf-8", newline="")`) and print nothing to stdout; otherwise write it
  to stdout.

Commands:

1. `build --db DB --nvd FILE [FILE ...] --kev FILE --epss FILE [FILE ...] [--force]` — runs
   `build_database`, prints `to_json(summary)`, returns 0.
2. `analyze --db DB [--date YYYY-MM-DD ...] [--lookback-days 730] [--horizon-days 365]
   [--epss-threshold 0.1] [--bootstrap 1000] [--seed 42] [--confidence 0.95]
   [--format json|markdown|html] [--output FILE]` — `--date` may be repeated (`action="append"`).
   Validation (exit 1): lookback and horizon >= 1, `0 < epss-threshold <= 1`, bootstrap >= 1,
   `0 < confidence < 1`. Runs `run_backtest`, then `compute_insights(conn, min(decision_dates),
   max(decision_dates) + horizon_days)`, then `build_analysis_report`, rendered with `to_json`
   (default), `render_analysis_markdown` or `render_analysis_html`.
3. `triage --db DB --findings FILE [--as-of YYYY-MM-DD] [--format csv|json|markdown]
   [--output FILE]` — `parse_findings_csv`, `run_triage(..., rows_skipped=skipped)`, rendered with
   `render_triage_csv` (default), `to_json` or `render_triage_markdown`.

## 10. Tests, samples and documentation

- Unit tests (`tests/`) cover every module, including streaming with a tiny `CHUNK_SIZE`, `.gz`
  inputs, every error message, each strategy and metric edge case (N == 0, P == 0, F == 0),
  boundary dates of the population and outcome windows, triage tiers/escalation/reasons, report
  formats and CLI exit codes. Temporary directories only.
- The provided samples are **synthetic** (fictional CVEs and vendors, random scores) in the real file
  formats. With default settings (lookback 730, horizon 365) both sample snapshot dates have complete
  outcome windows and at least one positive each, at least one KEV entry is ransomware-linked, and
  `samples/findings-sample.csv` triaged without `--as-of` yields every tier P1–P4. Sample results
  are illustrative only; the README must say so.
- `docs/DATA_SOURCES.md` (provided) lists the official download locations and the recommended
  real-data set; the README's `## Real data` section links to it and shows the build/analyze commands
  for that set.
- `docs/METHODOLOGY.md`: the time-split design, population filters, strategies, metrics, effort
  curve, bootstrap, and threats to validity (CVSS scores are as of download; KEV is an incomplete,
  US-government-centred ground truth; population limited to the lookback window; arbitrary but
  deterministic CVSS tie-breaks).
- `README.md` with sections `## Problem`, `## Features`, `## Installation`, `## Quick start`
  (build/analyze/triage on the samples), `## Real data`, `## Commands`, `## Outputs`,
  `## SQL views`, `## Methodology`, `## Testing`, `## Limitations`.
