# vulnpriority-analytics

An offline Python toolkit for measuring vulnerability prioritization and turning scanner findings
into an auditable remediation plan. Version 1.0.0 uses Python's standard library and SQLite.

## Problem

Security teams have more findings than remediation capacity. Severity alone does not indicate
which vulnerabilities will become known exploited. This toolkit compares CVSS and EPSS strategies
at historical decision dates, measures their coverage at different effort levels, and combines
exploitation evidence with asset context to prioritize current findings.

## Features

- Stream NVD CVE JSON 2.0 feeds, including gzip files, without loading an entire feed into memory.
- Ingest CISA KEV and historical FIRST EPSS snapshots into an atomically built SQLite database.
- Compare four strategies across complete, time-split outcome windows with pooled metrics.
- Produce an effort–coverage curve and a seeded, paired bootstrap confidence interval.
- Explore exploitation lags, CVSS bands, ransomware links, vendors and CWEs.
- Triage findings into P1–P4 tiers with ordered reason codes and asset-criticality escalation.
- Export deterministic JSON, Markdown, self-contained HTML with inline SVG charts, and triage CSV.

All operations run locally. The toolkit never downloads data or executes third-party code.

## Installation

Use Python **3.10 or later**, with its standard `sqlite3` module available. There are no pip
dependencies. From the repository root:

```bash
python3 --version
python3 -m vulnprio --version
```

Run commands from this directory, or place its parent package directory on `PYTHONPATH`.

## Quick start

The supplied data is **synthetic**: fictional CVEs and vendors with random scores in the real
feed formats. Sample results are illustrative only and do not support conclusions about real
vulnerabilities or strategy effectiveness.

Keep generated artifacts outside the source directory:

```bash
OUT=$(mktemp -d)
python3 -m vulnprio build \
  --db "$OUT/sample.sqlite" \
  --nvd samples/nvdcve-2.0-sample.json \
  --kev samples/kev-sample.csv \
  --epss samples/epss_scores-2025-01-01.csv samples/epss_scores-2025-04-01.csv

python3 -m vulnprio analyze --db "$OUT/sample.sqlite" \
  --format html --output "$OUT/analysis.html"
python3 -m vulnprio analyze --db "$OUT/sample.sqlite" \
  --format json --output "$OUT/analysis.json"
python3 -m vulnprio analyze --db "$OUT/sample.sqlite" \
  --format markdown --output "$OUT/analysis.md"

python3 -m vulnprio triage --db "$OUT/sample.sqlite" \
  --findings samples/findings-sample.csv --output "$OUT/remediation.csv"
python3 -m vulnprio triage --db "$OUT/sample.sqlite" \
  --findings samples/findings-sample.csv --format markdown --output "$OUT/remediation.md"
```

The sample build contains 49 CVEs, 11 KEV entries and two EPSS snapshots. Both snapshot dates
have complete default outcome windows and six positives in their respective populations.
Sample triage without `--as-of` includes all four remediation tiers.

## Real data

See [Data sources](docs/DATA_SOURCES.md) for the official download locations, used fields,
integrity information and recommended dataset. Download the files separately; then run the toolkit
offline. For the recommended five NVD yearly feeds, current KEV CSV and eight quarterly EPSS
snapshots, with files in `data/`:

```bash
OUT=$(mktemp -d)
python3 -m vulnprio build --db "$OUT/real.sqlite" \
  --nvd data/nvdcve-2.0-2021.json.gz data/nvdcve-2.0-2022.json.gz \
        data/nvdcve-2.0-2023.json.gz data/nvdcve-2.0-2024.json.gz \
        data/nvdcve-2.0-2025.json.gz \
  --kev data/known_exploited_vulnerabilities.csv \
  --epss data/epss_scores-2024-01-01.csv.gz data/epss_scores-2024-04-01.csv.gz \
         data/epss_scores-2024-07-01.csv.gz data/epss_scores-2024-10-01.csv.gz \
         data/epss_scores-2025-01-01.csv.gz data/epss_scores-2025-04-01.csv.gz \
         data/epss_scores-2025-07-01.csv.gz data/epss_scores-2025-10-01.csv.gz

python3 -m vulnprio analyze --db "$OUT/real.sqlite" \
  --format html --output "$OUT/real-analysis.html"
```

The default 365-day horizon requires a maximum KEV addition date of at least 2026-10-01 to
include all eight snapshots. Automatic date selection uses only complete windows. An explicitly
requested date with an incomplete window is an error.

## Commands

Use `python3 -m vulnprio COMMAND --help` for full argument syntax.

| Command | Required arguments | Optional arguments |
| --- | --- | --- |
| `build` | `--db DB --nvd FILE [FILE ...] --kev FILE --epss FILE [FILE ...]` | `--force`, `--output FILE` |
| `analyze` | `--db DB` | `--date YYYY-MM-DD` (repeatable), analysis settings below, `--format json\|markdown\|html`, `--output FILE` |
| `triage` | `--db DB --findings FILE` | `--as-of YYYY-MM-DD`, `--format csv\|json\|markdown`, `--output FILE` |

Analysis defaults are `--lookback-days 730`, `--horizon-days 365`, `--epss-threshold 0.1`,
`--bootstrap 1000`, `--seed 42`, and `--confidence 0.95`. Lookback, horizon and bootstrap iterations
must be at least 1; EPSS threshold must be in `(0, 1]` and confidence in `(0, 1)`.

Build refuses to overwrite a database unless `--force` is given. It builds `DB.tmp` and replaces
the destination only after a successful commit. Build summaries report skipped records and
duplicates. Later NVD records replace earlier records with the same CVE. KEV keeps the earliest
addition date; EPSS keeps the first valid score for a CVE. Duplicate EPSS snapshot dates fail the
build.

Findings CSV requires `asset_id,cve_id`. Optional columns are `asset_criticality`
(`high`, `medium`, `low`; default `medium`) and `internet_facing` (`true`, `yes`, `y`, `1` mean true).
Duplicate asset/CVE pairs and invalid rows are skipped and counted. Triage uses the latest EPSS
snapshot at or before `--as-of` and ignores later KEV additions; without `--as-of` it uses the latest
snapshot and all loaded KEV entries.

| Tier | Initial rule, in precedence order |
| --- | --- |
| P1 | Known exploited in KEV |
| P2 | EPSS ≥ 0.1, or CVSS ≥ 9.0 on an internet-facing asset |
| P3 | CVSS ≥ 7.0, or EPSS ≥ 0.01 |
| P4 | Remaining findings |

High-criticality assets escalate P3 to P2 and P4 to P3. Findings sort by tier, descending EPSS,
descending CVSS, asset ID and CVE ID, with missing scores last. JSON includes the reference date,
snapshot, ranks, reasons and skipped-row counts.

Exit codes are **0** for success (including help/version), **1** for runtime or data errors,
and **2** for CLI usage errors or a missing command. Runtime errors start with `error: ` on stderr.

## Outputs

By default, rendered text goes to stdout; `--output FILE` writes UTF-8 text and suppresses stdout.
Identical inputs and settings produce byte-identical reports without timestamps, host names or
input paths.

| Output | Content |
| --- | --- |
| Build JSON | Data counts, exclusions at ingestion, KEV coverage date and EPSS snapshot metadata |
| Analysis JSON (default) | Versioned envelope, build summary, per-date and pooled metrics, curve, bootstrap and insights |
| Analysis Markdown | Data, pooled results, statistical comparison, decision dates, effort curve, exploitation insights and limitations |
| Analysis HTML | The same analysis plus three accessible inline SVG charts; no external resources or scripts |
| Triage CSV (default) | Ranked findings, tiers, KEV/ransomware flags, scores, asset context and semicolon-separated reason codes |
| Triage JSON / Markdown | Structured remediation details or a readable plan with English reasons and tier counts |

Ratios in result dictionaries round once to six decimal places. Displayed percentages have two
decimal places. Undefined metrics appear as JSON `null`, report `n/a`, or empty CSV scores.
CSV uses `yes`/`no` booleans, six decimal places for EPSS and one for CVSS.

The Python API is available through `vulnprio.ingest`, `storage`, `backtest`, `insights`, `triage`
and `report`. Configuration dataclasses and ordered constants are in `vulnprio.models`.

## SQL views

The database contains `meta`, `cves`, `kev`, `epss_snapshots` and `epss` tables, plus three views:

| View | Purpose |
| --- | --- |
| `v_kev_lag` | KEV entries joined to NVD, including publication date, addition date, lag days, CVSS, vendor and ransomware |
| `v_cvss_bands` | Non-rejected NVD CVE counts and KEV counts by CVSS severity band |
| `v_kev_vendors` | Exploited and ransomware-linked KEV entry counts by vendor |

For example, using a separately available SQLite CLI:

```bash
sqlite3 "$OUT/sample.sqlite" 'SELECT * FROM v_cvss_bands ORDER BY band;'
sqlite3 "$OUT/sample.sqlite" 'SELECT * FROM v_kev_vendors ORDER BY exploited DESC, vendor;'
```

Views describe all loaded data. Analysis insights use their explicitly reported KEV date window.

## Methodology

At each historical decision date, scores come from that date's EPSS snapshot. The population
contains recently published, non-rejected CVEs with both CVSS and EPSS, excluding vulnerabilities
already in KEV. Positives are vulnerabilities added to KEV within the following outcome window.
Strategies are CVSS critical, CVSS high or above, EPSS at matched critical effort, and an EPSS
threshold. Pooled metrics aggregate integer counts across dates. The effort curve compares rankings
at fixed budgets; the paired bootstrap resamples positive date/CVE instances.

See [Methodology](docs/METHODOLOGY.md) for exact formulas, boundaries, tie-breaks, confidence
interval construction and interpretation.

## Testing

```bash
python3 -m unittest discover -s tests -t .
```

Tests use only the standard library, local samples, in-memory SQLite and temporary directories.
They require no network and do not write into the repository, so the repository root can be
read-only. Set `PYTHONDONTWRITEBYTECODE=1` to suppress Python's optional import caches as well.

## Limitations

- CVSS values reflect the download date and may contain revisions made after a decision date.
- KEV is an incomplete, US-government-centred ground truth. Its addition dates measure recognition
  of exploitation rather than the first exploitation event. Absence from KEV does not prove safety.
- The population is limited to the lookback window and requires both scores. Diagnostics expose
  missing-score exclusions and positives without CVSS.
- CVSS ties use an arbitrary, deterministic CVE ID order; results near effort cutoffs can depend on it.
- EPSS predicts activity over 30 days; longer backtest horizons evaluate ranking utility over that
  window and do not validate the probability calibration for it.
- Overlapping decision windows can contain the same CVE. Pooled counts are date/CVE instances;
  the specified bootstrap resamples those instances and does not model all temporal dependence.
- Triage provides a transparent default policy. It needs local review alongside remediation cost,
  compensating controls and asset context. Synthetic samples are illustrative only.
