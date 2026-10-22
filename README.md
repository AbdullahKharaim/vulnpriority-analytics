# VulnPriority Analytics

**Which vulnerabilities should a security team patch first?** VulnPriority Analytics is an offline
Python toolkit that backtests patch-prioritisation strategies on real public data (NVD, CISA KEV
and FIRST EPSS) and turns an organisation's scanner findings into an auditable P1–P4 remediation
plan. Version 1.0.0 uses only Python's standard library and SQLite.

> This project was built with the author's **AI Development Team** workflow, in which Claude Code
> (architect and reviewer) and Codex CLI (implementer) collaborate under human supervision. See
> [How this project was built](#how-this-project-was-built) for exactly what that means.

## Results on real data

One run on public data, with the CISA KEV catalogue as of **2026-10-16**. Numbers come from
[`results/report.json`](results/report.json); readable versions are in
[`results/report.md`](results/report.md) and [`results/report.html`](results/report.html).

| Dataset | Size |
| --- | --- |
| NVD CVE JSON 2.0 feeds 2021–2025 | 167,132 CVEs (5,348 rejected, 3,388 without a CVSS v3 score) |
| CISA Known Exploited Vulnerabilities | 1,748 entries |
| FIRST EPSS daily snapshots | 8 quarterly snapshots, 2024-01-01 to 2025-10-01 (2,099,758 scores, models v2023.03.01 and v2025.03.14) |

**Backtest design.** At each of the 8 decision dates, the population is CVEs published in the
previous 730 days that had a CVSS score and an EPSS score and were not yet in KEV. A CVE counts
as *later exploited* if it was added to KEV within the next 365 days. This gives 522,907
CVE-decision instances and 284 later-exploited ones (base rate 0.054%, about 1 in 1,841).

| Strategy (pooled over 8 dates) | Share patched (effort) | Later-exploited caught (coverage) | Lift vs. random |
| --- | --- | --- | --- |
| CVSS ≥ 9.0 ("critical only") | 14.00% | 42.61% | 3.04× |
| CVSS ≥ 7.0 | 51.27% | 90.85% | 1.77× |
| Top EPSS, same effort as "critical only" | 14.00% | 49.30% | 3.52× |
| EPSS ≥ 0.1 | 1.38% | 20.77% | 15.09× |

| Patching budget | Coverage when ranking by EPSS | Coverage when ranking by CVSS |
| --- | --- | --- |
| 1% | 19.37% | 5.28% |
| 2% | 23.94% | 6.69% |
| 5% | 34.15% | 8.45% |
| 10% | 44.37% | 23.24% |
| 20% | 55.28% | 48.94% |
| 30% | 64.08% | 62.68% |
| 50% | 75.35% | 88.38% |

**What the numbers say**

- With a small budget, EPSS ranking is far better. Patching the top 1% caught 3.7× as many
  later-exploited CVEs as the top 1% by CVSS (19.37% vs 5.28%).
- With a large budget, CVSS catches up and then overtakes. At 50% effort it caught 88.38% vs 75.35%.
- At exactly the "critical only" effort, EPSS caught 6.69 percentage points more. **This difference
  is not statistically significant**: the paired bootstrap 95% confidence interval is −0.35 to
  +14.08 points (1,000 resamples of the 284 positives, seed 42).
- Observation, not a tested result: under the newer EPSS model (v2025.03.14, last three dates),
  top-EPSS beat "critical only" at all three dates. Under the older model it won once, tied once
  and lost three times. The newer model also put far more CVEs above 0.1 (1,651–2,181 per date
  instead of 313–375), so fixed EPSS thresholds need recalibration when the model changes.

**Exploitation insights** (KEV additions from 2024-01-01 to 2026-10-01: 678 entries; 440 matched to
the 2021–2025 NVD feeds)

- 60.0% of the matched exploited CVEs were scored below CVSS 9.0, and 11.1% below 7.0.
- Median time from NVD publication to KEV listing was 22.5 days. 20.2% were listed on or before
  the publication date, 40.5% within 7 days, and 16.8% after more than a year.
- 102 of 678 entries (15.0%) are marked as used in ransomware campaigns.
- Most frequent vendors: Microsoft (114), Cisco (32), Apple (25), Google (24) and Ivanti (23). Most
  frequent weaknesses: CWE-78 OS command injection (45), CWE-502 deserialization (39) and CWE-22
  path traversal (34).

These results describe one data snapshot. NVD, KEV and EPSS change daily, so a later run will
produce different numbers. See [Limitations](#limitations).

## Problem

Security teams have more findings than remediation capacity. Severity alone does not indicate
which vulnerabilities will become known exploited. This toolkit compares CVSS and EPSS strategies
at historical decision dates, measures their coverage at different effort levels, and combines
exploitation evidence with asset context to prioritise current findings.

## Features

- Stream NVD CVE JSON 2.0 feeds, including gzip files, without loading an entire feed into memory.
- Ingest CISA KEV and historical FIRST EPSS snapshots into an atomically built SQLite database.
- Compare four strategies across complete, time-split outcome windows with pooled metrics.
- Produce an effort–coverage curve and a seeded, paired bootstrap confidence interval.
- Explore exploitation lags, CVSS bands, ransomware links, vendors and CWEs.
- Triage findings into P1–P4 tiers with ordered reason codes and asset-criticality escalation.
- Export deterministic JSON, Markdown, self-contained HTML with inline SVG charts, and triage CSV.

All operations run locally. The toolkit never downloads data or executes third-party code.

## How this project was built

The repository author designed and operates **AI Development Team**, a human-supervised workflow
that runs Claude Code and Codex CLI in an isolated WSL2 environment with a fixed budget (at most 2
review cycles, 7 model calls and 60 minutes per task). For this project:

1. **Planning (Claude Code, with the author).** The author set the goal of a CV project that combines
   data analytics with cybersecurity. Claude Code proposed the scope and wrote the binding
   specification ([`SPEC.md`](SPEC.md)), the provided skeleton and samples, and 61 hidden acceptance
   tests. Before the run, the tests were checked against a private reference implementation that
   was not given to the implementer.
2. **Implementation (Codex CLI).** Codex implemented the package, its 40 unit tests, the README and
   [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) from the specification. The requested model was
   `gpt-6.1-sol` with reasoning effort `xhigh`; the CLI does not report which model actually ran.
3. **Review (Claude Code).** The reviewer approved the result after **one review cycle**, using
   **3 of 7 model calls** in about **14 minutes**. **All 61 hidden acceptance tests and 40 unit
   tests passed**, and the reviewer recorded three low-severity findings (see
   [Known issues](#known-issues)).
4. **Real-data run (Claude Code, supervised by the author).** Downloading the data, verifying
   checksums, building the database, running the analysis and preparing this release were done
   afterwards, outside the automated run.

The code was generated by AI agents, not written by hand. The author's role was to set goals and
constraints, approve each step, launch the run and check the results. The commit history keeps this
visible: `98d44cb` (specification and skeleton, `aidev-architect`) and `281f9d1` (implementation,
`aidev-orchestrator`), followed by release documentation commits.

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

Raw data is **not** included in this repository. See [Data sources](docs/DATA_SOURCES.md) for the
official download locations, used fields, integrity checks and the recommended dataset (about
100 MB). Download the files separately into `data/` (ignored by Git), then run the toolkit offline:

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

For the published results, the build took about 4 minutes and produced a 206 MB database, and the
analysis took about 3 seconds (Windows 11 laptop, Python 3.13). The default 365-day horizon requires
a maximum KEV addition date of at least 2026-10-01 to include all eight snapshots. Automatic date
selection uses only complete windows. An explicitly requested date with an incomplete window is an
error.

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

The 40 repository tests use only the standard library, local samples, in-memory SQLite and
temporary directories. They require no network and do not write into the repository, so the
repository root can be read-only. Set `PYTHONDONTWRITEBYTECODE=1` to suppress Python's optional
import caches as well. The 61 hidden acceptance tests used to verify the AI-built implementation
are part of the private planning package and are not included in this repository.

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
- The published results cover one data snapshot and eight decision dates; 284 positives is a small
  sample, which is why the main EPSS-versus-CVSS difference is not statistically significant.
- Triage provides a transparent default policy. It needs local review alongside remediation cost,
  compensating controls and asset context. Synthetic samples are illustrative only.

## Known issues

Low-severity findings from the automated review, not yet fixed:

1. A truncated or corrupted `.gz` input stops `build` with a Python traceback instead of a clean
   `error:` message (exit code 1). Because the build is atomic, no partial database is left behind.
2. The NVD streaming parser copies part of its buffer after every record. It is still fast enough
   for real feeds (about 75 MB/s in a local benchmark; the full real build took about 4 minutes).
3. If a record in the middle of an NVD feed is invalid JSON, the parser reads to the end of the file
   before reporting the error, so memory use is not bounded in that error case.

## Data sources and attribution

- **NVD** (NIST National Vulnerability Database) CVE JSON 2.0 feeds. This product uses data from
  the NVD but is not endorsed or certified by the NVD.
- **CISA Known Exploited Vulnerabilities** catalogue.
- **FIRST EPSS** (Exploit Prediction Scoring System) daily scores.

The repository contains only synthetic samples and aggregate results, not the raw datasets.
Review each provider's terms of use before redistributing their data.

## Project structure

```
vulnprio/          package: ingest, storage, backtest, insights, triage, report, cli
tests/             40 unit tests (standard library only)
samples/           synthetic sample inputs in the real file formats
docs/              DATA_SOURCES.md and METHODOLOGY.md
results/           published results of the real-data run (JSON, Markdown, HTML)
SPEC.md            binding specification used by the AI Development Team
```

## License

No license has been chosen yet. Until one is added, default copyright applies and reuse requires
the author's permission.
