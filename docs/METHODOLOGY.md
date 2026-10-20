# Methodology

## Time-split design

Each decision date D is an available historical EPSS snapshot date. Let H be the outcome horizon
(default 365 days) and L the publication lookback (default 730 days). The maximum KEV `date_added`
is the data coverage cutoff. A decision date is usable only when `D + H <= cutoff`.
Automatic selection includes every complete snapshot date in ascending order; explicit dates are
deduplicated, sorted and validated. No usable snapshots or an empty KEV table is an error.

Inputs are frozen local files. There is no current EPSS lookup during analysis: a decision uses
only its own snapshot. KEV additions on or before D are removed from the decision population;
later additions are used as outcomes. This prevents future exploitation evidence from entering
strategy selection. Historical CVSS availability is a limitation described below.

## Population and diagnostics

Filters apply in this order:

1. Keep non-rejected CVEs with `D - L <= published < D`. Publication on the lower boundary is
   included; publication on the decision date is excluded. Rejected and out-of-window records
   contribute to no diagnostics.
2. Remove missing CVSS scores and increment `excluded_no_cvss`. Those with KEV additions in
   `(D, D + H]` also increment `positives_without_cvss`.
3. Remove records absent from the EPSS snapshot and increment `excluded_no_epss`.
4. Remove CVEs with KEV addition dates `<= D` and increment `excluded_known_exploited`.

The remaining population size is N. A positive has `D < date_added <= D + H`; P is its count.
A KEV addition on D is already known exploited; an addition exactly at D + H is positive.
The filter order matters: a record missing both scores is counted only under missing CVSS.
Zero is a valid score and is never treated as missing.

## Strategies and selection order

| Strategy | Selection |
| --- | --- |
| `CVSS_CRITICAL` | CVSS ≥ 9.0 |
| `CVSS_HIGH_PLUS` | CVSS ≥ 7.0 |
| `EPSS_EFFORT_MATCHED` | Top K by descending EPSS, then ascending CVE ID; K equals the number selected by `CVSS_CRITICAL` |
| `EPSS_THRESHOLD` | EPSS ≥ configured threshold (default 0.1) |

The effort-matched strategy compares ranking performance at exactly the same number of flagged
CVEs as the critical-CVSS policy, including K = 0. Strategies and their reported metrics always
appear in the order above.

## Metrics and pooling

For F flagged CVEs and TP flagged positives:

| Metric | Formula | Undefined case |
| --- | --- | --- |
| Effort | F / N | 0.0 when N = 0 |
| Coverage (recall) | TP / P | null when P = 0 |
| Efficiency (precision) | TP / F | null when F = 0 |
| Lift | (TP / F) / (P / N) | null when F = 0 or P = 0 |
| Base rate | P / N | null when N = 0 |

Pooled metrics first sum F, TP, N and P over decision dates, then apply these formulas. They are
not averages of per-date ratios. A vulnerability appearing at several dates contributes one
instance per date. Counts remain integers. Each ratio placed in a result dictionary is rounded
once with Python `round(value, 6)`, using exact counts as the inputs; intermediate ratios are
not rounded. Markdown and HTML display percentages with two decimals and lift with two decimals.

## Effort–coverage curve

Budgets are 1%, 2%, 5%, 10%, 20%, 30%, 50% and 100%. Independently for each decision date,
rank CVEs by `(-epss, cve_id)` and by `(-cvss_score, cve_id)`. CVSS ties do not use EPSS.
At each integer percentage pct, take:

```text
k = (pct * N + 99) // 100
coverage = sum(positives among the top k at each date) / sum(P at each date)
```

The integer formula implements the ceiling without floating-point boundary errors. Values are
null when the total number of positives is zero; otherwise they are rounded to six decimals.

## Paired bootstrap confidence interval

The comparison is the coverage difference `EPSS_EFFORT_MATCHED - CVSS_CRITICAL`. Build the list
of all positive `(decision_date, cve_id)` instances, sorted by date then identifier. Each holds
two paired indicators: a for selection by EPSS and b for selection by critical CVSS. The point
estimate is `(sum(a) - sum(b)) / n`, where n is the number of positive instances.

With `random.Random(seed)` (default seed 42), generate B bootstrap samples (default 1,000).
Each sample draws n indices with replacement using `int(rng.random() * n)` in sequence and
computes `(sum(a over draws) - sum(b over draws)) / n`. Preserve the pair on every draw.
Sort the B differences. For confidence c (default 0.95), use:

```text
lo = floor(B * (1 - c) / 2 + 1e-9)
hi = B - 1 - lo
CI = [sorted_differences[lo], sorted_differences[hi]]
```

The interval excludes zero when its unrounded lower bound is greater than zero or its unrounded
upper bound is less than zero; this determines `significant`. Point and interval bounds are
then rounded to six decimals. With no positives, bootstrap is null. This interval describes the
specified paired resampling scheme, not all sources of observational uncertainty.

## Exploitation insights

The analysis insight window runs inclusively from the earliest decision date to the latest
decision date plus H. All KEV entries in the window contribute to vendor, CWE and ransomware
statistics. Only entries with a matching NVD CVE contribute to publication-to-KEV lags and CVSS
bands; the two below-severity shares further require a non-null score.

Lags may be negative. Inclusive lag buckets are `<=0`, `1-7`, `8-30`, `31-90`, `91-365`, and
`>365`. Median and mean use all matched lags and round to one decimal. CVSS bands are critical,
high, medium, low, none and unscored. Lag and band shares use the NVD-matched count; ransomware
share uses all window KEV entries. Empty denominators produce null. Top vendors sort by
descending count then vendor; top CWEs sort by descending count then numeric CWE identifier.

## Operational triage

Triage selects the latest EPSS snapshot at or before an optional reference date, ignoring KEV
entries added later. Without a reference date, it uses the latest snapshot and all KEV data.
KEV makes a finding P1; high EPSS or critical severity on an internet-facing asset makes P2;
high severity or medium EPSS makes P3; remaining findings are P4. High-criticality assets move
P3 to P2 and P4 to P3. All applicable reason codes are recorded in the defined order.
Sorting uses raw scores before output rounding. These tiers are a transparent remediation policy,
distinct from the measured historical strategy comparison.

## Threats to validity

- **CVSS scores are as of download.** NVD feeds can include later revisions or newly assigned
  scores. The design prevents EPSS and KEV selection leakage but cannot reconstruct historical
  CVSS from a current yearly feed.
- **KEV is an incomplete, US-government-centred ground truth.** Addition dates record when
  exploitation became catalogued, rather than when it began. Unlisted CVEs can still be exploited,
  and catalogue inclusion is influenced by visibility and institutional priorities.
- **Population is limited to the lookback window.** Older vulnerabilities and records missing
  scores are excluded. Their risk and remediation burden are not represented by the primary
  metrics; exclusion diagnostics expose part of this selection effect.
- **CVSS tie-breaks are arbitrary but deterministic.** Equal-severity CVEs are ordered by CVE
  identifier, so cutoffs can move coverage without an underlying risk distinction.

EPSS's native probability horizon is 30 days; changing H measures utility of its ranking for a
different outcome window, not calibration at that horizon. Repeated CVEs and overlapping outcome
windows create dependence across instances that the specified bootstrap does not fully model.
Synthetic sample results demonstrate the pipeline only and are illustrative, not empirical evidence.
