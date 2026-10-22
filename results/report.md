# Vulnerability Prioritization Report

## Data

| Measure | Value |
| --- | --- |
| cves | 167132 |
| cves_rejected | 5348 |
| cves_without_cvss | 3388 |
| nvd_files | 5 |
| nvd_items_skipped | 0 |
| nvd_duplicates | 0 |
| kev_entries | 1748 |
| kev_rows_skipped | 0 |
| kev_as_of | 2026-10-16 |

| EPSS snapshot | Model version | Rows | Rows skipped |
| --- | --- | --- | --- |
| 2024-01-01 | v2023.03.01 | 220901 | 0 |
| 2024-04-01 | v2023.03.01 | 240713 | 0 |
| 2024-07-01 | v2023.03.01 | 252054 | 0 |
| 2024-10-01 | v2023.03.01 | 260671 | 0 |
| 2025-01-01 | v2023.03.01 | 271765 | 0 |
| 2025-04-01 | v2025.03.14 | 272867 | 0 |
| 2025-07-01 | v2025.03.14 | 284454 | 0 |
| 2025-10-01 | v2025.03.14 | 296333 | 0 |

Lookback: 730 days; outcome horizon: 365 days; EPSS threshold: 10.00%.

## Pooled results

Population instances: 522907; positives: 284; base rate: 0.05%.

| Strategy | Flagged | Effort | Coverage | Efficiency | Lift |
| --- | --- | --- | --- | --- | --- |
| CVSS_CRITICAL | 73201 | 14.00% | 42.61% | 0.17% | 3.04x |
| CVSS_HIGH_PLUS | 268085 | 51.27% | 90.85% | 0.10% | 1.77x |
| EPSS_EFFORT_MATCHED | 73201 | 14.00% | 49.30% | 0.19% | 3.52x |
| EPSS_THRESHOLD | 7198 | 1.38% | 20.77% | 0.82% | 15.09x |

## Statistical comparison

EPSS_EFFORT_MATCHED versus CVSS_CRITICAL: coverage difference 6.69%; 95.00% confidence interval [-0.35%, 14.08%]. Paired bootstrap with 284 positive instances and 1000 iterations (seed 42); significant: no.

## Per decision date

| Decision date | Window end | N | P | Base rate | No CVSS | No EPSS | Known exploited | Positives without CVSS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2024-01-01 | 2024-12-31 | 51806 | 26 | 0.05% | 13 | 2 | 245 | 0 |
| 2024-04-01 | 2025-04-01 | 54458 | 24 | 0.04% | 15 | 15 | 237 | 0 |
| 2024-07-01 | 2025-07-01 | 59600 | 35 | 0.06% | 40 | 511 | 240 | 0 |
| 2024-10-01 | 2025-10-01 | 61850 | 43 | 0.07% | 119 | 497 | 252 | 0 |
| 2025-01-01 | 2026-01-01 | 66365 | 39 | 0.06% | 317 | 496 | 272 | 0 |
| 2025-04-01 | 2026-04-01 | 71939 | 34 | 0.05% | 573 | 1 | 304 | 0 |
| 2025-07-01 | 2026-07-01 | 76299 | 39 | 0.05% | 959 | 4 | 320 | 0 |
| 2025-10-01 | 2026-10-01 | 80590 | 44 | 0.05% | 1505 | 2 | 307 | 0 |

### 2024-01-01

EPSS model: v2023.03.01.

| Strategy | Flagged | Effort | Coverage | Efficiency | Lift |
| --- | --- | --- | --- | --- | --- |
| CVSS_CRITICAL | 8270 | 15.96% | 46.15% | 0.15% | 2.89x |
| CVSS_HIGH_PLUS | 28644 | 55.29% | 84.62% | 0.08% | 1.53x |
| EPSS_EFFORT_MATCHED | 8270 | 15.96% | 69.23% | 0.22% | 4.34x |
| EPSS_THRESHOLD | 375 | 0.72% | 23.08% | 1.60% | 31.88x |

### 2024-04-01

EPSS model: v2023.03.01.

| Strategy | Flagged | Effort | Coverage | Efficiency | Lift |
| --- | --- | --- | --- | --- | --- |
| CVSS_CRITICAL | 8578 | 15.75% | 54.17% | 0.15% | 3.44x |
| CVSS_HIGH_PLUS | 29635 | 54.42% | 100.00% | 0.08% | 1.84x |
| EPSS_EFFORT_MATCHED | 8578 | 15.75% | 50.00% | 0.14% | 3.17x |
| EPSS_THRESHOLD | 348 | 0.64% | 20.83% | 1.44% | 32.60x |

### 2024-07-01

EPSS model: v2023.03.01.

| Strategy | Flagged | Effort | Coverage | Efficiency | Lift |
| --- | --- | --- | --- | --- | --- |
| CVSS_CRITICAL | 8616 | 14.46% | 45.71% | 0.19% | 3.16x |
| CVSS_HIGH_PLUS | 31223 | 52.39% | 97.14% | 0.11% | 1.85x |
| EPSS_EFFORT_MATCHED | 8616 | 14.46% | 45.71% | 0.19% | 3.16x |
| EPSS_THRESHOLD | 316 | 0.53% | 11.43% | 1.27% | 21.56x |

### 2024-10-01

EPSS model: v2023.03.01.

| Strategy | Flagged | Effort | Coverage | Efficiency | Lift |
| --- | --- | --- | --- | --- | --- |
| CVSS_CRITICAL | 8641 | 13.97% | 44.19% | 0.22% | 3.16x |
| CVSS_HIGH_PLUS | 31791 | 51.40% | 93.02% | 0.13% | 1.81x |
| EPSS_EFFORT_MATCHED | 8641 | 13.97% | 41.86% | 0.21% | 3.00x |
| EPSS_THRESHOLD | 314 | 0.51% | 9.30% | 1.27% | 18.32x |

### 2025-01-01

EPSS model: v2023.03.01.

| Strategy | Flagged | Effort | Coverage | Efficiency | Lift |
| --- | --- | --- | --- | --- | --- |
| CVSS_CRITICAL | 8965 | 13.51% | 38.46% | 0.17% | 2.85x |
| CVSS_HIGH_PLUS | 33561 | 50.57% | 87.18% | 0.10% | 1.72x |
| EPSS_EFFORT_MATCHED | 8965 | 13.51% | 33.33% | 0.14% | 2.47x |
| EPSS_THRESHOLD | 313 | 0.47% | 7.69% | 0.96% | 16.31x |

### 2025-04-01

EPSS model: v2025.03.14.

| Strategy | Flagged | Effort | Coverage | Efficiency | Lift |
| --- | --- | --- | --- | --- | --- |
| CVSS_CRITICAL | 9305 | 12.93% | 41.18% | 0.15% | 3.18x |
| CVSS_HIGH_PLUS | 35678 | 49.59% | 85.29% | 0.08% | 1.72x |
| EPSS_EFFORT_MATCHED | 9305 | 12.93% | 52.94% | 0.19% | 4.09x |
| EPSS_THRESHOLD | 2181 | 3.03% | 32.35% | 0.50% | 10.67x |

### 2025-07-01

EPSS model: v2025.03.14.

| Strategy | Flagged | Effort | Coverage | Efficiency | Lift |
| --- | --- | --- | --- | --- | --- |
| CVSS_CRITICAL | 10157 | 13.31% | 30.77% | 0.12% | 2.31x |
| CVSS_HIGH_PLUS | 37829 | 49.58% | 89.74% | 0.09% | 1.81x |
| EPSS_EFFORT_MATCHED | 10157 | 13.31% | 53.85% | 0.21% | 4.04x |
| EPSS_THRESHOLD | 1700 | 2.23% | 35.90% | 0.82% | 16.11x |

### 2025-10-01

EPSS model: v2025.03.14.

| Strategy | Flagged | Effort | Coverage | Efficiency | Lift |
| --- | --- | --- | --- | --- | --- |
| CVSS_CRITICAL | 10669 | 13.24% | 45.45% | 0.19% | 3.43x |
| CVSS_HIGH_PLUS | 39724 | 49.29% | 90.91% | 0.10% | 1.84x |
| EPSS_EFFORT_MATCHED | 10669 | 13.24% | 54.55% | 0.22% | 4.12x |
| EPSS_THRESHOLD | 1651 | 2.05% | 27.27% | 0.73% | 13.31x |

## Effort curve

Coverage at each effort level, pooling positive counts across decision dates.

| Effort | EPSS coverage | CVSS coverage |
| --- | --- | --- |
| 1% | 19.37% | 5.28% |
| 2% | 23.94% | 6.69% |
| 5% | 34.15% | 8.45% |
| 10% | 44.37% | 23.24% |
| 20% | 55.28% | 48.94% |
| 30% | 64.08% | 62.68% |
| 50% | 75.35% | 88.38% |
| 100% | 100.00% | 100.00% |

## Exploitation insights

KEV window: 2024-01-01 through 2026-10-01 (inclusive). Entries: 678; linked to NVD: 440; ransomware-linked: 102 (15.04%).

Publication-to-KEV lag: median 22.5 days, mean 207.0 days. Among scored entries, below critical: 60.00%; below high: 11.14%.

### Lag buckets

| Lag (days) | Count | Share |
| --- | --- | --- |
| <=0 | 89 | 20.23% |
| 1-7 | 89 | 20.23% |
| 8-30 | 50 | 11.36% |
| 31-90 | 53 | 12.05% |
| 91-365 | 85 | 19.32% |
| >365 | 74 | 16.82% |

### CVSS bands

| Band | Count | Share |
| --- | --- | --- |
| critical | 176 | 40.00% |
| high | 215 | 48.86% |
| medium | 48 | 10.91% |
| low | 1 | 0.23% |
| none | 0 | 0.00% |
| unscored | 0 | 0.00% |

### Top vendors

| Vendor | Count | Ransomware |
| --- | --- | --- |
| Microsoft | 114 | 21 |
| Cisco | 32 | 3 |
| Apple | 25 | 0 |
| Google | 24 | 0 |
| Ivanti | 23 | 7 |
| Fortinet | 20 | 5 |
| Linux | 19 | 2 |
| Adobe | 17 | 2 |
| Oracle | 13 | 3 |
| Citrix | 12 | 1 |

### Top CWEs

| CWE | Count |
| --- | --- |
| CWE-78 | 45 |
| CWE-502 | 39 |
| CWE-22 | 34 |
| CWE-287 | 31 |
| CWE-94 | 30 |
| CWE-416 | 28 |
| CWE-787 | 27 |
| CWE-306 | 23 |
| CWE-77 | 18 |
| CWE-89 | 17 |

## Limitations

- CVSS scores reflect the download date and may include later revisions.
- KEV is an incomplete, US-government-centred record of known exploitation; addition dates are not first exploitation dates.
- The population is limited to the lookback window and CVEs with both CVSS and EPSS data.
- CVSS ranking ties use an arbitrary but deterministic CVE identifier order.
