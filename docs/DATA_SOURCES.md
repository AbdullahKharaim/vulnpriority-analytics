# Data sources

`vulnpriority-analytics` never downloads anything itself. You download three public datasets once,
then every command runs offline. Locations below were checked in October 2026; review each
provider's terms of use before redistributing their data.

## 1. NVD CVE JSON 2.0 yearly feeds (NIST)

- Page: <https://nvd.nist.gov/vuln/data-feeds>
- Files: `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-YYYY.json.gz`
- Each yearly file holds the CVEs whose **id** carries that year (`CVE-2025-*` in the 2025 file),
  with publication date, status (`vulnStatus`), CVSS metrics and CWE weaknesses. Sizes vary; the 2025
  file was about 25 MB compressed and 291 MB uncompressed in October 2026, which is why the parser
  streams it instead of loading it whole.
- Integrity: each feed has a `.meta` file (`nvdcve-2.0-YYYY.meta`) with the SHA-256 of the
  uncompressed JSON.
- Used fields: `cve.id`, `cve.published`, `cve.vulnStatus`, `cve.metrics.cvssMetricV31` /
  `cvssMetricV30` (`type`, `cvssData.baseScore`), `cve.weaknesses[].description[].value`.

## 2. CISA Known Exploited Vulnerabilities (KEV)

- Page: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- File: `https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv`
- Columns (October 2026): `cveID, vendorProject, product, vulnerabilityName, dateAdded,
  shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, forensicTriage, notes,
  cwes`. Columns have been added over time, so the parser reads them **by name**.
- `dateAdded` (ISO date) is the ground-truth "exploitation became known" date used by the backtest.

## 3. FIRST EPSS daily scores

- Daily files: `https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz` (about 1.5 MB
  each); one file per day, so you can recover the scores exactly as they were on a past date.
- Format: an optional first comment line such as
  `#model_version:v2025.03.14,score_date:2025-04-01T00:00:00+0000`, then `cve,epss,percentile`.
  `epss` is the estimated probability of exploitation activity in the next 30 days.
- API (single CVEs, historical dates): `https://api.first.org/data/v1/epss?cve=CVE-2021-44228&date=2025-01-01`

## Recommended real-data set

| Item | Files |
|---|---|
| NVD | `nvdcve-2.0-2021.json.gz` … `nvdcve-2.0-2025.json.gz` (five files) |
| KEV | the current `known_exploited_vulnerabilities.csv` |
| EPSS | the eight quarterly snapshots 2024-01-01, 2024-04-01, 2024-07-01, 2024-10-01, 2025-01-01, 2025-04-01, 2025-07-01, 2025-10-01 |

With the default lookback (730 days) and horizon (365 days), all eight decision dates have a
complete outcome window as long as the KEV file is dated 2026-10-01 or later.

```bash
mkdir -p data && cd data
for y in 2021 2022 2023 2024 2025; do
  curl -fLO "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$y.json.gz"
done
curl -fLO "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
for d in 2024-01-01 2024-04-01 2024-07-01 2024-10-01 2025-01-01 2025-04-01 2025-07-01 2025-10-01; do
  curl -fLO "https://epss.empiricalsecurity.com/epss_scores-$d.csv.gz"
done
```

Total download: roughly 100 MB.
