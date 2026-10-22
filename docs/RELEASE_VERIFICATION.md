# v1.0.0 release verification

Verification date: 2026-10-22. Runtime: Windows, Python 3.13.12, standard library only.

## Code and tests

- The complete implementation is present on the publication branch, including all ten package
  modules, seven unit-test modules, synthetic inputs and the specification.
- `python -m unittest discover -s tests -t .` passed all 40 tests during this preparation.
- No implementation changes were required. The original implementation commit
  `281f9d1e5d52e545fd94be03ca45c71f5a2c06d5` and specification commit
  `98d44cbe62a536fcae3007e0f3836908635ec41c` remain ancestors of the release.
- The earlier 61/61 hidden acceptance-test result, one review cycle, three model calls and
  approximately 14-minute run are reported by the prior release-preparation account. Original
  orchestration/reviewer logs are not available in this checkout. Hidden tests and planning
  material remain private and were not rerun or included in the publication.

## Published analysis

The existing local SQLite database passed `PRAGMA quick_check`. It was opened in read-only mode
to recompute the default backtest, insights and all three report formats. The JSON object was
identical to `results/report.json`; JSON, Markdown and HTML text all matched the committed reports
after normalizing Windows CRLF to LF. The database was not rebuilt for this check.

Confirmed values include 167,132 NVD CVEs, 1,748 KEV entries, eight EPSS snapshots,
522,907 CVE-decision instances and 284 positive instances. The matched-effort coverage difference
was 0.066901, with a 95% paired-bootstrap interval of [-0.003521, 0.140845]; it is not statistically
significant under the documented resampling scheme.

`kev_as_of` is the maximum loaded KEV addition date (2026-10-16), used as a coverage proxy by the
implementation. It is not a recorded download timestamp or proof of catalogue completeness.

## Input integrity and reproduction

[`results/inputs.sha256`](../results/inputs.sha256) records SHA-256 digests of the 14 compressed
or CSV public input files currently held locally: five NVD feeds, eight EPSS snapshots and KEV.
The decompressed NVD feeds also matched the SHA-256 values in their corresponding local `.meta`
files. These checks establish consistency with the locally retained inputs and metadata; they
are not a fresh verification against remote provider files.

Follow the README commands to reproduce the pipeline with separately downloaded data. To check
an exact input set on Linux/macOS/WSL, run `sha256sum -c ../results/inputs.sha256` from `data/`.
On PowerShell, run `Get-FileHash -Algorithm SHA256 data/*` and compare each listed input with the
manifest. Mutable provider files may no longer match these hashes. The raw snapshot and database
are intentionally excluded, so fresh downloads may reproduce the procedure with different results.

## Publication scope and privacy

The candidate history was inspected for excluded paths, email addresses, private-key headers,
common credential/token patterns and local machine paths. No personal email or known secret
pattern was found in the commits, messages, tracked content or annotated tag selected for release.
This is a focused local inspection, not a guarantee that arbitrary secrets can be detected.

The human commit/tag identity uses the noreply address verified in GitHub account settings.
The original agent identities use `localhost.invalid`. Public provider/example addresses and
the existing AI coauthor attribution remain in the history.

Only `main` and the final `v1.0.0` tag are intended for the initial push. Raw data, SQLite files
and sidecars, private planning, hidden acceptance tests, personal CV material, credentials and
temporary files are excluded. Local backup/reflog objects are not publication refs.

This document records local preparation. Public repository creation, push and any GitHub Release
remain subject to the owner's explicit approval.
