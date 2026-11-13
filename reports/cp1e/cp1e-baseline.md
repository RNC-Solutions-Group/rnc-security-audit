# Scanner Harness Report

> Overall: **COMPLETE_WITH_LIMITATIONS**

> Matrix status: **PASS**

> Scanner: **gitleaks**

| Field | Value |
| --- | --- |
| Harness version | 0.4.0 |
| Run ID | `20261110T220409Z` |
| Generated (UTC) | 2026-11-10T22:07:37Z |
| Source repository | https://github.com/RNC-Solutions-Group/gitleaks |
| Source branch | master |
| Resolved commit | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |
| Scanner version | v8.0.0-rnc.5f6ec56cfa6f |
| Suites | gitleaks, git-history, levain, leaky-repo |

## Builds

| Platform | Kind | Build | Version | Artifact |
| --- | --- | --- | --- | --- |
| windows-amd64 | executable | PASS | v8.0.0-rnc.5f6ec56cfa6f | `e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2` |
| docker-linux-amd64 | docker | PASS | v8.0.0-rnc.5f6ec56cfa6f | `sha256:abefc3b269cb0bb4dd5f5af527fe2d32e5594e250846519ff06cef8f3682912b` |
| docker-linux-arm64 | docker | PASS | v8.0.0-rnc.5f6ec56cfa6f | `sha256:1583aa5d2ac492eba034e68501a413b9f562027fedb30a818283981c8bc542ac` |

## Datasets

| Dataset | Revision | Checksum |
| --- | --- | --- |
| gitleaks-fixtures | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` | `cd7f05e76b4590ee738d4573f3ddb3c493142ecd1204bc15754a21d0e66f7345` |
| levain | `c130c321aa9046af17a6c876cb97e2ed71397110` | `c811af9168650d2c3672873f80c019803329e30747daa2bcb6e4b9206d8e2098` |
| leaky-repo | `2e951359cac53addbee56437da3ffb546e3dfe24` | `146df5e25fa987a0b5c5610a958941e5416a29c9f72eadaa3677abc620b281ce` |

## Suites

| Suite | Status | Applicable | Metrics |
| --- | --- | --- | --- |
| gitleaks | PASS | True | scenario total=69; scenario passed=68; assertion total=435; assertion passed=435 |
| git-history | PASS | True | - |
| levain | PASS | True | true positives=47; expected secrets=85; false positives=3; duplicates=2 |
| leaky-repo | PASS | True | expected count=175; covered count=22; count coverage percent=12.57; files covered=13; files covered percent=29.55; excess findings=0 |

## Suite details

### gitleaks

- windows-amd64: **PASS**
- docker-linux-amd64: **PASS**
- docker-linux-arm64: **PASS**
- scenario total: 69
- scenario passed: 68
- assertion total: 435
- assertion passed: 435
- Limitation: One Linux-only symlink scenario is NOT_APPLICABLE on Windows native execution.
- Limitation: The legacy fixture lane retains hashed reports rather than raw scanner report bytes.

### git-history

- windows-amd64: **PASS**
- docker-linux-amd64: **PASS**
- docker-linux-arm64: **PASS**

### levain

- windows-amd64: **PASS**
- docker-linux-amd64: **PASS**
- docker-linux-arm64: **PASS**
- true positives: 47
- expected secrets: 85
- false positives: 3
- duplicates: 2
- Limitation: Levain is a synthetic corpus; counts are not real-world prevalence.

### leaky-repo

- windows-amd64: **PASS**
- docker-linux-amd64: **PASS**
- docker-linux-arm64: **PASS**
- expected count: 175
- covered count: 22
- count coverage percent: 12.57
- files covered: 13
- files covered percent: 29.55
- excess findings: 0
- unlisted findings: 0
- rich score status: COMPLETED
- rich matched count: 22
- rich missed count: 153
- rich unexpected count: 0
- rich duplicate count: 0
- rich detection recall percent: 12.57
- rich category conflict items: 31
- value verified count: 20
- line only count: 2
- Limitation: Legacy Leaky Repo score preserves the upstream line-count methodology.
- Limitation: RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Limitation: Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Limitation: Leaky Repo Git-history observations are not scored: no independently verified historical truth manifest exists, so history truth is BLOCKED and the filesystem 175-item denominator is not applied.

## Leaky Repo dual scores

| Methodology | Expected | Covered / matched | Files / misses | Exceptions |
| --- | ---: | ---: | ---: | ---: |
| Legacy upstream count | 175 | 22 (12.57%) | 13/44 files | excess=0, unlisted=0 |
| RNC line-level rich | 175 | 22 (12.57%) | missed=153 | duplicates=0, unexpected=0, category_conflicts=31 |

The rich score is detection-only: no precision, F1, or verified false-positive claim is made without a negative oracle.
Identity confidence: 20 value-verified matches, 2 line-only matches (source lines without reliable value fingerprints).

## Git history

| Metric | Value |
| --- | ---: |
| History status | COMPLETE |
| Unique expected secrets | 3 |
| Unique matched secrets | 3 |
| Unique recall | 100.0% |
| Expected occurrences | 5 |
| Matched occurrences | 5 |
| Missed occurrences | 0 |

## Leaky Repo history observation

**History truth: BLOCKED.** Execution: PASS; commits scanned: 25; observed findings: 26.

No historical recall or precision is claimed: Leaky Repo has no independently verified per-commit truth manifest, and the filesystem 175-item denominator is deliberately not applied.

## Exceptions

| Suite | Classification | Expected ID | Path | Line | Reason |
| --- | --- | --- | --- | --- | --- |
| levain | UNEXPECTED_FINDING | - | tailscale and wireguard status | 4 | negative corpus finding rule generic-api-key |
| levain | UNEXPECTED_FINDING | - | tailscale and wireguard status | 5 | negative corpus finding rule generic-api-key |
| levain | UNEXPECTED_FINDING | - | tailscale and wireguard status | 8 | negative corpus finding rule generic-api-key |
| levain | MISSED_EXPECTATION | - | env-file | - | credential kind aws_access_key_id not detected |
| levain | MISSED_EXPECTATION | - | curl-verbose-basic-auth | - | credential kind http_basic_auth not detected |
| levain | MISSED_EXPECTATION | - | hardhat-deploy-failure | - | credential kind wallet_seed_phrase not detected |
| levain | MISSED_EXPECTATION | - | wallet-restore-env | - | credential kind wallet_seed_phrase not detected |
| levain | MISSED_EXPECTATION | - | axios-error-dump | - | credential kind bearer_token not detected |
| levain | MISSED_EXPECTATION | - | postgres-connection-failure | - | credential kind url_password not detected |
| levain | MISSED_EXPECTATION | - | mongodb-uri | - | credential kind url_password not detected |
| levain | MISSED_EXPECTATION | - | cloudsql-iam-dsn | - | credential kind url_password not detected |
| levain | MISSED_EXPECTATION | - | cloudsql-iam-dsn | - | credential kind email not detected |
| levain | MISSED_EXPECTATION | - | payment-processing-log | - | credential kind payment_card not detected |
| levain | MISSED_EXPECTATION | - | payment-processing-log | - | credential kind payment_card not detected |
| levain | MISSED_EXPECTATION | - | terraform-apply-output | - | credential kind aws_access_key_id not detected |
| levain | MISSED_EXPECTATION | - | pip-index-url-with-password | - | credential kind url_password not detected |
| levain | MISSED_EXPECTATION | - | ai-gateway-upstream-errors | - | credential kind xai_api_key not detected |
| levain | MISSED_EXPECTATION | - | platform-cli-auth-failures | - | credential kind doppler_token not detected |
| levain | MISSED_EXPECTATION | - | platform-cli-auth-failures | - | credential kind supabase_access_token not detected |
| levain | MISSED_EXPECTATION | - | platform-cli-auth-failures | - | credential kind netlify_pat not detected |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.bash_profile:11:informative | .bash_profile | 11 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.bash_profile:13:informative | .bash_profile | 13 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.bash_profile:18:informative | .bash_profile | 18 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.bash_profile:19:informative | .bash_profile | 19 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.bash_profile:20:risk | .bash_profile | 20 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.bash_profile:21:risk | .bash_profile | 21 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.bash_profile:24:risk | .bash_profile | 24 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.bash_profile:25:informative | .bash_profile | 25 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.bashrc:104:informative | .bashrc | 104 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.bashrc:105:risk | .bashrc | 105 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.bashrc:107:informative | .bashrc | 107 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.bashrc:108:informative | .bashrc | 108 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.docker/.dockercfg:3:informative | .docker/.dockercfg | 3 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.docker/.dockercfg:7:informative | .docker/.dockercfg | 7 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.docker/config.json:4:informative | .docker/config.json | 4 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.docker/config.json:8:informative | .docker/config.json | 8 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.esmtprc:2:informative | .esmtprc | 2 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.esmtprc:3:informative | .esmtprc | 3 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.esmtprc:4:risk | .esmtprc | 4 | no observed finding matched this expected item |
| leaky-repo | MISSED_EXPECTATION | leaky-repo:.ftpconfig:3:informative | .ftpconfig | 3 | no observed finding matched this expected item |

## Cross-platform comparisons

| Suite | Comparison | Result | Details |
| --- | --- | --- | --- |
| gitleaks | windows-amd64_vs_docker-linux-amd64 | PASS |  |
| gitleaks | windows-amd64_vs_docker-linux-arm64 | PASS |  |
| gitleaks | docker-linux-amd64_vs_docker-linux-arm64 | PASS |  |
| git-history | windows-amd64_vs_docker-linux-amd64 | PASS | 0 finding-classification differences |
| git-history | windows-amd64_vs_docker-linux-arm64 | PASS | 0 finding-classification differences |
| git-history | docker-linux-amd64_vs_docker-linux-arm64 | PASS | 0 finding-classification differences |
| levain | windows-amd64_vs_docker-linux-amd64 | PASS |  |
| levain | windows-amd64_vs_docker-linux-arm64 | PASS |  |
| levain | docker-linux-amd64_vs_docker-linux-arm64 | PASS |  |
| leaky-repo | windows-amd64_vs_docker-linux-amd64 | PASS | 0 legacy metric differences; 0 per-file differences; 0 rich finding differences |
| leaky-repo | windows-amd64_vs_docker-linux-arm64 | PASS | 0 legacy metric differences; 0 per-file differences; 0 rich finding differences |
| leaky-repo | docker-linux-amd64_vs_docker-linux-arm64 | PASS | 0 legacy metric differences; 0 per-file differences; 0 rich finding differences |


## Baseline comparison

- Status: **PASS**
- gitleaks: METRIC_ONLY — baseline has no normalized scoring evaluations for this suite
- git-history: NOT_COMPARABLE — suite is absent from the baseline
- levain: METRIC_ONLY — baseline has no normalized scoring evaluations for this suite
- leaky-repo: PASS — 153 existing gaps, 0 new misses, 0 recovered, 0 new unexpected, 0 resolved unexpected

## Reports

- Sanitized: reports\cp1e\cp1e-baseline.json, reports\cp1e\cp1e-baseline.md
- Raw: not generated

## Limitations

- A successfully built artifact is not counted as tested unless an applicable suite executed it.
- Raw reports are opt-in and never printed in ordinary console summaries.
- Leaky Repo count coverage is 12.57% (13/44 files); this is a count benchmark, not a completeness claim.
- One Linux-only symlink scenario is NOT_APPLICABLE on Windows native execution.
- The legacy fixture lane retains hashed reports rather than raw scanner report bytes.
- Levain is a synthetic corpus; counts are not real-world prevalence.
- Legacy Leaky Repo score preserves the upstream line-count methodology.
- RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Leaky Repo Git-history observations are not scored: no independently verified historical truth manifest exists, so history truth is BLOCKED and the filesystem 175-item denominator is not applied.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
A built artifact is not counted as tested unless an applicable suite actually executed it.
