# Scanner Harness Report

> Overall: **COMPLETE_WITH_LIMITATIONS**

> Matrix status: **PASS**

> Scanner: **gitleaks**

| Field | Value |
| --- | --- |
| Harness version | 0.3.0 |
| Run ID | `20261110T021821Z` |
| Generated (UTC) | 2026-11-10T02:19:36Z |
| Source repository | https://github.com/RNC-Solutions-Group/gitleaks |
| Source branch | master |
| Resolved commit | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |
| Scanner version | v8.0.0-rnc.5f6ec56cfa6f |
| Suites | gitleaks, go, levain, leaky-repo |

## Builds

| Platform | Kind | Build | Version | Artifact |
| --- | --- | --- | --- | --- |
| windows-amd64 | executable | PASS | v8.0.0-rnc.5f6ec56cfa6f | `e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2` |
| docker-linux-amd64 | docker | PASS | v8.0.0-rnc.5f6ec56cfa6f | `sha256:ccff37adc38c9c7330a74225e3f4481cca4787cfaa84d730466f048cd6bcd9d7` |

## Datasets

| Dataset | Revision | Checksum |
| --- | --- | --- |
| gitleaks-fixtures | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` | `cd7f05e76b4590ee738d4573f3ddb3c493142ecd1204bc15754a21d0e66f7345` |
| levain | `c130c321aa9046af17a6c876cb97e2ed71397110` | `fc19ad4ef7ddbf20637b7a6c98aa9e9bc3325e3f864bac2810083eaf52093a47` |
| leaky-repo | `2e951359cac53addbee56437da3ffb546e3dfe24` | `146df5e25fa987a0b5c5610a958941e5416a29c9f72eadaa3677abc620b281ce` |

## Suites

| Suite | Status | Applicable | Metrics |
| --- | --- | --- | --- |
| gitleaks | PASS | True | scenario total=46; scenario passed=45; assertion total=288; assertion passed=288 |
| go | PASS | True | tests passed=270; tests failed=0; tests skipped=2 |
| levain | PASS | True | true positives=47; expected secrets=85; false positives=3; duplicates=2 |
| leaky-repo | PASS | True | expected count=175; covered count=22; count coverage percent=12.57; files covered=13; files covered percent=29.55; excess findings=0 |

## Suite details

### gitleaks

- windows-amd64: **PASS**
- docker-linux-amd64: **PASS**
- scenario total: 46
- scenario passed: 45
- assertion total: 288
- assertion passed: 288
- Limitation: One Linux-only symlink scenario is NOT_APPLICABLE on Windows native execution.
- Limitation: Docker coverage remains INCOMPLETE until every INTERNAL_GO contract is evidenced.
- Limitation: The legacy fixture lane retains hashed reports rather than raw scanner report bytes.

### go

- source: **PASS**
- tests passed: 270
- tests failed: 0
- tests skipped: 2
- Limitation: 4 INTERNAL_GO contracts are unmapped; 16 mapped contracts were skipped.

### levain

- windows-amd64: **PASS**
- docker-linux-amd64: **PASS**
- true positives: 47
- expected secrets: 85
- false positives: 3
- duplicates: 2
- Limitation: Levain is a synthetic corpus; counts are not real-world prevalence.

### leaky-repo

- windows-amd64: **PASS**
- docker-linux-amd64: **PASS**
- expected count: 175
- covered count: 22
- count coverage percent: 12.57
- files covered: 13
- files covered percent: 29.55
- excess findings: 0
- unlisted findings: 0
- Limitation: Leaky Repo is a count-based filesystem benchmark, not a credential-level TP/FP oracle.
- Limitation: Count coverage is min(observed, expected) over 44 labeled file rows; excess and unlisted findings are reported separately.
- Limitation: Git-history benchmarking is not enabled in this checkpoint.

## Cross-platform comparisons

| Suite | Comparison | Result | Details |
| --- | --- | --- | --- |
| gitleaks | executable_vs_docker | PASS |  |
| levain | executable_vs_docker | PASS |  |
| leaky-repo | executable_vs_docker | PASS | 0 metric differences |

## Reports

- Sanitized: reports\cp1c\cp1c-both.json, reports\cp1c\cp1c-both.md
- Raw: not generated

## Limitations

- A successfully built artifact is not counted as tested unless an applicable suite executed it.
- Raw reports are opt-in and never printed in ordinary console summaries.
- Gitleaks fixture coverage is incomplete until every INTERNAL_GO contract is evidenced.
- 4 INTERNAL_GO contracts are unmapped; 16 mapped contracts were skipped.
- Leaky Repo count coverage is 12.57% (13/44 files); this is a count benchmark, not a completeness claim.
- One Linux-only symlink scenario is NOT_APPLICABLE on Windows native execution.
- Docker coverage remains INCOMPLETE until every INTERNAL_GO contract is evidenced.
- The legacy fixture lane retains hashed reports rather than raw scanner report bytes.
- Levain is a synthetic corpus; counts are not real-world prevalence.
- Leaky Repo is a count-based filesystem benchmark, not a credential-level TP/FP oracle.
- Count coverage is min(observed, expected) over 44 labeled file rows; excess and unlisted findings are reported separately.
- Git-history benchmarking is not enabled in this checkpoint.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
A built artifact is not counted as tested unless an applicable suite actually executed it.
