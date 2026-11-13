# Scanner Harness Report

> Overall: **COMPLETE_WITH_LIMITATIONS**

> Matrix status: **PASS**

> Scanner: **gitleaks**

| Field | Value |
| --- | --- |
| Harness version | 0.3.0 |
| Run ID | `20261110T021936Z` |
| Generated (UTC) | 2026-11-10T02:20:14Z |
| Source repository | https://github.com/RNC-Solutions-Group/gitleaks |
| Source branch | master |
| Resolved commit | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |
| Scanner version | v8.0.0-rnc.5f6ec56cfa6f |
| Suites | go |

## Builds

| Platform | Kind | Build | Version | Artifact |
| --- | --- | --- | --- | --- |
| windows-amd64 | executable | PASS | v8.0.0-rnc.5f6ec56cfa6f | `e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2` |
| linux-amd64 | executable | PASS | NOT_RUN | `427efeb69ca00dce6185b58c4637d5dd5568c1a61cbdabae9f73302741b1ae25` |
| linux-arm64 | executable | PASS | NOT_RUN | `e77c0ffecd642670b25bf2aceecd608e7f6f997557d4f0073fd6ef442573c090` |
| darwin-amd64 | executable | PASS | NOT_RUN | `be8e348d93711ea832f0cb4ada06ff2dfc2aebd63aeb26952cea788aae2b16d5` |
| darwin-arm64 | executable | PASS | NOT_RUN | `2e4e5922114126dd13c16007ebea36f5947616b68d9ce54640bda62834ca10c5` |
| docker-linux-amd64 | docker | PASS | v8.0.0-rnc.5f6ec56cfa6f | `sha256:6032a8a47d83aac2520e473127fcc202ca2b3b43a1d9630899b6ed51bc0ca09d` |
| docker-linux-arm64 | docker | PASS | v8.0.0-rnc.5f6ec56cfa6f | `sha256:b4044d5814a0285f907a40eb6eaa910b89f36eea18b991b9cf7f74607710287c` |

## Datasets

| Dataset | Revision | Checksum |
| --- | --- | --- |
| gitleaks-fixtures | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` | `cd7f05e76b4590ee738d4573f3ddb3c493142ecd1204bc15754a21d0e66f7345` |

## Suites

| Suite | Status | Applicable | Metrics |
| --- | --- | --- | --- |
| go | PASS | True | tests passed=270; tests failed=0; tests skipped=2 |

## Suite details

### go

- source: **PASS**
- tests passed: 270
- tests failed: 0
- tests skipped: 2
- Limitation: 4 INTERNAL_GO contracts are unmapped; 16 mapped contracts were skipped.

## Reports

- Sanitized: reports\cp1c\cp1c-all-builds.json, reports\cp1c\cp1c-all-builds.md
- Raw: not generated

## Limitations

- A successfully built artifact is not counted as tested unless an applicable suite executed it.
- Raw reports are opt-in and never printed in ordinary console summaries.
- 4 INTERNAL_GO contracts are unmapped; 16 mapped contracts were skipped.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
A built artifact is not counted as tested unless an applicable suite actually executed it.
