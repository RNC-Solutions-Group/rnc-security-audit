# Consolidated Gitleaks Harness Report

> Overall: **COMPLETE_WITH_LIMITATIONS**
> Canonical target status: **PASS**
> Target selection: `docker`

| Field | Value |
| --- | --- |
| Target repository | https://github.com/RNC-Solutions-Group/gitleaks |
| Branch | master |
| Resolved commit | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |
| Source checkout | `C:\Dev\gitleaks\gitleaks-harness\datasets\cache\targets\4aa50df824a6f830\5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c\source` |
| Harness / scenario | 0.2.0 / cp1a-v1 |
| Generated (UTC) | 2026-11-09T22:57:05Z |

## Target matrix

| Target | Selected | Build | Fixture lane | Levain lane | Target status |
| --- | --- | --- | --- | --- | --- |
| executable | False | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE | **NOT_APPLICABLE** |
| docker | True | PASS | PASS | PASS | **PASS** |

## Builds

| Target | Status | Identity | Duration (s) |
| --- | --- | --- | --- |
| docker | PASS | `sha256:08326fdcab28952ba4a807fcbc4142b913c2a264ee905715ad3bc6bc5bd2146b` | 2.969 |

## Branch Go tests

- Status: **PASS**
- Tests passed / failed / skipped: 270 / 0 / 2
- Packages passed / failed: 7 / 0

## Fixture lanes

| Target | Status | Scenarios | Assertions | Coverage | Notes |
| --- | --- | --- | --- | --- | --- |
| executable | NOT_APPLICABLE | - | - | - | --targets does not select the executable target. |
| docker | PASS | 23 | 147 | False | docker parity=True |

### Docker parity

| Metric | Observed | Expected |
| --- | --- | --- |
| Docker scenarios | 23 | 23 |
| Assertions | 147 | 147 |
| Docker-applicable fixtures | 33 | 33 |
| Parity match | True | true |

## Cross-target comparisons

| Lane | Status | Differences | Not comparable |
| --- | --- | --- | --- |
| Fixtures | NOT_APPLICABLE | 0 | 0 |
| Levain | NOT_APPLICABLE | 0 | 0 |

## Levain results

- executable: NOT_APPLICABLE (--targets does not select the executable target.)
- docker: PASS (adapter `docker`)
  - negative: COMPLETED; false positives 3; sections tripped 1
  - positive: COMPLETED; true positives 47/85; partial 1; duplicates 2

## INTERNAL_GO evidence mapping

- Status: **NOT_RUN**
- Contracts: 75 total; 71 mapped; 4 unmapped
- Validated: 55 (49 direct, 6 indirect); skipped: 16; failed: 0

Unmapped contracts:

- `testdata/baseline/baseline.json` - No executing Go test loads this file; TestFileLoadBaseline covers the CSV and SARIF rejection paths.
- `testdata/config/invalid/extend_invalid_base.toml` - no named executing Go test
- `testdata/expected/git/small-branch-foo.txt` - The only upstream reference is a commented-out test in sources/git_test.go.
- `testdata/expected/git/small.txt` - The only upstream reference is a commented-out test in sources/git_test.go.

Skipped contracts:

- 16 contracts via detect.TestFromGit (not executed on this host)

## Limitations

- Levain is a synthetic corpus; its counts are not real-world prevalence estimates.
- Functional conformance and performance lanes remain separate from this consolidated report.
- Raw reports and scanner outputs remain in ignored work directories.
- 4 INTERNAL_GO contract(s) have no named executing Go test; 16 mapped contract(s) were skipped on this host.
- Docker fixture coverage remains INCOMPLETE until every INTERNAL_GO contract is independently evidenced.

Raw reports and scanner outputs remain in ignored work directories.
