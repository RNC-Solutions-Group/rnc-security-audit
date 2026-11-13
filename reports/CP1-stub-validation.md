# Gitleaks Scan Harness — CP1 Detection Report

> **HARNESS VALIDATION REPORT.**
This file contains no raw matched values, no expected secret text, and no raw scanner report.

| Field | Value |
| --- | --- |
| Overall status | **COMPLETED** |
| Gitleaks integration | STUB_VALIDATION_ONLY |
| Gitleaks execution | BLOCKED |
| Detection accuracy | NOT_A_GITLEAKS_MEASUREMENT |
| Scanner kind | stub |
| Harness / scenario | 0.1.0 / cp1-v1 |
| Generated (UTC) | 2026-11-09T19:18:51Z |

## Scope warning

The scanner used here is a **controlled test double**, not Gitleaks. The numbers demonstrate the harness's acquisition, execution, scoring, failure detection, and reporting paths. **They are not Gitleaks benchmark results.** Actual Gitleaks execution is `BLOCKED` because no executable or Go toolchain was available in this environment.

## Dataset

| Field | Value |
| --- | --- |
| Name | Levain FP Corpus (negative and positive fixtures) |
| Source | https://github.com/levainbot/fp-corpus |
| Revision | c130c321aa9046af17a6c876cb97e2ed71397110 |
| Tag | v1 |
| License | MIT |
| Manifest SHA-256 | c456d2a4943494dea0ac3e5161193d91a77250c700c23e5113de12b2a311af3e |
| Counting unit | individual labeled case: negative corpus counts sections (expected secrets are zero); positive corpus counts planted credentials |

| Corpus | Sections | Lines | Credentials | Hard sections |
| --- | --- | --- | --- | --- |
| Negative | 116 | 866 | 0 | 0 |
| Positive | 45 | 368 | 85 | 3 |

## Target

| Field | Value |
| --- | --- |
| Scanner kind | stub |
| Binary path | `tests/fixtures/stub-gitleaks.cmd` |
| Binary SHA-256 | `56cd2b9dd324602b8a26ff2253c22b3ad936201e7bcabe6adb5785240c3e256a` |
| Gitleaks source revision | not supplied |
| Integration status | STUB_VALIDATION_ONLY |
| Scan mode | dir |

## Execution

### Negative corpus

| Field | Value |
| --- | --- |
| Status | **COMPLETED** |
| Command | `tests/fixtures/stub-gitleaks.cmd dir <corpus-dir> --report-format json --report-path <report> --no-banner` |
| Exit code | 0 |
| Timed out | no |
| Timeout limit (s) | 300.0 |
| Duration (s) | 0.18 |
| Positive control reported | yes |
| Scanner report SHA-256 | `ec9b4582505a11cf6349c59d1f47bd94609f641410d070118e5113020395f8df` |
| Stderr (redacted) | (empty) |

| Metric | Value |
| --- | --- |
| Sections scanned | 116 |
| Expected credentials | 0 |
| Findings parsed | 882 |
| False positives | 833 |
| Duplicate findings | 0 |
| Personal-data matches (not counted) | 49 |
| Sections tripped | 115 |
| Clean | no |

True negatives are **not** inferred from line counts; this corpus has no per-line oracle. A clean run means no unexpected finding was reported.

| Section | Findings |
| --- | --- |
| pem certificate | 32 |
| windows event log xml | 29 |
| dpkg and apt history log | 22 |
| openapi security scheme | 22 |
| json schema with patterns | 18 |
| package-lock json | 18 |
| progress bar with carriage returns | 18 |
| terraform state | 18 |
| aws cli | 17 |
| grpcurl and protobuf | 15 |

### Positive corpus

| Field | Value |
| --- | --- |
| Status | **COMPLETED** |
| Command | `tests/fixtures/stub-gitleaks.cmd dir <corpus-dir> --report-format json --report-path <report> --no-banner` |
| Exit code | 0 |
| Timed out | no |
| Timeout limit (s) | 300.0 |
| Duration (s) | 0.152 |
| Positive control reported | yes |
| Scanner report SHA-256 | `d9d17685a3d0f97be403b7987785950d5a8b980300a23aa3b52bb30d10b43fd0` |
| Stderr (redacted) | (empty) |

| Metric | Value |
| --- | --- |
| Sections scanned | 45 |
| Expected credentials | 85 (82 core, 3 hard) |
| True positives | 85 |
| False negatives | 0 |
| Core recall | 100.0% |
| Hard recall | 100.0% |
| Overall recall | 100.0% |
| Unexpected findings | 259 |
| Duplicate findings | 15 |
| Personal-data matches (not counted) | 10 |

Unexpected findings (locations only):

| Section | Line | Rule |
| --- | --- | --- |
| env-file | 1 | stub |
| env-file | 2 | stub |
| env-file | 3 | stub |
| env-file | 4 | stub |
| env-file | 9 | stub |
| env-file | 10 | stub |
| docker-run-command | 1 | stub |
| docker-run-command | 2 | stub |
| docker-run-command | 5 | stub |
| docker-run-command | 6 | stub |

## Limitations

- The scanner used for this report is a controlled test double, not Gitleaks. The counts below validate the harness and must not be read as Gitleaks detection accuracy.
- Only the CP1 detection lane is implemented; functional conformance, performance, and Go race testing are not part of this report.
- The corpus is synthetic and finite; it does not measure real-world repository or credential prevalence.
- Negative-corpus true negatives are not inferred from line counts; the oracle is 'expected secrets are zero'.
- Three hard-tier credentials are reported separately and are not included in the core recall percentage.
- The Gitleaks JSON report parser is written to the documented shape but has not been exercised against a real Gitleaks executable in this checkpoint.
- No target Gitleaks source revision was supplied.

## Reproduction

```sh
python -m harness prepare
python -m harness run --gitleaks <path-to-gitleaks> --corpus both \
  --gitleaks-source-revision <40-char-sha> --out-dir reports --name <name>
```

The scan target directory and raw report are temporary. See `docs/checkpoints/CP1-report.md` for the checkpoint record.
