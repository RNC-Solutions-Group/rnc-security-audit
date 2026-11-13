# Consolidated Gitleaks Harness Report

> Overall: **COMPLETE_WITH_LIMITATIONS**

| Field | Value |
| --- | --- |
| Target repository | https://github.com/RNC-Solutions-Group/gitleaks |
| Branch | master |
| Resolved commit | 5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c |
| Source checkout | `C:\Dev\gitleaks\gitleaks-harness\datasets\cache\targets\4aa50df824a6f830\5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c\source` |
| Harness / scenario | 0.2.0 / cp1a-v1 |
| Generated (UTC) | 2026-11-09T22:30:45Z |

## Target builds

| Target | Status | Identity | Duration (s) |
| --- | --- | --- | --- |
| executable | PASS | `e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2` | 3.329 |
| docker | PASS | `sha256:e9e096883b0f956e40625c08cb2040e616551a849763b83c712efa59f2da1044` | 1.63 |

## Testing lanes

| Lane | Status | Evidence |
| --- | --- | --- |
| Branch Go tests | PASS | 270 passed, 0 failed |
| Docker fixtures | FUNCTIONAL_PASS_COVERAGE_INCOMPLETE | functional=PASS, coverage=INCOMPLETE |
| Levain | COMPLETED | adapter=executable |

## Parity

| Metric | Observed | Expected |
| --- | --- | --- |
| Docker scenarios | 23 | 23 |
| Assertions | 147 | 147 |
| Docker-applicable fixtures | 33 | 33 |
| Parity match | True | true |

## Levain results

- negative: COMPLETED; false positives 3; sections tripped 1
- positive: COMPLETED; true positives 47/85; partial 1; duplicates 2

## Limitations

- Docker fixture coverage remains INCOMPLETE until the 75 INTERNAL_GO fixture contracts are independently evidenced.
- Levain numbers are synthetic-corpus measurements, not real-world prevalence.
- Functional conformance and performance lanes are separate and not part of this consolidated report.
- Raw reports and scanner outputs remain in ignored work directories.
