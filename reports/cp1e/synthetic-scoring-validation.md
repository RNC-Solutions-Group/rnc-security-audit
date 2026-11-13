# Synthetic Scoring-Engine Validation

> Dataset: `synthetic-scoring` / `synthetic-v1`

| Metric | Value |
| --- | --- |
| Synthetic test cases | 31 |
| Correct outcomes | 31 |
| Incorrect outcomes | 0 |
| Scoring accuracy | **100.0%** |
| Unexpected classifications | 0 |
| Unresolved discrepancies | 0 |

## Cases

| Case | Expected | Actual | Correct |
| --- | --- | --- | --- |
| all-expected | `COMPLETED` | `COMPLETED` | True |
| zero-detection | `COMPLETED` | `COMPLETED` | True |
| partial-match | `COMPLETED` | `COMPLETED` | True |
| missing-one | `COMPLETED` | `COMPLETED` | True |
| unexpected-finding | `COMPLETED` | `COMPLETED` | True |
| false-positive-negative-oracle | `COMPLETED` | `COMPLETED` | True |
| duplicate | `COMPLETED` | `COMPLETED` | True |
| multiple-same-file | `COMPLETED` | `COMPLETED` | True |
| wrong-file | `COMPLETED` | `COMPLETED` | True |
| wrong-classification | `COMPLETED` | `COMPLETED` | True |
| overlapping-range | `COMPLETED` | `COMPLETED` | True |
| skipped-truth | `COMPLETED` | `COMPLETED` | True |
| unavailable-truth | `COMPLETED` | `COMPLETED` | True |
| blocked-execution | `BLOCKED` | `BLOCKED` | True |
| execution-error | `EXECUTION_ERROR` | `EXECUTION_ERROR` | True |
| empty-dataset | `COMPLETED` | `COMPLETED` | True |
| empty-output | `COMPLETED` | `COMPLETED` | True |
| malformed-finding | `COMPLETED` | `COMPLETED` | True |
| ambiguous-truth | `COMPLETED` | `COMPLETED` | True |
| not-ready-integrity | `NOT_READY` | `NOT_READY` | True |
| identity-value-verified | `COMPLETED` | `COMPLETED` | True |
| identity-value-mismatch | `COMPLETED` | `COMPLETED` | True |
| identity-swapped | `COMPLETED` | `COMPLETED` | True |
| identity-duplicate-same-key | `COMPLETED` | `COMPLETED` | True |
| identity-wrong-rule | `COMPLETED` | `COMPLETED` | True |
| identity-redacted-unverified | `COMPLETED` | `COMPLETED` | True |
| baseline-regression | `{'status': 'FAIL', 'new_misses': ['A2']}` | `{'status': 'FAIL', 'reason': None, 'existing_gaps': [], 'new_misses': ['A2'], 'recovered': [], 'new_unexpected': [], 'resolved_unexpected': [], 'changed_classification': [], 'summary': '0 existing gaps, 1 new misses, 0 recovered, 0 new unexpected, 0 resolved unexpected'}` | True |
| baseline-improvement | `{'status': 'PASS', 'recovered': ['A2']}` | `{'status': 'PASS', 'reason': None, 'existing_gaps': [], 'new_misses': [], 'recovered': ['A2'], 'new_unexpected': [], 'resolved_unexpected': [], 'changed_classification': [], 'summary': '0 existing gaps, 0 new misses, 1 recovered, 0 new unexpected, 0 resolved unexpected'}` | True |
| identical-counts-different-identities | `{'status': 'FAIL', 'new_misses': ['A1'], 'recovered': ['A3']}` | `{'status': 'FAIL', 'reason': None, 'existing_gaps': ['A4', 'A5', 'B1', 'B2', 'C1'], 'new_misses': ['A1'], 'recovered': ['A3'], 'new_unexpected': [], 'resolved_unexpected': [], 'changed_classification': [], 'summary': '5 existing gaps, 1 new misses, 1 recovered, 0 new unexpected, 0 resolved unexpected'}` | True |
| legacy-count-scoring | `{'expected_count': 3, 'covered_count': 2, 'files_covered': 1, 'excess_findings': 0, 'unlisted_findings': 1}` | `{'expected_count': 3, 'covered_count': 2, 'files_covered': 1, 'excess_findings': 0, 'unlisted_findings': 1}` | True |
| sanitized-unsanitized-reporting | `{'sanitized_omits_value': True, 'raw_contains_value': True}` | `{'sanitized_reports': ['synthetic.json', 'synthetic.md'], 'raw_report': 'raw-export-directory'}` | True |

## Independence

- Findings are emitted by the synthetic adapter through the normalized contract.
- The expected answers are static values in the validation module, not values computed by the scorer.
- The synthetic adapter imports no Gitleaks parser, rule, executable, or result model.

A passing result requires exact expected-versus-actual agreement; the process exit code alone is not evidence.
