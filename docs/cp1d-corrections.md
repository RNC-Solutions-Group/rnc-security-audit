# CP1D correction register

**Checkpoint:** CP1E
**Starting commit:** `86de44bf1cb13abf9a0c375a8b91d102c9b6dc9f`

| ID | CP1D defect / gap | Correction | Evidence |
| --- | --- | --- | --- |
| C1 | A successful legacy Leaky score could leave rich scoring `NOT_READY` while targets/parity stayed PASS | Rich readiness now propagates: lane `rich_status=NOT_READY` makes the target FAIL, suite FAIL, and matrix scoring-failure FAIL; parity emits a rich UNKNOWN difference | `harness/suites/leaky_repo.py`; `tests/test_suites.py::ScoringReadinessTests`; `tests/test_matrix.py::test_scoring_not_ready_is_a_scoring_failure` |
| C2 | Synthetic validation checked aggregate metrics but not individual finding identity/classification | 31 cases now include exact expected/actual classification, expected ID, path, line, and identity confidence; six adversarial identity cases | `harness/synthetic_validation.py`; `reports/cp1e/synthetic-scoring-validation.json` |
| C3 | Rich identity was location-only | Truth items may carry safe value fingerprints; matches report `identity_confidence=value|line`; PEM items remain explicitly line-only; redacted output is never treated as value-verified | `harness/scoring_engine.py`; `datasets/leaky-repo.rnc-truth.json`; Leaky metrics `value_verified_count=20`, `line_only_count=2` |
| C4 | Simplified observed-key maps could collide at the same file/line | Parity keys now include secret fingerprint/commit/index; unexpected observations cannot overwrite each other | `harness/suites/leaky_repo.py`; `harness/suites/git_history.py` |
| C5 | Leaky per-file counts were not validated against the inventory | Validation checks every file's total and, except the six annotated conflicts, risk/informative counts; unannotated conflicts fail | `harness/leaky_truth.py`; `tests/test_leaky_truth.py` |
| C6 | Active reports retained Go-contract warnings and four-unmapped/16-skipped obligations | Gitleaks fixture acceptance now uses scenario/assertion parity only; active Go imports/methods/CLI lane removed; legacy `consolidate` module is archived and no longer a CLI command | `harness/adapters/gitleaks.py`; `harness/adapters/gitleaks_fixtures.py`; `tests/test_architecture.py` |
| C7 | Matrix work directory remained named `work/cp1c` | Corrected to `work/cp1e` | `harness/matrix.py` |
| C8 | Truth category reconciliation was reported at aggregate level only | Per-file reconciliation is persisted in integrity and final reports; six conflicts remain explicit and do not change the 175 denominator | `harness/leaky_truth.py`; `reports/cp1e/history-accountability.json` |

## Regression proof

- Full Python suite: see CP1E report / final commit.
- Synthetic: **31/31**, **100.0%**, zero unexpected classifications.
- Leaky filesystem: 22/175 legacy; 22 matched / 153 missed rich; 20 value-verified, 2 line-only.
- Three-product filesystem, history, and cross-product parity: all PASS.
- CP1D baseline comparison: PASS with no new misses or unexpected findings for Leaky.
