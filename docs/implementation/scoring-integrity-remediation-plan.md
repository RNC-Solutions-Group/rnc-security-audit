# Scoring-Integrity Remediation Plan

**Checkpoint:** CP-SI0 → CP-SI7
**Branch:** `feat/scoring-integrity-remediation`
**Baseline:** `benchmark-harness` at `1d147f9feb7b73003c46adab3ea9e780807e5cdf`
**Authority:** Implement, validate, document, commit, and prepare a PR; do not merge.

## 1. Objectives

1. Give equivalent, independently verified evidence equivalent credit regardless of scanner format or redaction.
2. Never credit incorrect evidence, unsupported normalization, wrong locations, partial detections, or uncertain findings as TP.
3. Make attribution deterministic and one-to-one.
4. Reconcile every observation and oracle expectation.
5. Distinguish scanner failure, adapter failure, scorer failure, oracle limitation, and reporting limitation.
6. Preserve historical reports and original scores.

## 2. Workstreams

### CP-SI1 — Common evidence contract and resolver

**New module:** `harness/evidence.py`

Contracts:

- `EvidenceKind`:
  - `IDENTITY_DIGEST`
  - `SOURCE_SPAN_EXACT`
  - `SOURCE_SPAN_NORMALIZED`
  - `DECODED_IDENTITY`
  - `PRIVATE_KEY_MATERIAL`
  - `PUBLIC_KEY_ONLY`
  - `TRANSIENT_TEXT`
- `VerificationStage`:
  - `ADAPTER`
  - `SOURCE_IDENTITY`
  - `CANDIDATE_DISCOVERY`
  - `VALUE`
  - `LOCATION`
  - `MATERIAL`
  - `ATTRIBUTION`
- `ReasonCode`:
  - evidence: `EVIDENCE_MISSING`, `EVIDENCE_CONFLICT`, `REPRESENTATION_UNSUPPORTED`, `PRIVATE_MATERIAL_UNPROVEN`
  - location: `LOCATION_UNVERIFIED`, `LOCATION_LINE_MISMATCH`, `LOCATION_OFFSET_MISMATCH`
  - attribution: `CANDIDATE_AMBIGUOUS`, `SOURCE_OCCURRENCE_MISMATCH`
  - value: `VALUE_TRUNCATED`, `VALUE_EXTENDED`, `VALUE_MISMATCH`, `PARTIAL_MATERIAL`
  - adapter: `ADAPTER_CONTRACT_FAILURE`
  - oracle: `ORACLE_COVERAGE_UNKNOWN`
- `EvidenceResolution`:
  - `item_id`
  - `evidence_kind`
  - `value_verified`
  - `location_verified`
  - `material_verified`
  - `normalization`
  - `stage`
  - `reason_code`
  - `detail`

Functions:

- `span_aliases(span: bytes, *, representation: str, match_policy: str | None) -> tuple[EvidenceAlias,...]`
  - exact span;
  - PEM-only terminal `\r\n`/`\n` and trailing whitespace aliases;
  - complete-block validation (header/footer/body, no truncation);
  - LF/CRLF variants only when the block remains complete.
- `private_key_span_material(span: bytes, representation: str) -> bool`
  - PEM/OpenSSH complete private block;
  - Base64 K8s decode to complete private PEM;
  - no public/SPKI/filename-only.
- `classify_value_relation(span: bytes, finding_digest: str | None, finding_text: str | None) -> str | None`
  - exact/normalized/truncated/extended/partial material candidates;
  - conservative, digest/text based, no proximity.
- `stable_finding_key(finding)` and `stable_candidate_key(...)` helpers.

**Contract changes:** `NormalizedFinding` gains optional defaults only:

- `byte_start: int | None = None`
- `byte_end: int | None = None`
- `container_member: str | None = None`
- `source_span_sha256: str | None = None`
- `evidence_kind: str | None = None` (optional adapter hint; scorer verifies independently)

No serialization of transient text; `safe_dict()` continues to omit it.

### CP-SI2 — RNC Lab evidence resolution and attribution

Modify `harness/rnclab.py`:

1. Build an oracle alias index:
   - exact identity, span, public identity;
   - PEM normalized aliases from `evidence.span_aliases`;
   - alias-kind metadata for reasons.
2. Replace `_value_evidence` with resolver-based checks:
   - exact identity;
   - exact source span for any normalization, if path and location validate;
   - approved normalized source span;
   - decoded identity if text exists;
   - explicit `UNSUPPORTED_NORMALIZATION` otherwise.
3. Enforce location:
   - line equality when oracle line and finding line are present;
   - byte offset equality/tolerance when both are present (RNC metadata);
   - missing coordinates allowed only under an explicit policy; otherwise near-miss/unverified.
4. Private-key material:
   - complete PEM/OpenSSH or decoded K8s private material;
   - exact oracle private span + oracle representation acceptable for redacted evidence;
   - public-only/incomplete/incorrect identity → `UNVERIFIED_EVIDENCE`/`PARTIAL_MATERIAL`.
5. Avoid premature short-circuit:
   - evaluate all candidates for a finding;
   - only after evaluating all candidates assign the best evidence;
   - private-key failure on one candidate must not hide another valid candidate.
6. Deterministic attribution:
   - build all finding→candidate edges;
   - sort edges by `(evidence strength, line distance, item_id, stable finding key)`;
   - greedily assign one-to-one;
   - equal-strength competing candidates are recorded, not silently first-wins;
   - findings are processed in stable order independent of input order.
7. Near-miss classification:
   - after exact assignment, proven-relation failures become `NEAR_MISS` with a reason code:
     - exact value, wrong line/offset → `LOCATION_LINE_MISMATCH`/`LOCATION_OFFSET_MISMATCH`;
     - truncated/extended value → `VALUE_TRUNCATED`/`VALUE_EXTENDED`;
     - incomplete private key → `PARTIAL_MATERIAL`;
     - exact value at another occurrence → `SOURCE_OCCURRENCE_MISMATCH`;
     - unsupported alias → `UNSUPPORTED_NORMALIZATION`.
   - near-miss target remains FN; target counted once;
   - unrelated same-line findings stay `UNVERIFIED_EVIDENCE`;
   - no proximity-only near misses.
8. Diagnostics:
   - add `reason_code`, `stage`, `evidence_kind` to outcomes/exceptions;
   - add `exception_total`, `exceptions_truncated`;
   - add `near_miss_count`, `near_miss_target_count`, `near_miss_reason_counts`, `near_miss_targets`.
9. Metrics invariants:
   - `true_positive_occurrences + false_negative_occurrences == expected_positives`;
   - outcome count == observed findings;
   - near misses excluded from TP and FP;
   - duplicates excluded from TP;
   - negative/trap-only FP.

### CP-SI3 — Private-key and encoded-source verification

1. Use `evidence.private_key_span_material` to validate decoded K8s private keys.
2. Accept exact private-key source span + oracle representation for redacted RNC evidence after location validation.
3. Preserve public-only rejection (existing test).
4. Add explicit `PRIVATE_MATERIAL_UNPROVEN` diagnostics.
5. Do not add any scanner-specific raw-secret exposure.

### CP-SI4 — Metric and reporting accounting

Modify `harness/scoring.py`:

- `match_classification.miss` = only ordinary misses.
- `match_classification.partial_uncredited` = partials.
- `false_negatives` remains expected − TP (partials not credited).
- positive-run `false_positives` = unexpected findings only; add `partial_findings`, `ambiguous_findings`.
- suite metrics continue to use the negative corpus for FP.
- add a reconciliation flag/expected count.

Modify `harness/suites/levain.py` and `harness/report.py` to report:

- expected, TP, FN, ordinary misses, partial-uncredited, ambiguous, unexpected;
- explicit statement that partials are not TP and are included in FN;
- no mutually exclusive bucket sum mismatch.

Modify `harness/report.py` / `harness/reporting.py`:

- RNC Lab near-miss table/counts and reason codes;
- explicit exception truncation metadata;
- private-key limitation; `NO_ALERT` wording;
- target-level accounting summary;
- no pooled accuracy across suites.

Do not modify `scoring_engine.py` legacy metric names unless required for a tested reconciliation fix; add explicit aliases where appropriate.

### CP-SI5 — Calibration suite

Add `tests/test_scoring_calibration.py` and small synthetic fixtures created in-test with `tempfile`/`tmp_path` patterns or in-memory truth manifests.

Calibration cases:

- exact identity; exact digest-only; Base64 source-span; decoded identity;
- truncated/extended/mismatched/whitespace-modified values;
- complete PEM; terminal LF/CRLF; Base64 PEM; public-only; missing footer; truncated body; wrong identity;
- exact line/offset; off-by-one/two; wrong line; wrong file; missing coordinates; wrong archive member; wrong DB record;
- Git introduction/ancestry/later revision/reintroduction/rename/merge/wrong commit;
- one-to-one, multiple findings, multiple candidates, identical values, reversed order, reversed oracle order, duplicate;
- negative/trap hit, incomplete negative truth, legitimate unverified;
- reporting reconciliation, reason codes, precision nullity, incomplete execution.

Use `unittest` style consistent with repo. Add property-based/order-permutation tests using `itertools.permutations` for small cases; no external dependency.

### CP-SI6 — Real-scanner validation

After unit/calibration/regression passes:

- Run targeted RNC CP4B native RNC Lab to validate Base64/PEM/K8s and near-miss diagnostics.
- Run Gitleaks/Betterleaks RNC Lab to validate equivalence.
- Run `--suites all` for CP4B/Gitleaks/Betterleaks to validate Levain/Leaky reporting.
- Run CP3 to validate N/A Git and no regressions.
- Run full unit suite.
- Run fresh baselines only after correctness; do not use historical scores as expected.

Use `--platforms windows-amd64`, 2 warmups/5 runs, `DEV`, offline. Preserve provenance and original reports.

### CP-SI7 — Final disposition, commit, PR

- `docs/implementation/scoring-integrity-execution-ledger.md`
- `docs/implementation/scoring-integrity-final-disposition.md`
- Commit in logical checkpoints.
- Push `feat/scoring-integrity-remediation`.
- Prepare PR against `benchmark-harness`; do not merge.
- If PR creation is unavailable, provide the exact push/PR command and compare URL.

## 3. Implementation sequence

1. Write CP-SI0 docs (this file + architecture review).
2. Add `harness/evidence.py` and contract fields.
3. Add evidence unit tests (not yet integrated).
4. Refactor `rnclab` resolver + strict location; run `test_rnclab`.
5. Refactor deterministic attribution; add order tests.
6. Add near-miss outcomes/metrics; add tests.
7. Fix Levain classification/FP semantics; update tests.
8. Update reporting/JSON/Markdown; add tests.
9. Add calibration suite; run.
10. Run full regression.
11. Real-scanner Stage A/B/C.
12. Fresh baselines Stage D.
13. Ledger/final disposition; commit/push/PR.

## 4. Acceptance criteria

- 100% calibration agreement, including expected unverified/unmatched cases.
- TP + FN = expected positives for fully assessed lanes.
- Sum of terminal finding classifications = observed findings.
- Reversed finding/oracle order produces identical metrics and target sets.
- Exact Base64 source spans receive TP for RNC and G/B.
- PEM terminal LF/CRLF receives TP; truncated/public-only does not.
- Wrong line/offset does not receive TP and receives a near-miss or unverified reason.
- FP only from verified negative/trap truth.
- Near-miss does not create an extra FN.
- Duplicate does not create TP.
- Levain classification totals equal expected; positive-run partial not an FP.
- Exception truncation is explicit with total.
- Full test suite passes.
- Real-scanner targeted validation passes.
- Fresh baselines complete or are accurately blocked.
- Final disposition is GO/CONDITIONAL GO/NO-GO with exact scope.
- PR prepared; not merged.

## 5. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Exact span acceptance too broad | Path/line/offset validation; oracle POSITIVE only; no negative/informative credit |
| PEM alias accepts truncated block | Require header, body, footer, complete key marker; tests |
| K8s private policy too permissive | Decode and validate private PEM; reject public/SPKI |
| Strict line breaks real scanner TPs | Measure before/after; allow explicit missing-coordinate policy; near-miss diagnostics |
| Deterministic assignment changes target sets | Calibration/order tests; compare real reports; document deltas |
| Levain metric name changes break consumers | Add new fields, update report, preserve aliases where possible |
| Near-miss overreach | Require value/offset/occurrence proof; no proximity-only |
| Historical comparability | Keep originals; corrected reports labeled; no rewrite |

## 6. Migration and compatibility

- Existing `NormalizedFinding` constructors remain valid (new fields default).
- Existing JSON report keys retained where possible; new fields additive.
- Levain `false_positives` positive-run semantics change; document in schema notes and update tests/reports.
- RNC Lab exception arrays gain totals/truncation; existing 250-row cap retained.
- Historical reports unchanged; new scoring version recorded.
- No oracle/fixture/scanner changes.
