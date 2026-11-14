# Scoring-Integrity Execution Ledger

**Checkpoint:** CP-SI0 → CP-SI7  
**Branch:** `feat/scoring-integrity-remediation`  
**Baseline:** `benchmark-harness` at `1d147f9feb7b73003c46adab3ea9e780807e5cdf`  
**Authority:** Implement, validate, document, commit, and prepare a PR; do not merge.  
**Recorded:** 2026-11-13 (America/New_York)

This ledger records what was implemented, how it was validated, and what was not
changed. It is deliberately separate from the prior investigation report under
`run/investigations/scoring-integrity-20261113/`; that report and all historical
benchmark reports remain untouched.

## 0. Pre-merge corrective review (PR #15)

Four independent findings were examined before merge.

| Finding | Review result | Root cause | Correction | Regression intent |
|---|---|---|---|---|
| Evidence priority and alias selection | **Confirmed** | Ambiguity used `min(priority, ...)` while attribution used `-priority`; per-item aliases were retained by first encounter order, not strongest proof. | One `_candidate_rank()` contract; strongest alias per finding/item; ambiguity and assignment use the same rank. | Exact+weaker candidate stays uniquely stronger; digest/oracle/finding/alias permutations do not change attribution. |
| Global one-to-one attribution | **Confirmed** | Greedy edge assignment can consume a shared target needed by a later finding (A→1/2, B→1). | Deterministic maximum-weight bipartite assignment with positive coverage first, total assignment second, evidence quality third; genuinely ambiguous findings remain uncredited. | Adversarial A/B case assigns both targets; equal-strength cycles remain `AMBIGUOUS`; permutations preserve target sets. |
| Archive-member identity end-to-end | **Confirmed as a contract gap** | Adapters did not populate `container_member`; RNC path resolution parsed only the filename. Native RNC reports do not expose a separate member field; Gitleaks/Betterleaks may embed it in the path. | Shared canonical archive-member parser; adapters populate the field from embedded paths; resolver requires the explicit member or an embedded member, with gzip single-member handling only. | Correct/wrong archive and member, nested members, identical values in different members, explicit vs embedded identity, gzip path-only. |
| Kubernetes structured-source location | **Confirmed** | `_line_matches()` accepted any earlier line for recognized rule names. | Source-verified YAML document/`kind: Secret`/`data` block/key policy, bounded to the item's enclosing document and exact value evidence. | Exact line, valid `kind`/`data`/key line, unrelated earlier line/document, wrong field, wrong digest, repeated values. |

No finding was unreproducible. The archive finding is partly a **capability
limitation**: native RNC reports do not provide container-member identity, so the
common scorer cannot invent it. Gitleaks/Betterleaks path-embedded members are
recoverable and are now carried explicitly. Single-member gzip may use the
enclosing path; multi-member ZIP/TAR may not.

The correction preserves the existing architecture: the evidence contract remains
central, and no scanner-specific score exception is introduced.

## 1. Scope and constraints observed

- No RNC, Gitleaks, Betterleaks, or RNC-Mod source was modified.
- No registered executable, image, ruleset, oracle, certified fixture, corpus, or
  `run/manifest.toml` was modified.
- No matching rule was loosened to increase recall.
- No historical score or report was rewritten.
- Raw matches and raw scanner output remain in Git-ignored `run/`.
- The local `AGENTS.md` was not modified.
- Native Windows AMD64 executables and the already-registered builds were used;
  no scanner source build, image pull, or Docker dependency was introduced.
- GitHub Actions was not invoked or configured.

## 2. Implementation ledger

### CP-SI1 — Common evidence contract

**Added:** `harness/evidence.py`

- Explicit evidence kinds: identity digest, exact source span, normalized source
  span, decoded identity, private-key material, public-key-only, transient text.
- Explicit verification stages: adapter, source identity, candidate discovery,
  value, location, material, attribution.
- Stable reason codes for missing/conflicting evidence, unsupported
  representations, private-material failures, location failures, ambiguous
  candidates, source-occurrence mismatch, truncation/extension, partial material,
  and oracle-coverage gaps.
- Conservative PEM terminal-newline aliases only for complete private PEM blocks.
- Private-material validation from oracle source bytes; Kubernetes/Base64
  payloads are decoded before validation.
- Conservative value relation (`exact`, representation alias, truncated,
  extended, proven whitespace mismatch); no generic value normalisation.
- Stable finding keys for deterministic ordering.

**Contracts changed:** `harness/contracts.py`

- `NormalizedFinding` gained optional `byte_start`, `byte_end`,
  `container_member`, and `source_span_sha256`.
- The fields are additive and default to `None`; existing adapters remain valid.

**Adapter changed:** `harness/adapters/rnc.py`

- RNC normalized findings now carry the scanner's byte range and source-span
  digest so the resolver can apply a verifiable location policy.

### CP-SI2 — Evidence resolver and RNC Lab attribution

**Changed:** `harness/rnclab.py`

- All value evidence is resolved through an explicit alias index. Exact source
  spans are accepted for every normalization; PEM aliases are accepted only for
  complete private PEM blocks; Kubernetes/Base64 decoded private PEM aliases are
  accepted only when the decoded material is a complete private key.
- Private-key credit still requires private material. Public-only, SPKI-only,
  malformed, and merely filename-adjacent evidence cannot earn a TP.
- Location is enforced against path, archive member (where reported), line, and
  byte range. A contained byte range is accepted when the reported value identity
  is exact (for example, the userinfo component of a database URL). Extended or
  overlapping ranges are not accepted.
- Kubernetes secret YAML may report the enclosing data-block line rather than the
  base64 value line; this is a declared structured-source location policy, used
  only after exact value evidence has been proved.
- Attribution is global, one-to-one, and order-independent. All candidate edges
  are built first, sorted by evidence strength and stable keys, and assigned once.
  Equal-strength unresolvable candidates become `AMBIGUOUS`; they are never
  resolved by finding or oracle order.
- A finding that proves an exact value at the wrong source occurrence is
  `NEAR_MISS` with `SOURCE_OCCURRENCE_MISMATCH`; a finding with the wrong line or
  byte range is a location near miss. A target that is only near-missed remains a
  false negative and is counted once.
- A finding at the right positive path/line with an unrelated value is
  `UNVERIFIED_EVIDENCE` with `EVIDENCE_CONFLICT`, not a near miss and not a false
  positive.
- Duplicate alerts never increase TP. Partial/ambiguous evidence is never a
  verified false positive.
- New metrics: near-miss count, near-miss target count, near-miss reason counts,
  ambiguous count, target-accounting and finding-accounting reconciliation.
- Exception export now carries reason code, stage, evidence kind, and candidate
  IDs. Truncation is explicit through `exceptions_truncated`; all missed targets
  contribute to `exception_count` before the 250-row display cap.
- The `findings` export now includes the classification and diagnostic fields;
  raw secret text remains excluded.

### CP-SI3 — Levain target/finding accounting

**Changed:** `harness/scoring.py`

- `partial` is a distinct target bucket and remains uncredited (`FN`).
- `miss` now means ordinary missed targets, not the sum of partial + ordinary.
- Complete + normalized + partial + ordinary miss reconcile to expected.
- Positive-run `false_positives` now counts only unexpected findings, not partial
  or ambiguous findings. Suite-level false positives remain sourced from the
  negative corpus.
- Added `partial_findings`, `ambiguous_findings`, `unexpected_findings`, and
  `target_accounting`.

**Changed:** `harness/report.py`

- Levain Markdown distinguishes partial-uncredited, ambiguous findings, ordinary
  misses, and target reconciliation.

### CP-SI4 — Cross-suite diagnostics and reporting

**Changed:** `harness/scoring_engine.py`

- Added explicit `unmatched_only_count`, `unexpected_observation_count`,
  `unmatched_or_unmapped_count`, finding-classification counts/totals, and
  target/finding accounting.
- Legacy metric names are retained for compatibility; the new fields make the
  difference between verified false positives and unresolved observations
  explicit.

**Changed:** `harness/experiment.py`, `harness/suites/rnclab.py`,
`harness/reporting.py`

- Near-miss, unverified, ambiguous, and accounting fields are propagated into the
  detection summary and readable RNC Lab summary instead of being dropped during
  suite aggregation.
- RNC Lab summary now reports near misses and unverified evidence alongside TP,
  pending, and verified FP.

### CP-SI5 — Independent calibration

**Added:** `tests/test_scoring_calibration.py`

Predetermined cases cover:

- exact identity/source span without plaintext;
- Base64 exact source span;
- PEM terminal LF and CRLF variation;
- Kubernetes Base64 private key;
- decoded Kubernetes private key with a stripped terminal newline;
- public-key-only rejection;
- incomplete PEM footer (`PARTIAL_MATERIAL`);
- wrong private key identity;
- wrong line, wrong byte offset, and truncated value near misses;
- unrelated same-line value (`UNVERIFIED_EVIDENCE`, not near miss);
- unmatched findings not becoming false positives;
- verified negative evidence producing a false positive;
- duplicate alerts not increasing TP;
- finding-order and oracle-order invariance;
- exception truncation visibility;
- Levain partial buckets and target reconciliation;
- Leaky scoring target/finding accounting.

**Expanded:** `tests/test_rnclab.py`

- Exact Base64 span, PEM newline alias, Kubernetes private key, wrong line/offset,
  truncated value, unrelated value, order reversal, and exception-count tests.
- The prior "unknown path stays pending" expectation was updated because an exact
  value at a different source occurrence is now a `SOURCE_OCCURRENCE_MISMATCH`
  near miss, while still not a TP.

## 3. Test evidence

Command:

```powershell
python -m unittest discover -s tests -t .
```

Final result: **354 tests run, OK, 1 skipped** (the skip is the existing
platform/capability skip, not a failed or unscored test). The final count includes
the new RNC Lab, archive-member, Kubernetes-location, assignment, and independent
calibration cases added by this package and the pre-merge corrective pass.

Targeted commands used during development:

```powershell
python -m unittest tests.test_rnclab -v
python -m unittest tests.test_scoring -v
python -m unittest tests.test_scoring_engine -v
python -m unittest tests.test_scoring_calibration -v
python -m unittest tests.test_report tests.test_reporting tests.test_experiment -v
```

## 4. Real-scanner validation

All runs used native Windows AMD64 registered artifacts, `--platforms
windows-amd64`, `--warmups 2 --runs 5 --benchmark-environment DEV --offline`, and
sequential execution. No historical report was substituted.

### 4.1 Fresh baselines

| Build | Suite | Overall | Corrected RNC Lab FS | Corrected RNC Lab Git |
|---|---|---:|---:|---:|
| `rnc-cp3` | `all` | COMPLETE_WITH_LIMITATIONS | — | — |
| `rnc-cp3` | `rnclab` | COMPLETE | 302/640 (47.19%) | N/A |
| `rnc-cp4a` | `all` | COMPLETE_WITH_LIMITATIONS | — | — |
| `rnc-cp4a` | `rnclab` | COMPLETE | 347/640 (54.22%) | 115/160 (71.88%) |
| `rnc-cp4b` | `all` | COMPLETE_WITH_LIMITATIONS | — | — |
| `rnc-cp4b` | `rnclab` | COMPLETE | 347/640 (54.22%) | 120/160 (75.00%) |
| `gitleaks-master` | `all` | COMPLETE_WITH_LIMITATIONS | — | — |
| `gitleaks-master` | `rnclab` | COMPLETE | 369/640 (57.66%) | 130/160 (81.25%) |
| `betterleaks-lts` | `all` | COMPLETE_WITH_LIMITATIONS | — | — |
| `betterleaks-lts` | `rnclab` | COMPLETE | 438/640 (68.44%) | 158/160 (98.75%) |
| `gl-rnc-mod-v10` | `all` | COMPLETE_WITH_LIMITATIONS | — | — |
| `gl-rnc-mod-v10` | `rnclab` | COMPLETE | 369/640 (57.66%) | 130/160 (81.25%) |

All baseline and corrective RNC Lab reports report
`target_accounting_reconciled=true` and `finding_accounting_reconciled=true` for
both applicable lanes. All performance measurements completed with `PASS`; the
RNC Lab runs are intentionally separate from the `all` suite.

Private-key cross-scanner result after correction:

| Build | Filesystem private keys | Git private keys |
|---|---:|---:|
| `rnc-cp4b` | 14/28 | 10/10 |
| `gitleaks-master` | 14/28 | 10/10 |
| `betterleaks-lts` | 14/28 | 10/10 |
| `gl-rnc-mod-v10` | 14/28 | 10/10 |

This equivalence is the key fairness result: the same private-key evidence is
credited regardless of whether the scanner reports the PEM source span, the PEM
with a different terminal line ending, or the decoded Kubernetes key with a
stripped terminal newline.

### 4.2 Corrected impact relative to the historical reports

The historical reports were not modified. The corrected comparison is:

| Build | Lane | Historical TP | Corrected TP | Delta |
|---|---|---:|---:|---:|
| `rnc-cp3` | FS | 260 | 302 | +42 |
| `rnc-cp4a` | FS | 297 | 347 | +50 |
| `rnc-cp4a` | Git | 105 | 115 | +10 |
| `rnc-cp4b` | FS | 297 | 347 | +50 |
| `rnc-cp4b` | Git | 110 | 120 | +10 |
| `gitleaks-master` | FS | 357 | 369 | +12 |
| `gitleaks-master` | Git | 120 | 130 | +10 |
| `betterleaks-lts` | FS | 426 | 438 | +12 |
| `betterleaks-lts` | Git | 148 | 158 | +10 |
| `gl-rnc-mod-v10` | FS | 357 | 369 | +12 |
| `gl-rnc-mod-v10` | Git | 120 | 130 | +10 |

The deltas are evidence-resolution corrections, not score inflation: every
credited target was independently re-verified against the oracle source identity,
representation, private material, and location. The additional Gitleaks/
Betterleaks filesystem credit relative to the initial estimate is the decoded
Kubernetes private key for `RNC-SL-POS-000419`, whose reported digest is the
decoded PEM with its terminal newline stripped.

### 4.3 Levain classification result

| Build | TP | Expected | Partial (uncredited) | Ordinary miss | Reconciled |
|---|---:|---:|---:|---:|---|
| `rnc-cp3` | 32 | 85 | 0 | 53 | yes |
| `rnc-cp4a` | 43 | 85 | 0 | 42 | yes |
| `rnc-cp4b` | 43 | 85 | 0 | 42 | yes |
| `gitleaks-master` | 47 | 85 | 1 | 37 | yes |
| `betterleaks-lts` | 48 | 85 | 3 | 34 | yes |
| `gl-rnc-mod-v10` | 47 | 85 | 1 | 37 | yes |

Positive-run unexpected findings are no longer added to `false_positives`;
suite-level false positives remain the verified negative-corpus count.

### 4.4 PR #15 corrective reruns

After the pre-merge hardening changes, fresh `rnclab` reports were generated for
all six registered builds:

| Build | FS TP | Git TP | Overall | Performance |
|---|---:|---:|---|---|
| `rnc-cp3` | 302/640 | N/A | COMPLETE | PASS |
| `rnc-cp4a` | 347/640 | 115/160 | COMPLETE | PASS |
| `rnc-cp4b` | 347/640 | 120/160 | COMPLETE | PASS |
| `gitleaks-master` | 369/640 | 130/160 | COMPLETE | PASS |
| `betterleaks-lts` | 438/640 | 158/160 | COMPLETE | PASS |
| `gl-rnc-mod-v10` | 369/640 | 130/160 | COMPLETE | PASS |

The corrective pass changed no credited target sets or aggregate scores. It
changed the correctness of assignment and location decisions: the adversarial
A/B case now credits both targets, repeated Kubernetes values remain ambiguous,
archive members are explicit, and Kubernetes alternatives are bounded to the
item's own document and block. All corrective reports reconcile targets and
findings.

Corrective evidence is under
`run/investigations/scoring-integrity-remediation/corrective/`, with a machine
summary at `corrective/validation-summary.json`.

## 5. Unexpected failures found during validation and their disposition

1. **Contained byte ranges were initially rejected.** RNC reports the userinfo
   component of a database URL while the oracle span is the enclosing URL. The
   value identity was exact, but strict equality rejected 33 filesystem and 10 Git
   targets. Fixed by accepting a byte range fully contained in the oracle span
   after exact value evidence; extended/overlapping ranges remain near misses.
2. **Kubernetes secret YAML location was initially over-broad.** Gitleaks/
   Betterleaks report the `kind: Secret` document line rather than the base64
   value line. The first fix accepted any earlier line for a Kubernetes rule.
   Replaced with a source-verified policy limited to the item's enclosing
   document `kind` line, its `data`/`stringData` block, its key line, or the exact
   value line; unrelated lines, fields, and documents are rejected.
3. **Nested archive member separators differed.** Betterleaks reports
   `archive!member`, while the oracle member can contain `!` before a nested path.
   Fixed by canonicalizing `!/` and `::` and by allowing a path-only report only
   for single-member gzip streams. Adapters now populate `container_member` from
   the reported path and the resolver uses it, with embedded/explicit conflicts
   rejected.
4. **Decoded Kubernetes private keys were not aliased.** Gitleaks/Betterleaks
   report the decoded PEM with its terminal newline stripped; the initial fix only
   aliased the encoded source span. Added decoded PEM aliases for Kubernetes
   representations. This produced the final 369/438 filesystem results and the
   14/28 private-key equivalence.
5. **Suite aggregation dropped the new diagnostics.** The RNC Lab JSON lane had
   the metrics but the suite-level summary did not. Fixed in
   `harness/suites/rnclab.py` and propagated through `harness/experiment.py`.
6. **The prior Levain `miss` bucket double-counted partials.** Fixed by making
   partial a distinct target bucket; `target_accounting.reconciled` is asserted.
7. **Ambiguity ranking was inverted and alias selection was first-seen.**
   `min(priority, ...)` evaluated the weakest tier while assignment used
   `-priority`; the per-item `seen_items` set kept the first digest rather than
   the strongest proof. Replaced with `EVIDENCE_STRENGTH`, an explicit
   `_candidate_rank`, strongest-proof-per-item retention, and ambiguity detection
   over the same ranking contract.
8. **Greedy assignment could lose avoidable coverage.** A finding with two valid
   targets could consume the only target of another finding. Replaced with a
   deterministic maximum-weight bipartite assignment: positive coverage first,
   total assignment second, evidence/location quality third, with forced-edge
   ambiguity checks. The adversarial A/B case now credits both targets; equal
   cycles remain `AMBIGUOUS`.
9. **Archive member identity was not end-to-end.** Added `harness/archive.py`,
   adapter population in Gitleaks/Betterleaks/RNC, explicit-versus-embedded
   consistency checks, nested-member canonicalization, and single-member gzip
   handling. RNC native reports still do not expose a separate member field; that
   remains a capability limitation, not a reason to accept enclosing ZIP/TAR
   paths.
10. **Kubernetes repeated-value ambiguity used line proximity.** When two fields
    shared the same value and the scanner reported the document `kind` line, line
    distance made the earlier field look stronger. Structured location ranks now
    treat `kind`/`data`/key alternatives equally for that document; repeated
    identical values remain genuinely ambiguous.

## 6. Evidence locations

- Corrected baseline and corrective reports:
  `run/investigations/scoring-integrity-remediation/baselines/`,
  `run/investigations/scoring-integrity-remediation/validation/`, and
  `run/investigations/scoring-integrity-remediation/corrective/`
- Corrective machine-readable summary:
  `run/investigations/scoring-integrity-remediation/corrective/validation-summary.json`
- Prior corrected summary and historical comparison:
  `run/investigations/scoring-integrity-remediation/validation-summary.json`,
  `run/investigations/scoring-integrity-remediation/corrected-historical-impact.csv`
- Prior investigation (unchanged):
  `run/investigations/scoring-integrity-20261113/`

## 7. Commit ledger

- `b2e106b` — `fix: correct scoring evidence attribution` (implementation,
  regression tests, architecture review, and remediation plan).
- `61f60da` — `docs: record scoring-integrity validation and disposition`
  (initial ledger and disposition).
- `c3e907e` — `fix: harden scoring evidence ordering and source identity`
  (pre-merge corrective implementation, archive contract, bounded Kubernetes
  location policy, adversarial calibration, and adapter coverage).
- The updated ledger and final disposition follow as the documentation checkpoint;
  see the final branch status for that SHA.

The work is on `feat/scoring-integrity-remediation`, based on
`benchmark-harness` at `1d147f9feb7b73003c46adab3ea9e780807e5cdf`.

## 8. Residual limitations

- `NO_ALERT` still cannot prove that a scanner executed a non-reporting unit;
  complete execution coverage remains a separate requirement.
- Archive member identity is strict where supplied. Native RNC units do not
  expose a separate member field; database/structured-member identity is not fully
  modelled. Enclosing ZIP/TAR paths alone never earn credit.
- Precision/F1 remain `NOT CERTIFIED` because the negative oracle is not
  exhaustive. Unmatched and unverified findings remain visible; they are not
  converted to false positives.
- Scanner capability gaps (for example, CP3 Git-history unsupported) remain
  explicit `NOT_APPLICABLE` results, not zeros.
- Some negative traps with a scanner line off by one are now `UNVERIFIED_EVIDENCE`
  rather than verified FP. This is intentional strictness: a wrong location does
  not establish negative evidence.
- Kubernetes structured location support is deliberately limited to the
  certified `kind: Secret` + `data`/`stringData` shape. Other YAML structures are
  not inferred.
