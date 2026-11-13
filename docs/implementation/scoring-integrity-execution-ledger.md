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

Final result: **330 tests run, OK, 1 skipped** (the skip is the existing
platform/capability skip, not a failed or unscored test). The final count includes
the new RNC Lab and independent calibration cases added by this package.

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

All 12 reports report `target_accounting_reconciled=true` and
`finding_accounting_reconciled=true` for both RNC Lab lanes. All performance
measurements completed with `PASS`; the RNC Lab runs are intentionally separate
from the `all` suite.

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

## 5. Unexpected failures found during validation and their disposition

1. **Contained byte ranges were initially rejected.** RNC reports the userinfo
   component of a database URL while the oracle span is the enclosing URL. The
   value identity was exact, but strict equality rejected 33 filesystem and 10 Git
   targets. Fixed by accepting a byte range fully contained in the oracle span
   after exact value evidence; extended/overlapping ranges remain near misses.
2. **Kubernetes secret YAML line was initially rejected.** Gitleaks/Betterleaks
   report the `data:` block line rather than the base64 value line. Fixed with an
   explicit structured-source line policy, valid only for Kubernetes
   representations after value evidence.
3. **Nested archive member separators differed.** Betterleaks reports
   `archive!member`, while the oracle member can contain `!` before a nested path.
   Fixed by canonicalizing `!/` and `::` and by allowing a path-only report only
   for single-member gzip streams.
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

## 6. Evidence locations

- Corrected reports and console logs:
  `run/investigations/scoring-integrity-remediation/baselines/` and
  `run/investigations/scoring-integrity-remediation/validation/`
- Machine-readable summary:
  `run/investigations/scoring-integrity-remediation/validation-summary.json`
- Flat summary:
  `run/investigations/scoring-integrity-remediation/validation-summary.csv`
- Corrected historical comparison:
  `run/investigations/scoring-integrity-remediation/corrected-historical-impact.csv`
- Prior investigation (unchanged):
  `run/investigations/scoring-integrity-20261113/`

## 7. Commit ledger

- `b2e106b` — `fix: correct scoring evidence attribution` (implementation,
  regression tests, architecture review, and remediation plan).
- Documentation checkpoint for this ledger and the final disposition follows the
  code commit; see the final branch status for the documentation SHA.

The code commit was made on `feat/scoring-integrity-remediation`, based on
`benchmark-harness` at `1d147f9feb7b73003c46adab3ea9e780807e5cdf`.

## 8. Residual limitations

- `NO_ALERT` still cannot prove that a scanner executed a non-reporting unit;
  complete execution coverage remains a separate requirement.
- Database/structured container member identity is not fully modelled; archive
  members are strict where the scanner reports them.
- Precision/F1 remain `NOT CERTIFIED` because the negative oracle is not
  exhaustive. Unmatched and unverified findings remain visible; they are not
  converted to false positives.
- Scanner capability gaps (for example, CP3 Git-history unsupported) remain
  explicit `NOT_APPLICABLE` results, not zeros.
- Some negative traps with a scanner line off by one are now `UNVERIFIED_EVIDENCE`
  rather than verified FP. This is intentional strictness: a wrong location does
  not establish negative evidence.
