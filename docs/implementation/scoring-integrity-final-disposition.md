# Scoring-Integrity Final Disposition

**Package:** RNC Benchmark Harness scoring-integrity remediation  
**Branch:** `feat/scoring-integrity-remediation`  
**Baseline:** `benchmark-harness` at `1d147f9feb7b73003c46adab3ea9e780807e5cdf`  
**Decision date:** 2026-11-13  
**Decision:** **CONDITIONAL GO** for using the corrected harness to produce new
RNC Lab and Levain comparisons. **NO-GO** for publishing the historical scores as
if they were produced by the corrected scorer, and **NO-GO** for certifying
precision/F1 from the current negative oracle.

The package did not merge its PR and did not modify any scanner, executable,
oracle, fixture, corpus, historical report, or `run/manifest.toml`.

## 1. Executive conclusion

The confirmed scoring-integrity defects are fixed and independently calibrated.
The corrected harness now credits equivalent, independently verified evidence
equivalently: exact Base64 source spans, PEM terminal-newline variations, and
Kubernetes Base64 private keys all reach the same target outcome as their exact
plaintext equivalents. Attribution is deterministic and one-to-one, wrong
locations are not true positives, partial/ambiguous findings are not verified
false positives, and every observed finding has a terminal classification or an
explicit exception-ledger entry.

The strongest fairness evidence is the private-key result:

| Build | Filesystem private keys | Git private keys |
|---|---:|---:|
| `rnc-cp4b` | 14/28 | 10/10 |
| `gitleaks-master` | 14/28 | 10/10 |
| `betterleaks-lts` | 14/28 | 10/10 |
| `gl-rnc-mod-v10` | 14/28 | 10/10 |

All four scanners now receive identical private-key credit on the certified
filesystem and Git oracles. Before remediation, RNC received 0/28 filesystem
private keys and the other scanners received 2/28.

The corrected RNC Lab filesystem/Git results are:

| Build | Filesystem | Git |
|---|---:|---:|
| `rnc-cp3` | 302/640 (47.19%) | N/A |
| `rnc-cp4a` | 347/640 (54.22%) | 115/160 (71.88%) |
| `rnc-cp4b` | 347/640 (54.22%) | 120/160 (75.00%) |
| `gitleaks-master` | 369/640 (57.66%) | 130/160 (81.25%) |
| `betterleaks-lts` | 438/640 (68.44%) | 158/160 (98.75%) |
| `gl-rnc-mod-v10` | 369/640 (57.66%) | 130/160 (81.25%) |

These are corrected **measurements under the existing corpus and methodology**,
not a change to the oracle or to scanner behavior. The deltas are concentrated in
the previously mis-scored Base64 and private-key representations.

## 1a. PR #15 pre-merge corrective disposition

| Finding | Diagnosis | Corrective action | Regression evidence | Status |
|---|---|---|---|---|
| Evidence priority and alias selection | **Confirmed** — ambiguity used `min(priority, ...)` while assignment used `-priority`; per-item aliases were retained by first digest encounter. | Added `EVIDENCE_STRENGTH`, one `_candidate_rank`, strongest-proof-per-item retention, and ambiguity checks over the same rank. | `test_stronger_identity_alias_survives_digest_order`, `test_unique_stronger_evidence_is_not_ambiguous`, candidate-order tests. | **RESOLVED** |
| Global one-to-one attribution | **Confirmed** — greedy assignment could consume a target needed by a later finding (A→1/2, B→1). | Replaced with deterministic maximum-weight bipartite assignment: positive coverage, total assignment, evidence/location quality; forced-edge ambiguity checks. | `test_shared_target_does_not_create_avoidable_false_negative`, full synthetic A/B integration, equal-cycle ambiguity test, order invariance. | **RESOLVED** |
| Archive-member identity end-to-end | **Confirmed as a contract gap** — `container_member` was not populated by adapters and only filename parsing was used. | Added canonical `harness/archive.py`; Gitleaks/Betterleaks/RNC populate the field; resolver requires explicit/embedded agreement; nested members canonicalized; ZIP/TAR path-only rejected; gzip single-member permitted. | Adapter tests, explicit/embedded/wrong/missing/conflict/nested/gzip/identical-member tests. | **RESOLVED WITH RNC CAPABILITY LIMITATION** |
| Kubernetes location policy | **Confirmed** — any earlier line was accepted for recognized rule names. | Source-verified YAML document/kind/data-block/key policy with bounded ranks; unrelated lines, fields, and documents rejected. | Kind/data/key acceptance, unrelated line/field/document, wrong digest, multiple credentials, repeated-value ambiguity, synthetic multi-document test. | **RESOLVED** |

Additional directly related defect: **Kubernetes repeated values were separated by
line distance**, making an earlier field look stronger when both were reported at
the document `kind` line. Structured location ranks now make those alternatives
equal, so repeated identical values remain genuinely ambiguous rather than being
credited to the lexicographically or positionally first field.

The corrective reruns produced the same target sets and aggregate scores as the
validated baseline, which is expected: the corrections close latent attribution
paths rather than manufacturing new detections.

## 2. Defect disposition

| ID | Defect | Disposition | Evidence |
|---|---|---|---|
| SI-01 | RNC exact Base64 source-span misses (109) | **RESOLVED** | Exact span accepted for every normalization; RNC CP4B FS 297→347 |
| SI-02 | PEM terminal-EOL false negatives (RNC 53/59; G/B 11 FS + 10 Git) | **RESOLVED** | Conservative complete-PEM CR/LF aliases; private keys 14/28 all scanners |
| SI-03 | Kubernetes/Base64 private key rejected by raw-text policy | **RESOLVED** | Oracle span decoded and validated; Git 10/10 all scanners |
| SI-04 | Levain partial included in `miss` and positive-run FP | **RESOLVED** | Partial is a distinct uncredited bucket; target accounting reconciles |
| SI-05 | Exception ledger silently truncated at 250 | **RESOLVED** | `exception_count` covers all entries; `exceptions_truncated` explicit |
| SI-06 | Archive member not strict | **RESOLVED WITH RNC CAPABILITY LIMITATION** | Shared canonical contract, adapter population, explicit/embedded agreement, nested/gzip policy; native RNC units still expose no separate member |
| SI-07 | RNC Kubernetes private key + public-only ambiguity | **RESOLVED** | Public-only rejected; decoded K8s PEM credited; 14/28 all scanners |
| SI-08 | Order-dependent, proximity-ranked attribution | **RESOLVED** | Maximum-weight one-to-one matching, stable keys, forced-edge ambiguity checks, order tests |
| SI-09 | Near-miss / unverified / ambiguous diagnostics absent | **RESOLVED** | Classification, reason codes, stages, evidence kinds, calibration |
| SI-10 | Suite/readable reports dropped new RNC diagnostics | **RESOLVED** | Aggregation and detection-summary propagation fixed |
| SI-11 | Cross-suite finding/target accounting ambiguous | **RESOLVED** | Explicit target/finding accounting and reconciliation booleans |

SI-06 is conditional only at the source-capability boundary. Archive member
identity is enforced when the scanner supplies it, an explicit field must agree
with an embedded path, nested members are canonicalized, and a path-only report
is accepted only for a single-member gzip stream. Native RNC units do not expose
a separate member field, so RNC cannot claim ZIP/TAR member identity; that is an
explicit capability limitation, not an implicit credit path. Database/table/row
identity remains a documented model limitation.

## 3. Acceptance criteria

| Criterion | Result | Basis |
|---|---|---|
| Equivalent verified evidence receives equivalent credit | PASS | Private-key 14/28 and 10/10 across all four scanners |
| Incorrect evidence cannot earn TP | PASS | Calibration: public-only, wrong key, incomplete PEM, wrong location, unrelated value |
| Matching is not weakened to increase recall | PASS | No generic strip; only representation-specific complete-PEM/decoded-K8s aliases |
| Attribution is deterministic and one-to-one | PASS | Maximum-weight matching; forced-edge ambiguity checks; finding/oracle-order tests |
| Every observed finding is accounted for | PASS | `finding_accounting_reconciled=true` in all baseline and corrective reports |
| Every expected target is TP or FN | PASS | `target_accounting_reconciled=true` in all baseline and corrective reports |
| Near misses are visible without becoming TP/FP | PASS | `NEAR_MISS` reason codes; calibration includes line/offset/truncation/source mismatch |
| FP only from verified negative evidence | PASS | Unmatched/unverified/partial/ambiguous excluded from verified FP |
| Partial remains uncredited | PASS | Partial is an FN bucket; Levain target accounting passes |
| Truncation is explicit | PASS | `exceptions_truncated`; 250-row display cap documented |
| Independent calibration | PASS | `tests/test_scoring_calibration.py`, 43 predetermined cases |
| Real-scanner validation | PASS | 18 fresh runs (12 baseline + 6 corrective) across six registered builds |
| Historical reports unchanged | PASS | No historical report or score was edited |
| No raw secrets in committed artifacts | PASS | Raw evidence remains in Git-ignored `run/`; exports are hashes/diagnostics |

## 4. Validation evidence

- Full regression: `python -m unittest discover -s tests -t .`
  - **354 tests run, OK, 1 skipped**.
  - The skip is an existing platform/capability skip; no test was reported as
    passed without execution.
- Calibration suite: 43 predetermined cases, including Base64, PEM LF/CRLF,
  Kubernetes decoded private key, public-only rejection, wrong line, wrong byte
  offset, truncated value, unrelated same-line value, duplicate, order invariance,
  archive-member contracts, bounded Kubernetes locations, repeated-value
  ambiguity, and accounting.
- Fresh scanner reports: six builds × (`all`, `rnclab`) = 12 baseline runs plus six
  corrective `rnclab` reruns, native Windows AMD64, `--warmups 2 --runs 5
  --benchmark-environment DEV --offline`.
- All 18 reports are `COMPLETE` or `COMPLETE_WITH_LIMITATIONS`; no artifact was
  substituted and no historical report was used. The six corrective reruns did
  not change credited target sets or scores.

Evidence paths (Git-ignored, not committed):

- `run/investigations/scoring-integrity-remediation/validation-summary.json`
- `run/investigations/scoring-integrity-remediation/validation-summary.csv`
- `run/investigations/scoring-integrity-remediation/corrected-historical-impact.csv`
- `run/investigations/scoring-integrity-remediation/baselines/`
- `run/investigations/scoring-integrity-remediation/validation/`
- `run/investigations/scoring-integrity-remediation/corrective/`
- `run/investigations/scoring-integrity-remediation/corrective/validation-summary.json`
- Prior investigation, unchanged:
  `run/investigations/scoring-integrity-20261113/`

## 5. Conditions attached to the GO

1. **Use corrected reports for new comparisons.** The historical reports remain
   valid only as historical artifacts. Do not compare a historical score to a
   corrected score without labeling the scoring revision.
2. **Do not certify precision/F1.** The negative oracle is not exhaustive; the
   harness correctly reports `NOT CERTIFIED`. Verified FP counts may be published;
   precision/F1 may not.
3. **Keep unresolved findings visible.** Unverified, pending-review, ambiguous,
   and near-miss findings must remain in the report. They must not be collapsed
   into false positives or silently dropped.
4. **Respect capability gaps.** CP3 Git-history is `NOT_APPLICABLE`; unsupported
   private-key formats remain scanner coverage limitations, not scoring passes.
5. **Do not re-open source identity through filenames.** Archive members require
   a canonical explicit or embedded identity; ZIP/TAR path-only reports are
   unverified. Native RNC units do not expose a separate member field, so RNC
   cannot claim ZIP/TAR member identity. Database/structured-member identity
   remains a known model limitation.
6. **Preserve the no-merge boundary.** This package prepares a PR against
   `benchmark-harness`; the operator retains merge authority.

## 6. Remaining limitations and risks

- **Execution completeness:** `NO_ALERT` cannot prove a scanner executed a
  non-reporting unit. Complete execution coverage remains separate from scoring.
- **Negative oracle:** the certified corpus is not an exhaustive negative oracle;
  unmatched findings remain pending. This is why precision/F1 are not certified.
- **Archive capability:** Gitleaks/Betterleaks path-embedded members are carried
  explicitly and validated; RNC native units expose no separate member. Database/
  table/row identity is not fully represented in the normalized finding contract.
- **Kubernetes scope:** structured location support is limited to the certified
  `kind: Secret` + `data`/`stringData` shape. Other YAML structures are not
  inferred.
- **Scanner coverage:** the 14/28 filesystem private-key ceiling is shared by all
  scanners and reflects formats not reported as complete private material (for
  example PPK/PKCS#12 or archive-embedded keys), not a harness credit rule.
- **Wrong-line negatives:** some negative traps reported one line off are now
  `UNVERIFIED_EVIDENCE` rather than verified FP. This is intentional: a wrong
  location does not establish negative evidence.
- **Genuine ambiguity:** when multiple verified assignments remain equally
  optimal, the finding is `AMBIGUOUS` and the targets remain FN. The harness does
  not choose a lexicographic or positional winner.
- **Legacy metric names:** `scoring_engine` retains compatibility names while
  adding explicit `unmatched_only_count`, `unexpected_observation_count`, and
  accounting. Consumers should prefer the explicit fields.
- **G/B text evidence:** retained reports do not serialize scanner text; live
  validation was used for the final Gitleaks/Betterleaks results. Offline
  re-scoring of old reports can therefore be lower than the live result.

## 7. PR and branch status

- Branch: `feat/scoring-integrity-remediation`
- PR target: `benchmark-harness`
- PR state: prepared for operator review; **not merged**
- No source, executable, oracle, fixture, corpus, or manifest changes are included.
- The local `AGENTS.md` is unchanged.

## 8. Final recommendation

**CONDITIONAL GO.** The corrected harness is suitable for producing new RNC Lab
and Levain/Leaky comparisons, including CP4C evaluation, provided the corrected
reports are used, precision/F1 remain uncertified, and the residual limitations
above are carried into the publication notes. It is not a GO for rewriting
historical scores or for claiming complete container/negative-oracle coverage.
