# Scoring-Integrity Architecture Review

**Checkpoint:** CP-SI0
**Branch:** `feat/scoring-integrity-remediation`
**Baseline:** `benchmark-harness` at `1d147f9feb7b73003c46adab3ea9e780807e5cdf`
**Review mode:** Source-level architectural assessment; no production scoring changes in this checkpoint.

## 1. Scope and method

This review traces the complete evidence-to-report lifecycle for RNC, Gitleaks, and Betterleaks:

**Oracle truth → source verification → scanner execution → native output → adapter normalization → evidence resolution → candidate matching → attribution → classification → metrics → reporting.**

The review used:

- The source modules named in the work package.
- The retained CP3/CP4A/CP4B, Gitleaks, Betterleaks, and RNC-Mod reports.
- The read-only evidence package in `run/investigations/scoring-integrity-20261113/`.
- Targeted hash and source-span reproduction from the frozen RNC Lab corpus.
- Existing unit/integration tests, especially `test_rnclab.py`, `test_scoring.py`, `test_scoring_engine.py`, `test_history_matching.py`, and `test_adapters.py`.

The prior investigation established confirmed defects. This review treats those as evidence, not as a complete defect list, and examines adjacent contracts that could produce the same class of failure.

## 2. Current component map

| Layer | Component | Responsibility | Current boundary risk |
| --- | --- | --- | --- |
| Oracle / truth | `datasets/cache/rnc-synth-lab`, `datasets/leaky-repo.*` | Immutable source spans, identities, representations, negatives | Truth is exact-span oriented; normalized representations are not materialized as scoring aliases |
| Adapters | `harness/adapters/{rnc,gitleaks,betterleaks}.py` | Execute scanners, parse native reports, produce `NormalizedFinding` | Different evidence richness: RNC digest-only/redacted, G/B plaintext |
| Common model | `harness/contracts.py` | `NormalizedFinding`, `TruthItem`, `ScoringPolicy`, `FindingEvaluation`, `ScoringResult` | No required source-span/evidence-kind/location-stage model; optional transient text encourages asymmetric logic |
| RNC Lab evaluation | `harness/rnclab.py` | Verify lab, resolve findings, classify, compute lane metrics | Local digest index, private-key policy, truncation, no common resolver |
| Levain scoring | `harness/scoring.py`, `harness/matching.py` | Text/digest matching, partial/ambiguous/duplicate accounting | Partial is a second-class bucket mixed into miss/FP semantics; generic whitespace normalization |
| Leaky scoring | `harness/scoring_engine.py`, `harness/truth.py` | Line/value fingerprint scoring, negatives/informatives | Separate metric semantics from RNC Lab; exception and unmatched naming |
| History | `harness/history_matching.py`, `harness/history_oracle.py` | Commit ancestry, source occurrence, representation aliases | Has PEM aliases that RNC Lab lacks; separate contract |
| Experiment | `harness/experiment.py` | Orchestrates builds, suites, performance, report assembly | Concatenates suite semantics without a common reconciliation contract |
| Reporting | `harness/report.py`, `harness/reporting.py` | Markdown/JSON projections, compaction | Exception truncation and metric labels can imply completeness |
| Tests | `tests/test_*` | Unit/integration/regression | Mostly behavior-preservation; no independent calibration with predetermined outcomes for encoded/redacted evidence |

## 3. Actual evidence flow

### 3.1 RNC Lab filesystem/Git

1. `rnclab.load()` verifies the frozen manifest, oracle, corpus, Git lane, and every oracle source span.
2. Adapter parses scanner-native output into `NormalizedFinding`:
   - RNC: path, line, commit, rule, `secret_sha256`/`match_sha256` from `evidence_digest`; no `secret_text`; `secret_redacted=True`.
   - Gitleaks: path, line, commit, rule, SHA-256 of `Secret`/`Match`; transient text retained.
   - Betterleaks: equivalent to Gitleaks with its native key names.
3. `rnclab._attribute()`:
   - normalizes path;
   - builds `digest_index` from exact oracle `identity_sha256`, `span_sha256`, `public_identity_sha256`;
   - filters by path and Git ancestry;
   - `_value_evidence()` checks identity digest, then exact span only for `identity_direct`;
   - private-key policy checks `secret_text`/decoded identity;
   - assigns `used` items and duplicates;
   - emits TP/FP/informative/duplicate/unmatched/unverified outcomes.
4. Lane metrics count outcomes and item-level misses; exceptions are truncated to 250.
5. Reporting projects lane metrics and detection summaries.

### 3.2 Levain

1. Corpus sections are parsed into expected credential cases.
2. `matching.classify()` normalizes text (line endings, Unicode NFC, outer whitespace, one quote pair) and identifies complete/normalized/partial.
3. `scoring.score_positive()` assigns one finding per case, counts duplicates, puts partial cases into `missed_secrets`, and computes `match_classification`.
4. `suites/levain.py` uses negative-corpus findings for suite false positives; positive-run `false_positives` is a separate, differently scoped field.

### 3.3 Leaky Repo

1. Truth items carry path/line/value fingerprints and reviewed negative/informative classifications.
2. `scoring_engine.score_findings()` resolves paths, location, fingerprints, and one-to-one claims.
3. Metrics mix some exceptional classes under legacy names (`unexpected_count` includes unmatched findings; `unmatched_pending_review_count` includes unmapped).
4. History scoring has its own matcher and representation aliases.

## 4. Confirmed architectural defects

### A. Evidence model is not explicit

`NormalizedFinding` has digests and optional transient text but no mandatory:

- evidence kind (identity digest, source-span digest, normalized source span, decoded identity);
- verification stage/outcome;
- source-span identity separate from credential-value identity;
- container/member identity;
- verification failure reason code.

This forces each scorer to infer what a digest means. RNC and G/B produce different evidence shapes for the same oracle item, so equivalent evidence is not treated equivalently.

### B. RNC Lab rejects exact encoded source spans

`_value_evidence()` accepts an exact `span_sha256` only for `identity_direct`. For `base64_decode_text`, RNC's span digest is exact but is rejected because it is not decoded identity text. G/B text decoders bridge the gap. Confirmed 109 exact-span misses (CP3 31, CP4A 39, CP4B 39). This is a common-model/scorer defect, not a scanner miss.

### C. PEM terminal-EOL aliases are absent

The scanner hashes the complete PEM block with trailing CR/LF stripped; the oracle span includes one terminal newline. `history_matching` already defines PEM aliases, but RNC Lab does not. Confirmed 53/59 RNC PEM findings; G/B also lose 11 FS + 10 Git.

### D. Private-key evidence depends on plaintext

`private_key_material_required` requires raw text or decoded identity. RNC's redacted evidence provides neither. Three exact K8s/Base64 private-key findings are `UNVERIFIED_EVIDENCE`. The oracle already verifies the source bytes and representation; requiring scanner plaintext is an unfair evidence-format dependency.

### E. Location is not enforced in RNC Lab attribution

`_attribute()` filters by path and digest but does not require the finding line to equal the oracle occurrence line. `possible.sort()` uses line distance only as a tie-breaker. An exact credential at the wrong line in the same file can be credited as TP. Byte offsets are present in RNC metadata but unused. This violates the strict location requirement.

### F. Attribution is order-dependent

`_attribute()` iterates `findings` in input order; each finding claims the first available candidate after a local sort. Competing findings or candidates can produce different assignments if the scanner changes finding order. There is no global deterministic assignment/audit of tie-breaks.

### G. Duplicate/partial/ambiguous/unverified semantics differ by suite

- RNC Lab has explicit `MATCH_*` outcomes and `used` item tracking.
- Levain puts partials in `missed_secrets` and also reports them as `partial_matches`; `match_classification.miss` includes them, so classification totals exceed the expected count. Positive-run `false_positives` includes partials at run level, while suite FP uses the negative corpus only.
- Leaky/`scoring_engine` mixes `UNEXPECTED_FINDING` and `UNMATCHED_PENDING_REVIEW` in `unexpected_count`, and `UNMATCHED`/`UNMAPPED` in `unmatched_pending_review_count`.

There is no single, shared terminal-classification contract across suites.

### H. Near-miss visibility is absent

RNC Lab currently collapses failed positive associations into `UNMATCHED_PENDING_REVIEW` or `UNVERIFIED_EVIDENCE`. It cannot say “correct credential, truncated value,” “correct value, wrong line,” “correct value, wrong occurrence,” or “incomplete private key.” The target remains FN, but the diagnostic path is lost.

### I. Exceptions are silently truncated

`rnclab._attribute()` returns `exceptions[:250]` without a verified total/truncation flag (the compact reporter has its own limit for other shapes). Reports can imply completeness while omitting evidence. The work package requires explicit pagination/truncation.

### J. Tests preserve behavior rather than prove the scorer

Existing tests cover exact positives, duplicates, public-only private keys, path prefixes, and partial classification. They do not include a calibration matrix with predetermined outcomes for encoded/redacted evidence, PEM EOL, wrong line/offset, near misses, order-independence, or cross-scanner equivalence. The existing tests would not catch the confirmed Base64 defect.

## 5. Systemic risks

1. **Evidence asymmetry:** RNC's redacted digest-only evidence is structurally disadvantaged whenever the scorer requires plaintext for normalization.
2. **Exact-span bias:** exact oracle spans are treated as the only source of truth; authorized representation aliases are ad hoc and suite-specific.
3. **Location permissiveness:** digest-only matching can ignore line/offset mistakes and still award TP.
4. **Nondeterminism:** scanner finding order can change attribution under contention.
5. **Metric divergence:** TP/FN/FP/partial/duplicate semantics differ between Levain, Leaky, RNC Lab, and history.
6. **Hidden truncation:** diagnostic completeness is not guaranteed by the report schema.
7. **No near-miss channel:** failed detections of known positive targets are indistinguishable from unrelated noise.
8. **Adapter-specific shortcuts:** G/B text decoders and RNC structured components each compensate locally; fixes are not reusable across future scanners.

## 6. Architectural recommendations

1. **Introduce a common evidence resolver** (`harness/evidence.py`) with:
   - explicit evidence kinds: exact identity, exact source span, normalized source span, decoded identity, private-key material, public-only;
   - representation-specific alias generation;
   - source-span and location evidence separate from value evidence;
   - a controlled reason-code taxonomy and stage names.
2. **Extend `NormalizedFinding` minimally** with optional source location/container/evidence fields, preserving backward compatibility:
   - `byte_start`, `byte_end`, `container_member`, `source_span_sha256` (or equivalent);
   - transient plaintext remains optional and non-serialized.
3. **Refactor RNC Lab attribution** to:
   - use the resolver;
   - enforce line equality when oracle line is known;
   - enforce byte-range offsets when finding offsets are available;
   - perform deterministic global one-to-one assignment independent of finding order;
   - distinguish near misses from unverified/unmatched;
   - preserve private-key strictness without requiring plaintext.
4. **Align suite classification semantics**:
   - one terminal classification per finding;
   - target outcomes separate from finding outcomes;
   - partial/near-miss target remains FN;
   - false positives only from verified negative/trap truth;
   - explicit near-miss reason codes.
5. **Fix Levain accounting**:
   - `match_classification` buckets mutually exclusive;
   - `false_negatives` retains uncredited partials;
   - positive-run partials are not mislabeled as verified false positives;
   - suite FP remains negative-corpus only.
6. **Make exception reporting complete or explicitly paginated**, with total counts and truncation flags.
7. **Add an independent calibration suite** with synthetic normalized findings and predetermined outcomes, including adversarial and order-reversal cases.
8. **Add real-scanner integration checks** on the registered native builds after unit/calibration validation.

## 7. Baseline evidence and open questions

Confirmed by the prior investigation and independently rechecked:

- 109 RNC exact Base64 misses; 0 for G/B/Mod.
- 53/59 RNC PEM terminal-EOL matches; 11 FS + 10 Git for G/B.
- 3 RNC exact K8s private-key findings rejected by policy.
- Levain classification totals 86/85 and 88/85.
- Betterleaks archive member private keys remain an evidence gap.
- G/B K8s target credit via `kubernetes-secret-yaml` is a separate scanner representation, not proof that the PEM finding is correctly evaluated.

Open questions to resolve during implementation:

- Whether strict line equality reduces any current TP on real scanner reports; measure before/after.
- Whether deterministic global assignment changes any current target set; measure.
- Whether archive member evidence can be represented without a scanner-specific contract.
- Whether Levain's generic outer-whitespace normalization is too permissive for credential values; characterize with calibration cases before changing it.
- Whether Leaky/`scoring_engine` legacy metric names must be preserved for compatibility; add explicit aliases rather than breaking consumers.

## 8. Architecture decision

The remediation will use a **common evidence resolver plus suite-specific policy hooks**, not a single permissive matcher.

- Common: evidence kinds, source-span aliases, PEM/Base64/PEM-K8s resolution, stage/reason taxonomy, deterministic candidate resolution helpers.
- Suite-specific: RNC Lab's private-key oracle policy, Levain's text corpus semantics, Leaky's line/fingerprint policy, history's ancestry policy.
- No oracle values or certified fixtures change.
- No scanner plaintext exposure is required.
- No generic `.strip()` or substring rule is introduced.
