# Normalized scoring contract

**Checkpoint:** CP3

**Schema version:** 1

The adapter/scorer/reporter boundary is deliberately narrow: adapters produce
normalized findings, truth manifests describe expected findings, the scoring
engine produces normalized evaluations, and reporters render them. The scoring
engine has no scanner parser, executable, rule, output-format, performance, or
report-formatting dependency, and it does not identify which scanner produced a
finding. Scanner-specific behavior stays in the adapter; benchmark expectations
stay in truth; experiment reporting stays above both.

Gitleaks and Betterleaks both feed the same engine. There are no scanner-specific
matching exceptions and no truth changes that favor one scanner. A scanner may
miss many expected items while the scorer is fully correct; scoring-engine
accuracy and scanner detection accuracy are separate claims. The harness scores
one registered scanner artifact per invocation; comparisons across reports are external
to the harness.

## Normalized finding

Defined in [`harness/contracts.py`](../harness/contracts.py).

| Field | Required | Meaning |
| --- | --- | --- |
| `file` | yes | Portable path; absolute paths may be resolved against truth paths |
| `line` | no | Start line or location |
| `rule_id` | yes | Scanner rule/category identifier |
| `secret_sha256` | no | Safe fingerprint of matched evidence |
| `match_sha256` | no | Safe fingerprint of match context |
| `secret_redacted` | no | Whether the scanner redacted the value |
| `finding_id` | no | Scanner/result-local ID, if supplied |
| `target` | no | Product/target identity |
| `scanner`, `scanner_version` | no | Scanner identity |
| `commit` | no | Commit identity for Git-history findings |
| `metadata` | no | Optional scanner-specific metadata; never controls core scoring |
| `secret_text`, `match_text` | transient | Exact matching context, excluded from `repr` and serialization |

The `safe_dict()` projection never emits `secret_text`, `match_text`, or raw
matched values.

## Truth item and manifest

| Field | Meaning |
| --- | --- |
| `finding_id` | Stable expected-item identity |
| `dataset_id`, `dataset_version` | Dataset identity |
| `path`, `line_start`, `line_end` | Expected location |
| `commit` | Expected commit identity for history occurrences |
| `classification` | `EXPECTED_DETECTION`, `SKIPPED`, `NOT_APPLICABLE`, or `BLOCKED` |
| `category`, `risk_bearing` | Dataset category and designation |
| `fingerprint_sha256` | Safe deterministic identity |
| `source_reference` | Upstream/source evidence for the item |
| `matching_policy` | `line_range`, `file`, or dataset-specific policy |
| `expected_rule_id` | Optional classification constraint |
| `category_conflict` | Upstream aggregate vs source-line category divergence |

A manifest carries `manifest_id`, `manifest_version`, `dataset_id`,
`dataset_version`, scoring policy, counts, category reconciliation, and integrity
state. `harness/truth.py` loads/validates structure; `harness/leaky_truth.py`
validates Leaky Repo lines and fingerprints.

## Scoring classifications

- `EXPECTED_DETECTION`
- `MISSED_EXPECTATION`
- `UNEXPECTED_FINDING`
- `FALSE_POSITIVE` (only with an authoritative negative oracle)
- `PARTIAL_MATCH`
- `DUPLICATE`
- `AMBIGUOUS_MATCH`
- `UNMAPPED`
- `SKIPPED`
- `NOT_APPLICABLE`
- `BLOCKED`
- `EXECUTION_ERROR`

`FALSE_POSITIVE` is never inferred merely because an expected count is exceeded.

## Identity confidence

A truth item may carry `metadata.value_fingerprints` (safe SHA-256 values, never
raw credentials) and `metadata.requires_value`. A finding matches a candidate only
when its file/line/commit/classification constraints and any required value
fingerprint agree. Matches report:

- `identity_confidence="value"` when a safe value fingerprint agreed;
- `identity_confidence="line"` only when the applicable truth policy explicitly
  authorizes line-only credit and the item has no value oracle.

A location match without a value fingerprint is `UNVERIFIED_EVIDENCE` by default;
it is never an automatic TP. `ScoringPolicy.allow_line_only` must be set
explicitly for a dataset whose truth intentionally has no value identity.
PEM/private-key lines without a reliable value token remain explicitly line-only
where such a policy applies. Redacted scanner output cannot satisfy
`requires_value`.

Every observed finding produces exactly one evaluation. The metrics
`observed_count`, `accounted_observed_count`, and
`finding_accounting_reconciled` make silent drops visible. Unmatched, unverified,
ambiguous, partial, unmapped and unexpected observations remain in the exception
ledger. `FALSE_POSITIVE` requires a validated reviewed-negative value, not merely
an absence from the positive manifest.

## Target-driven capabilities

Operators select one registered build and benchmark suites/products. Leaky Repo
always evaluates filesystem capability and automatically evaluates Git history
when the artifact declares Git mode. Unsupported scanner capability is
`NOT_APPLICABLE` with a reason; it is not zero recall. When execution is supported
but independent truth is unavailable, the dimension is executed and marked
`COMPLETED_UNSCORED` rather than omitted. Actual execution failure remains
`FAILED` or `BLOCKED`, never capability absence.

## Configuration profiles

DEFAULT uses the registered scanner defaults (for RNC, the operator-provided
`rules_file`) and cannot accept an external experiment configuration. CUSTOM
requires an explicit configuration and records its path and SHA-256.
Controlled synthetic fixtures use a separately labeled `CONTROLLED_FIXTURE`
configuration and are excluded from default-baseline metrics. CUSTOM results are
also excluded from default-baseline metrics.

## Detection reporting responsibility

The experiment reports one registered artifact across one or more execution products.
It does not execute multiple scanners as one scoring transaction, score one
scanner against another, or infer superiority from separate reports. Those
comparisons belong to external orchestration and reporting.

## Rich-scoring readiness

A completed legacy score does **not** imply a valid rich score. If the truth
manifest is missing/invalid or scoring raises, the lane `rich_status` is
`NOT_READY` or `BLOCKED`; findings and the legacy count result remain in the
report, and the filesystem dimension is `COMPLETED_UNSCORED`. This is not an
execution failure and does not invent a denominator. Scanner execution status,
legacy count status, and rich scoring status remain separate.

The Leaky Repo dataset ships its validated line-level truth manifest; an actual
absence of that manifest is reported as an unscored observation, not as a scanner
miss.

## Git-history occurrences versus unique credentials

History truth items are occurrences with `commit`, path, line, stable finding ID,
and `metadata.unique_secret_id`. The scoring engine matches one occurrence to one
finding. Reports additionally group matched occurrences by `unique_secret_id` to
compute unique-credential recall. A credential repeated across commits is one
unique secret and multiple occurrences. The filesystem 175-item denominator is
never applied to history.

## Execution versus detection quality

`ScoringResult.execution_status` records whether execution happened;
`scoring_status` records whether truth/scoring was possible. A benchmark can
complete successfully while missing expected findings. `NOT_READY` is used when
the truth manifest is invalid; `BLOCKED`/`EXECUTION_ERROR` when execution could
not produce findings.

## Metrics

The engine reports expected, matched, missed, unexpected, false-positive, partial,
duplicate, ambiguous, unmapped, skipped, not-applicable, blocked, and execution-error
counts, plus `unmatched_pending_review_count`, `unverified_evidence_count`,
`informative_match_count`, `verified_false_positive_count`, and the observed/
accounted reconciliation fields. `detection_recall_percent` is computed over
expected items. `precision_percent`/`f1_percent` are only computed with a reviewed
negative oracle, no pending adjudications and no informative alerts; otherwise they
are `null` and `precision_certification_status` records why.

History additionally reports occurrence and unique-group denominators,
category-specific occurrence and unique recall, duplicates, informative hits,
reviewed negatives, unmatched/unverified alerts, and representation counts. Leaky
Repo reports rich line-level filesystem detection only; it has no exhaustive
negative oracle. Its upstream count score is labeled **LEGACY COUNT COVERAGE** and
is not a substitute for verified recall.

## Reproducibility fields

Reports record the registered build ID, local artifact-manifest path and SHA-256,
operator-supplied source-commit metadata, executable SHA-256 or image ID, dataset
revision, inventory and truth-manifest hashes, manifest version, scoring policy
version, product platform, execution method, image architecture, and whether
Docker ARM64 was emulated. The verified artifact identity is the runtime identity;
source-commit metadata is not a substitute for it.

## Strict report validation

A valid empty scanner report (`[]`, or Betterleaks `null`) is a legitimate
zero-finding result. Missing, empty-byte, malformed, truncated, schema-incompatible,
or entry-invalid reports are `REPORT_MISSING`/`REPORT_INVALID` execution failures.
Parser failure is never converted into zero findings.

## Boundary tests

[`tests/test_architecture.py`](../tests/test_architecture.py) fails if the scoring
engine imports scanner parsers/adapters, if suites import scanner parsers, if
performance imports scoring, if generic orchestration/reporting mentions a
scanner, or if removed cross-scanner comparison modules reappear. Performance
telemetry and report formatting never feed the scoring engine.

## Approved Leaky Repo Git-history source oracle (integrated)

**Canonical owner truth:** [`datasets/leaky-repo.history-oracle.json`](../datasets/leaky-repo.history-oracle.json). Scope is the pinned 25-commit Git history. Primary denominator: **65 introduced/modified credential occurrences and 53 unique credential groups**. Owner-approved supplemental references: 89 NEGATIVE, 30 INFORMATIVE, 0 LINEAGE_ONLY (LH-0170 is informative rename lineage). These are **not** the 175 filesystem expected detection items. CP10 applied the approved 184/89 migration; there is no accepted 181/86 fallback.

The source oracle is integrated through `harness/history_oracle.py` and
`harness/history_matching.py`; the Leaky Repo suite runs it automatically for
Git-capable adapters. The loader validates the 184 rows, owner decisions, policy,
source blob identities and digest-to-source evidence before scoring. The matcher
is scanner-independent and enforces commit ancestry, source-representation
presence, path/line identity and validated typed value identity.

**Mandatory unmatched investigation:** the normalized scorer emits
`UNMATCHED_PENDING_REVIEW` for unmatched source locations and
`UNVERIFIED_EVIDENCE` where a credential location exists but required value
identity does not match. A reviewed non-secret earns `FALSE_POSITIVE` only when its
approved source/value evidence is validated. These states are present in the
exceptions and safe evaluations, and precision/F1 remain blocked while pending
findings exist. Every finding remains represented in the result or an auditable
exception queue.

**Credential scoring:** one TP per owner-approved source occurrence per scanner/run;
separate placements are independent; repeated observations from later snapshots
map to the introduction occurrence and are duplicates, not new occurrences; rename
lineage adds none. Commit ancestry and source/value history are validated before
linking a later observation. Unique positive groups are counted separately.

**Typed evidence:** full PEM blocks may differ by a terminal newline; encoded
Docker, FileZilla and JetBrains representations require validated source
attribution; MongoDB URI findings must show the password component or the complete
validated URI. No scanner-specific truth exceptions or broad substring credit are
used. Redaction and evidence-confidence states are preserved.

Category-wise reporting reconciles expected, detected, missed, duplicates,
informative hits, reviewed negatives and unmatched/unverified alerts. Informative
references earn no primary recall. History precision/F1 remain **NOT CERTIFIED**
because the 89 reviewed negatives are explicitly not exhaustive
(`BLOCKED_INCOMPLETE_NEGATIVE_ORACLE`).

The existing Leaky Repo filesystem manifest still has 175 `EXPECTED_DETECTION` items, categorized 88 risk and 87 informative, with `negative_oracle=false`.
