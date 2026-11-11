# Independent harness handoff contract

**Status:** Tested adapter at CP0. External scoring engine executed against the handoff; **no external corpus was executed and no production scanner accuracy is claimed.**

- External harness: `RNC-Solutions-Group/gitleaks`, orphan branch `test/scan-harness`
- Inspected and pinned revision: `86de44bf1cb13abf9a0c375a8b91d102c9b6dc9f`
- External scoring contract schema version: `1`
- CP0 handoff version: `rnc-harness-handoff-v1`
- Reference implementation: `tools/cp0/harness_adapter.py`
- Pinned integration check: `tools/cp0/external_harness_check.py`

The earlier CP0 inventory cited revision `cf8f9153...`; the audit re-inspected the newer pinned revision above. The external harness's normalized contracts and scoring engine were used directly, not copied or reimplemented.

## Boundary

The external harness owns detection-accuracy grading. CP0 exports evidence; it does not import external scoring into the detector or rewrite the harness's truth.

| CP0 record | Handoff field(s) | Rule |
| --- | --- | --- |
| `source-unit.locator` | `file` / truth `path` | Strict canonical relative path only; never an absolute or private locator. No backslash/`./` repair. |
| `finding.line` | `line` / truth `line_start`, `line_end` | External matching is line-addressed |
| `finding.rule_id` | `rule_id` / truth `expected_rule_id` | Rule identity is preserved |
| `finding.evidence_digest` | `secret_sha256`, `match_sha256` | Digest only; no matched bytes |
| `finding.start_byte`, `end_byte` | `metadata.start_byte`, `metadata.end_byte` | Retained as richer RNC evidence |
| `finding.finding_id` | `finding_id` | Stable RNC identity |
| `execution.engine_version`, `ruleset_*` | `scanner.version`, `scanner.ruleset_*` | Provenance retained |
| `policy` dispositions | sidecar `provenance.policy` | Policy is not passed to the accuracy scorer |
| `result` / `ci` | sidecar `execution_semantics` and digests | Execution correctness and CI acceptance stay separate |

Blocked and uninspected targets become external truth items with classification `BLOCKED` and `SKIPPED`; they are not counted as missed detections. Expected synthetic findings become `EXPECTED_DETECTION` items with line ranges and expected rule IDs.

## Tested conformance

The pinned external `harness.truth.from_dict` loader and `harness.scoring_engine.score_findings` were executed on exported handoffs:

| Case | Expected | Matched | Missed | False positive | Blocked | Skipped | Status |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| synthetic-v1 perfect | 25 | 25 | 0 | 0 | 1 | 1 | COMPLETED |
| synthetic-v1 miss-one | 25 | 24 | 1 | 0 | 1 | 1 | COMPLETED |
| synthetic-v1 false-positive | 25 | 25 | 0 | 1 | 1 | 1 | COMPLETED |
| synthetic-v0 perfect | 13 | 13 | 0 | 0 | 1 | 0 | COMPLETED |

This proves the **handoff and external scoring path**, not scanner accuracy against Levain, Leaky Repo or any production code. The stub that produces the controlled findings is excluded from production builds.

## Two score lanes

The external harness already distinguishes corpus-native and normalized scoring. CP0 preserves both:

- **Corpus-native:** external corpus definitions own their counting unit, e.g. Leaky Repo's 175 upstream count units and Levain's section/credential cases.
- **RNC normalized:** line-addressed findings, byte metadata, truth item IDs, recall, false positives, misses, duplicates and execution correctness.

Do not average or combine these into one synthetic percentage. A negative-only corpus has no defensible per-line true-negative denominator; precision/F1 require an authoritative negative oracle.

## Deliberate limitations

1. The external harness scores by **file and line**, not byte range. Two same-rule findings on one line are ambiguous. The CP0 corpus was adjusted so this does not occur; CP1 must either define a line-composite adapter policy or extend the harness with byte-range matching. The handoff retains byte offsets for that extension.
2. External truth item `classification` is limited to its known set. RNC's policy dispositions remain in the sidecar; the harness does not grade policy correctness.
3. The handoff does not run external datasets. No network verification, credential validation or external upload is implied.
4. Prowlbench remains excluded pending a licensing decision.
5. The external harness branch is orphaned and independent. Never merge it into this repository; pin a commit and check it out read-only.

## Outstanding integration tasks

- [ ] Add an RNC adapter inside the independent harness (outside this repository) that consumes this handoff or CP0 canonical JSON.
- [ ] Decide whether the harness adds byte-range truth matching or keeps line identity with a documented collision rule.
- [ ] Run pinned Levain FP corpus and Leaky Repo with integrity/resource controls, preserving native and normalized scores separately.
- [ ] Record per-target execution and detection exceptions for external corpora, not only aggregate percentages.
- [ ] Obtain a licensing disposition before any Prowlbench work.
- [ ] Keep external corpus data, raw findings and private evidence outside public repository artifacts.


## CP2 same-line collision note

RNC findings are byte-addressed: a finding carries `start_byte`, `end_byte`, rule ID/version and an immutable ID. The pinned external harness is line-addressed. Two distinct RNC findings for the same rule on one line can therefore collide in the external adapter even when they are distinct events.

CP2 keeps the RNC record unchanged and validates each strategy through the external scoring engine on the current synthetic corpora. The proposed compatibility extension is an adapter-side composite key `(locator, rule_id, line, ordinal-on-line, start_byte, end_byte)` or a byte-aware harness input. Truth must not be altered to hide the collision, and the external repository is not modified without separate authorization.

No same-line collision is present in the current v0/v1 truth. This remains a documented integration limitation, not a reason to weaken byte identity or backend equivalence.
