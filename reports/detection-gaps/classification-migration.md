# Detection-gap classification migration (analysis 1.0.0 to 2.0.0)

This migration changes only derived attribution in
`reports/detection-gaps/`. It does not change any expected target ID, credited
target, missed target, benchmark score, unique-group count, oracle, frozen dataset,
scanner rule, or scoring policy.

## Why the classification changed

Analysis 1.0.0 marked every uncredited archive member, database record and binary
key container as `SOURCE_UNSUPPORTED` / `CONFIRMED` solely because no target in
that container class received detection credit. That is an invalid causal
inference. Absence of a finding is not proof that a container was not inspected.

Analysis 2.0.0 separates:

1. source capability (`CLAIMED_SUPPORTED`, `DECLARED_UNSUPPORTED`, `NOT_DECLARED`);
2. inspection evidence (`INSPECTED_VERIFIED`, `NOT_INSPECTED_VERIFIED`,
   `INSPECTION_UNVERIFIED`, `UNSUPPORTED_VERIFIED`, `NOT_APPLICABLE`);
3. detection outcome (credited or missed).

Container misses without member/record-level evidence now use
`SOURCE_INSPECTION_UNVERIFIED` / `UNRESOLVED`. `SOURCE_UNSUPPORTED` / `CONFIRMED`
is reserved for a validated capability declaration or a source-unit probe that
proves the type unsupported.

## Before/after totals

| Scanner | Before confirmed / probable / unresolved | After confirmed / probable / unresolved | Before `SOURCE_UNSUPPORTED` | After `SOURCE_UNSUPPORTED` | After `SOURCE_INSPECTION_UNVERIFIED` |
| --- | --- | --- | ---: | ---: | ---: |
| RNC Scanner CP4C | 419 / 124 / 12 | 333 / 184 / 38 | 26 confirmed | 0 | 26 |
| RNC-Mod V14 | 123 / 380 / 31 | 86 / 391 / 57 | 26 confirmed | 0 | 26 |
| RNC-Mod V16 | 123 / 379 / 31 | 86 / 390 / 57 | 26 confirmed | 0 | 26 |

The 26 container targets remain identified by the same target IDs. They are not
removed, hidden, or converted into scored detections.

## Inspection-state migration

| Scanner | Before states | After states |
| --- | --- | --- |
| CP4C | 529 `INSPECTED`, 26 `UNSUPPORTED_CONTAINER` | 346 `INSPECTED_VERIFIED`, 209 `INSPECTION_UNVERIFIED`, 0 `UNSUPPORTED_VERIFIED` |
| V14 | 428 `INSPECTED`, 80 `INSPECTED_UNVERIFIED`, 26 `UNSUPPORTED_CONTAINER` | 0 `INSPECTED_VERIFIED`, 534 `INSPECTION_UNVERIFIED`, 0 `UNSUPPORTED_VERIFIED` |
| V16 | 428 `INSPECTED`, 79 `INSPECTED_UNVERIFIED`, 26 `UNSUPPORTED_CONTAINER` | 0 `INSPECTED_VERIFIED`, 533 `INSPECTION_UNVERIFIED`, 0 `UNSUPPORTED_VERIFIED` |

The previous `INSPECTED` label on ordinary files was often unsupported by the
retained report. For external adapters, a completed process is not a per-file
coverage attestation. Those misses are now `INSPECTION_UNVERIFIED`, and any
`CONFIRMED` detection hypothesis is downgraded to `PROBABLE`.

CP4C retains `INSPECTED_VERIFIED` only where it has scanner-native coverage
(principally the RNC Lab filesystem lane outside the reported symlink aliases).
V14/V16 reports do not contain equivalent per-unit proof.

## Score invariance

| Scanner | Matched before | Matched after | Missed after | Risk-bearing recall after |
| --- | ---: | ---: | ---: | ---: |
| CP4C | 570 | 570 | 555 | 54.91% |
| V14 | 591 | 591 | 534 | 56.84% |
| V16 | 592 | 592 | 533 | 56.94% |

All target IDs, unique-group accounting, oracle references and report metrics
reconcile. `oracle_or_scoring_changed` remains `false`.

## Development-priority consequences

- The confirmed "container unsupported" claim is withdrawn. The actionable next
  step is to obtain source-unit evidence (member/record identity or a validated
  capability contract), not to assert that the scanner skipped the container.
- The 26 container targets remain visible in the backlog as
  `container_inspection_evidence` at low/medium priority.
- Confirmed detection hypotheses that survive source verification remain
  prioritized. In particular, CP4C's WordPress identifier gap, positional/encoded
  password representations, HMAC/signing identifier family and application
  passwords remain evidence-supported where the source lane is verified.
- V14/V16 detection findings become predominantly `PROBABLE` because their
  retained reports do not prove per-unit inspection. This is an evidence
  limitation, not a scanner regression.

## Reproducibility

The migration is derived from the same pinned report hashes in
[`analysis-inputs.json`](analysis-inputs.json). Analysis 2.0.0 substantive files
are deterministic for that lock; `analysis-run.json` and `publication.json` are
volatile metadata.
