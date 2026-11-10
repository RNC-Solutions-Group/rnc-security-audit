# Execution status and CI acceptance specification

> **Design contract v0.1 — not implemented.** This is the canonical five-result model for a finalized RNC Scanner run; the wider audit orchestrator may aggregate required scanner outcomes under the same precedence after coverage reconciliation.

## Final classification

| `result_code` | `result` | Eligibility |
| --- | --- | --- |
| `1` | `CLEAN` | All required content and evidence inspected/validated; no detections, applied exemptions or verified blocks |
| `2` | `POLICY_APPLIED` | Required content/evidence completed with only **verified**, authorized blocks and/or applied exemptions; zero actionable findings |
| `3` | `ACTIONABLE` | Required inspection complete; at least one actionable finding remains, irrespective of exemptions or blocks |
| `4` | `INCOMPLETE` | Run reached a terminal point but required coverage/evidence could not be verified; findings may still exist |
| `5` | `FAILED` | Operational failure, unsafe global policy/config, fatal reporting error or interruption prevented trustworthy completion |

**Precedence:** `FAILED > INCOMPLETE > ACTIONABLE > POLICY_APPLIED > CLEAN`. These are mutually exclusive *final* outcomes, not flags to overwrite evidence. Record all concurrent lower-priority facts.

Examples:

| Facts | Final | Notes retained |
| --- | --- | --- |
| Inspected all required units, no detections or applied policies | `CLEAN` | Complete coverage, count zero |
| Two verified blocks and three exempted detections, no actionable | `POLICY_APPLIED` | Origin/IDs and exact counts retained |
| Three actionable plus one exemption | `ACTIONABLE` | Raw detections = 4; exemption remains visible |
| Three actionable plus one **inaccessible required** file | `INCOMPLETE` | Three findings remain in report; partial coverage explicit |
| Scanner crashes after emitting findings | `FAILED` | Valid partial evidence retained; never declared clean |
| CLI cancelled during a run | `FAILED` | Cause `INTERRUPTED` and partial evidence retained |

## Execution state versus coverage versus result

Keep these dimensions separate:

- **Execution state:** `COMPLETED`, `INTERRUPTED`, `ERROR`; a tool's own findings return code may still mean `COMPLETED`.
- **Coverage:** `COMPLETE`, `COMPLETE_POLICY_ADJUSTED`, `PARTIAL`, `NONE`; required unit/scanner omissions drive incomplete status. An intentional, verified policy block can yield `COMPLETE_POLICY_ADJUSTED` but can never be called full/unmodified scope.
- **Result:** one immutable five-state classification calculated *after* validation.

`READY`, `UNAVAILABLE`, `DISABLED` and `NOT_APPLICABLE` are **preflight/scanner-selection statuses**, not replacements for the five result classes. Disabled or inapplicable **optional** scanners do not cause incomplete status. An enabled **required** scanner that cannot run makes coverage partial; a planned run with zero inspected required scope is never `CLEAN`. An invalid global scope policy stops the run as `FAILED`, not `POLICY_APPLIED`.

## Deterministic classification algorithm

1. If execution/authorization/reporting suffered a fatal operational failure or was interrupted, select `FAILED`.
2. Else if any required unit, required scanner or required evidence is uninspected, missing, malformed or unverified, select `INCOMPLETE`.
3. Else if `actionable_findings > 0`, select `ACTIONABLE`.
4. Else if `applied_exemptions > 0` or `verified_applied_blocks > 0`, select `POLICY_APPLIED`.
5. Else select `CLEAN` **only** after required inspection actually occurred and is verified.

Reject contradictory inputs (for example negative counts or a detected finding without disposition) as an integrity failure; do not guess a lower-priority class. A result is assigned once upon finalization, is immutable, and includes a documented reason list.

## CI is a separate decision

The scan *always* reports its real `result_code` and name. A CLI invocation may explicitly accept completed outcomes:

```text
rnc scan . --accept-results 1,2  # result 2: process exit 0
rnc scan . --accept-results 1    # same result 2: process exit 10
```

**Approved CP0 default:** `--accept-results 1,2` (`CLEAN` and `POLICY_APPLIED`). Code `3` may be explicitly opted into for a nonblocking workflow, with that choice logged. Organizations may deliberately tighten acceptance to `1` only. In the initial contract, `INCOMPLETE` and `FAILED` **cannot** be accepted as successful scans; changing that invariant would require a separate explicit design review, not a generic CLI override.

| Situation | Proposed OS process exit | Meaning |
| --- | --- | --- |
| Final result is in configured accepted set (only `1`–`3`) | `0` | CI policy accepted the completed assessment; does **not** mean zero findings |
| Completed result `1`–`3` is not accepted | `10` | Policy/security gate rejected a completed scan |
| `INCOMPLETE` | `20` | Required evidence/coverage missing |
| `FAILED` | `30` | Operational failure |
| Invalid CLI invocation before a run starts | `64` | Usage/config invocation error; no finalized result unless a run record exists |
| Operator interrupt (`SIGINT`) | `130` | Conventional shell interruption; finalized run is `FAILED` if a run record exists |

These process codes are **proposed contract values**, subject to tests and platform review before release. They are intentionally different from report result codes `1`–`5`. An external GitHub Actions step sees any nonzero process exit as failure unless the workflow explicitly handles it; the scanner should still write the actual result report wherever safe.

### Illustrative report plus acceptance event

```json
{
  "result_code": 2,
  "result": "POLICY_APPLIED",
  "execution": "COMPLETED",
  "actionable": 0,
  "exempted": 2,
  "verified_blocked": 3
}
```

```json
{
  "accepted_result_codes": [1, 2],
  "accepted": true,
  "process_exit_code": 0
}
```

The second event does not modify the first. The reporting system may show both together, but must preserve their independence.

## Required test matrix

- Exercise each of the five outcomes with synthetic immutable input records.
- Exercise every precedence collision, especially findings + incomplete and findings + failed.
- Demonstrate requested-but-unapplied policy does not create `POLICY_APPLIED`.
- Demonstrate verified block versus inaccessible required input is distinguishable.
- Verify clean, policy-applied and actionable results against both accepting and rejecting CI policies **without changing result codes**.
- Validate nonzero exits for `INCOMPLETE`, `FAILED`, invalid invocation, and interruption.
- Prove a tool's findings-specific return code cannot be mistaken for an operational crash.
