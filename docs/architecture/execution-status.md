# Execution status and CI acceptance specification

> **Contract v0.2.0 — reference implementation validated in CP0; production scanner/reporter not implemented.** This is the canonical five-result model for a finalized RNC Scanner run. The wider audit orchestrator may aggregate required scanner outcomes under the same precedence after coverage reconciliation.

## Final classification

| `result_code` | `result` | Eligibility |
| --- | --- | --- |
| `1` | `CLEAN` | At least one required unit; all required content/evidence inspected or verified-blocked and validated; no detections, applied exemptions or verified blocks |
| `2` | `POLICY_APPLIED` | Required content/evidence completed with only **verified** authorized blocks and/or applied exemptions; zero actionable findings |
| `3` | `ACTIONABLE` | Required inspection complete; at least one actionable finding remains, irrespective of exemptions or blocks |
| `4` | `INCOMPLETE` | Run reached a terminal point but required coverage/evidence could not be verified; findings may still exist |
| `5` | `FAILED` | Operational failure, unsafe/invalid global policy, fatal reporting error or interruption prevented trustworthy completion |

**Precedence:** `FAILED > INCOMPLETE > ACTIONABLE > POLICY_APPLIED > CLEAN`. These are mutually exclusive final outcomes, not flags that overwrite evidence. Record every concurrent lower-priority fact.

A policy-approved block is a **verified absence of inspection**, not a finding disposition. A post-scan exemption still requires the original detection event to exist. Neither may be represented as the other.

## Required versus optional coverage

`source_unit.required_scope` is binding. Result counts distinguish total and required subsets:

```text
discovered           = inspected + verified_blocked + uninspected
required_discovered  = required_inspected + required_verified_blocked + required_uninspected
```

- `required_uninspected > 0` makes the result at most `INCOMPLETE`.
- An optional uninspected unit remains visible in `uninspected` but does not by itself make required coverage incomplete.
- `required_discovered == 0` is never `CLEAN`; a scan with no required scope is `INCOMPLETE` with coverage `NONE`.
- A completed result requires `evidence_valid: true`. Invalid or unverifiable required evidence is `INCOMPLETE`, never a lower-priority result.

## Execution state versus coverage versus result

Keep these dimensions separate:

- **Execution state:** `COMPLETED`, `INTERRUPTED`, `ERROR`. A findings-specific scanner return code is not an operational failure.
- **Coverage:** `COMPLETE`, `COMPLETE_POLICY_ADJUSTED`, `PARTIAL`, `NONE`, `UNVERIFIED`. This describes required-scope coverage; optional gaps do not silently upgrade it.
- **Result:** one immutable five-state classification calculated after record reconciliation and evidence validation.

`READY`, `UNAVAILABLE`, `DISABLED` and `NOT_APPLICABLE` remain preflight/scanner-selection statuses, not replacements for the five result classes. An enabled required scanner that cannot run creates a required coverage gap; a disabled optional scanner does not.

## Deterministic classification algorithm

1. If the execution state is `ERROR`/`INTERRUPTED`, `fatal_errors` is non-empty, the effective policy is invalid, or reporting/authorization failed: `FAILED`.
2. Else if `required_discovered == 0`, required coverage is uninspected/missing, or `evidence_valid` is false: `INCOMPLETE`.
3. Else if `actionable > 0`: `ACTIONABLE`.
4. Else if `verified_blocked > 0` or `exempted > 0`: `POLICY_APPLIED`.
5. Else: `CLEAN`, only after the required inspection actually occurred.

Reject contradictory records as an integrity failure rather than guessing a lower-priority class. A finalized result is immutable and carries deterministic reason codes for `INCOMPLETE`/`FAILED`.

## Final result record

The result is not just a number. It commits to the exact records that produced it:

```json
{
  "schema_version": "0.2.0",
  "run_id": "synthetic-run-001",
  "result_code": 3,
  "result": "ACTIONABLE",
  "coverage": "COMPLETE_POLICY_ADJUSTED",
  "evidence_valid": true,
  "engine_version": "reference-only",
  "ruleset_id": "synthetic-v1",
  "ruleset_digest": "sha256:<illustrative-digest>",
  "source_adapter": {"id": "local-working-tree", "version": "0.2.0"},
  "counts": {
    "discovered": 12,
    "inspected": 10,
    "verified_blocked": 2,
    "uninspected": 0,
    "required_discovered": 12,
    "required_inspected": 10,
    "required_verified_blocked": 2,
    "required_uninspected": 0,
    "detected": 5,
    "actionable": 2,
    "exempted": 3
  },
  "reason_codes": [],
  "records": {
    "execution_digest": "sha256:<digest>",
    "findings_digest": "sha256:<digest>",
    "policy_digest": "sha256:<digest>"
  }
}
```

The CI event is outside this immutable envelope and references its `result_digest`.

## CI is a separate decision

The scan always reports its real `result_code` and name. A CLI invocation may explicitly accept completed outcomes:

```text
rnc scan . --accept-results 1,2  # result 2: process exit 0
rnc scan . --accept-results 1    # same result 2: process exit 10
```

**Approved CP0 default:** `--accept-results 1,2` (`CLEAN` and `POLICY_APPLIED`). Code `3` may be explicitly opted into for a nonblocking workflow, with that choice logged. Organizations may tighten acceptance to `1` only. Under the initial contract, `INCOMPLETE` and `FAILED` **cannot** be accepted; a change would require a separate explicit design review, not a generic CLI override.

| Situation | OS process exit | Meaning |
| --- | --- | --- |
| Final result in configured accepted set (only `1`–`3`) | `0` | CI policy accepted the completed assessment; does **not** mean zero findings |
| Completed result `1`–`3` not accepted | `10` | Security gate rejected a completed scan |
| `INCOMPLETE` | `20` | Required evidence/coverage missing |
| `FAILED` | `30` | Operational failure |
| Invalid CLI invocation before a run starts | `64` | Usage/config error; no finalized result unless a run record exists |
| Operator interrupt (`SIGINT`) | `130` | Conventional shell interruption; finalized run is `FAILED` if a run exists |

These process codes are **proposed contract values**, not the report's result codes. `64` and `130` are not CI acceptance events and are not valid in `ci-decision.schema.json`.

## Evidence boundaries

- **Private records:** execution, findings and policy retain locators, reason text and evidence provenance. They are not publication-safe as-is.
- **Public records:** the finalized result and CI decision contain no locators, raw bytes or secret-shaped values. The validator's publication check is fail-closed for those records.
- **Digests are not secrets:** `evidence_digest` is the SHA-256 of matched bytes; raw bytes are never inserted into a finding.
- **Redaction failure:** if a publication check fails, the run is not published as trustworthy. This is a reporting failure, not a reason to downgrade to `CLEAN`.

## Required test matrix

CP0's validated matrix includes 28 independently declared cases across the v0.1 baseline and v0.2 expanded table:

- all five outcomes;
- every precedence collision, especially findings + incomplete and findings + failed;
- verified block versus inaccessible required input;
- optional uninspected versus required uninspected;
- invalid policy elevated to `FAILED`;
- requested-but-unapplied policy does not create `POLICY_APPLIED`;
- clean, policy-applied and actionable results under accepting and rejecting CI sets without changing result codes;
- nonzero exits for `INCOMPLETE`, `FAILED` and invalid invocation;
- a findings-specific return code cannot be mistaken for an operational crash.

The reference implementation proves these decisions; production policy/reporting remains CP2.
