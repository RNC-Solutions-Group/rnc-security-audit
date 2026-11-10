# Reporting and accounting specification

> **Design contract v0.2 — not implemented.** Reporting consumes evidence and policy records; it does not perform detection or silently correct suspicious outputs. The CP0 reference reconciler proves interface integrity only; the production reporter belongs to CP2.

## Three independently testable records

| Record | Required contents | Owner |
| --- | --- | --- |
| **Execution** | Run ID, target/source manifest, adapter/backend identity, selected and required scope, units discovered/blocked/inspected/unavailable, timings, failures, evidence validation, fingerprints | Adapter, preflight and runner |
| **Detection** | Every engine event, stable finding ID, rule/version, source and location references, confidence signals, validation, raw evidence linkage | RNC detection engine |
| **Policy** | Effective config with provenance, verified block register, per-finding disposition, requested vs applied exclusions/exemptions, conflicts and authorizations | Policy modules |

The **reporting module** verifies and reconciles these records, computes a finalized five-way result under [execution-status.md](execution-status.md), and emits approved reports. The **CI decision** is then appended as a separate enforcement record (`accepted`, configured acceptable codes, process exit code). CI acceptance cannot revise the already-finalized scan result.

Treat raw records as append-only logical evidence. Corrections require a new revision with explicit parent/reference and reason; no silent overwrites. Run IDs, schema versions, digests, and tool versions make reports traceable.

## Accounting invariants

- `discovered_units = inspected_units + verified_blocked_units + uninspected_units` for a **disjoint, normalized** target manifest. A source with mixed statuses must be split into unambiguous units before aggregation.
- Required-scope counts are a subset with the same equation. An optional uninspected unit remains visible but does not make required coverage incomplete.
- `detected_findings = actionable_findings + exempted_findings` for the initial two-disposition model; no event may disappear or be double-counted. Deduplication occurs at a documented detection-event boundary **before** disposition.
- A policy request that matches nothing is recorded as **requested, not applied**. It does not create `POLICY_APPLIED`.
- Missing required targets, unvalidated evidence, unsupported block enforcement, invalid policy and unavailable required scanners remain explicit omissions. They are never interpreted as zero findings.
- Per-rule, per-target and aggregate counts must reconcile to the same canonical event IDs. Reports may summarize but not silently mutate them.
- No completed result may be published as trustworthy if the reporting/redaction integrity check fails; the operational failure is disclosed without leaking raw evidence.
- The finalized result commits to canonical digests of the execution, ordered finding array and policy record. The CI decision commits to the exact result digest. A changed record cannot be paired with an old summary.
- All arrays are emitted in documented canonical order; object keys use deterministic sorted serialization.

## Draft canonical JSON envelope

Illustrative shape only; the exact JSON Schema, enum values and field types must be frozen and tested before implementation.

```json
{
  "schema_version": "0.2.0",
  "run_id": "synthetic-run-001",
  "engine_version": "design-only",
  "ruleset_digest": "sha256:<illustrative-digest>",
  "execution": {
    "state": "COMPLETED",
    "coverage": "COMPLETE_POLICY_ADJUSTED",
    "discovered_units": 12,
    "inspected_units": 10,
    "verified_blocked_units": 2,
    "uninspected_units": 0,
    "required_uninspected_units": 0
  },
  "detection": {
    "detected": 5,
    "actionable": 2,
    "exempted": 3
  },
  "policy": {
    "applied_block_ids": ["GLOBAL-014"],
    "applied_exemption_ids": ["DEV-001"],
    "effective_policy_digest": "sha256:<illustrative-digest>"
  },
  "result_code": 3,
  "result": "ACTIONABLE",
  "records": {
    "execution_digest": "sha256:<digest>",
    "findings_digest": "sha256:<digest>",
    "policy_digest": "sha256:<digest>"
  }
}
```

The execution, detection and policy records contain **item-level audit trails** in the private evidence bundle; the envelope above is a non-sensitive summary. The `CI acceptance` event is outside the immutable result envelope. A reproducible sanitized report should carry only approved metadata and possibly safe location hints, never secret values or restricted target identifiers.

## Evidence handling and exports

- **Private raw evidence:** controlled location outside public repository; strict permissions and retention, no automatic upload; may contain matched secrets, evidence digests, finding IDs and command diagnostics.
- **Sanitized report:** redact matched values, sensitive path segments, target IDs, environment details and raw logs; **do not publish `evidence_digest` or `finding_id`** because an unkeyed digest over a low-entropy credential is guessable. Fail closed when validation/redaction cannot be proven.
- **Initial exports:** versioned JSON as the canonical private contract and a concise terminal summary with counts only. Human-readable Markdown may follow once schema is stable.
- **Later exports:** SARIF, CI annotations, Markdown/HTML, comparison reports and machine APIs as **renderers over the same records**, not additional detection systems. Public renderers must use opaque case IDs rather than credential-derived hashes.
- **Safety:** explicit user-approved scopes, no arbitrary command strings, no secrets in CI logs, no destructive cleanup outside run-owned files/resources. See [evidence-privacy.md](evidence-privacy.md).

## Two different kinds of scoring

| In-product finding assessment | Independent harness evaluation |
| --- | --- |
| Confidence, severity, detector rule/category, policy disposition | Recall, precision, false positives, false negatives, missed fixtures, execution correctness |
| Describes a particular finding | Grades scanner behavior against an externally owned manifest |
| May be enriched by versioned rules and policy | Must work with synthetic stub, RNC engine, Gitleaks and other adapters using a normalized finding contract |

**A detector must not grade itself.** A high-confidence finding is not proof of high corpus-level precision, and an exemption does not make a false positive disappear from harness scoring.

## Verification gates

Feed the reporter synthetic execution/detection/policy records (without launching any scanner), including 10 known in-scope credentials, two verified blocks, three exemptions, inaccessible required targets, corrupt evidence and operational errors. Validate exact counts, preserved actionable findings, correct precedence, non-leaking redaction and stable JSON under independently known expected outputs. Compare canonical JSON with every later export to catch drift.
