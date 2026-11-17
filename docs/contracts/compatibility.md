# Contract compatibility and migration — v0.1 to v0.2

**Decision:** v0.2 is a deliberate, non-silent contract revision. The v0.1 drafts were CP0 design artifacts; no production scan records exist, so no automatic v0.1 record migration is shipped. v0.2 validators reject `schema_version: "0.1.0"` rather than coercing it.

## Why the revision was necessary

The CP0 audit found schema-valid contradictions in v0.1:

| Defect | v0.1 behavior | v0.2 control |
| --- | --- | --- |
| Impossible `CLEAN` | Schema accepted `CLEAN` alongside non-zero actionable/detected/blocked counts or zero required inspection | Result conditionals plus cross-record recomputation; zero required scope is `INCOMPLETE` |
| Optional coverage | `required_scope` existed but was ignored by classification; an optional missing unit forced `INCOMPLETE` | Required and total counts are separate; optional gaps remain visible without changing required completeness |
| Broken accounting | `required_scanners_missing` was added to the classifier's uninspected count but not to result counts | Field removed from the CP0 record; coverage applies to canonical source units only |
| Untyped identity | `unit_id`/`finding_id` were arbitrary strings; a finding could exceed unit bytes or lie about its line | Documented SHA-256 formulas; byte/line/evidence validation against content |
| Unverified blocks | A boolean in the policy object was not tied to a request or unit | Blocked units and applied block events reconcile one-to-one to `APPLIED` requests |
| Silent policy | No record of requested-but-unapplied blocks or exemptions | `requests` retains `APPLIED`, `NOT_MATCHED`, `UNSUPPORTED`, `INVALID` with matches and provenance |
| CI drift | A CI object could claim acceptance inconsistent with its result | CI references the result digest and is checked against the exact accepted set and exit mapping |
| Untraceable result | No record digests or reason codes | Result commits to execution/finding/policy digests and carries deterministic reason codes |
| Ordering drift | Arrays were not ordered | Canonical order is part of validation and serialization |
| Configuration | No machine-readable unified configuration schema | `config.schema.json` and a reference loader with explicit legacy migration |

## Field migration map

| v0.1 | v0.2 | Consequence |
| --- | --- | --- |
| `schema_version` absent on source units, findings, CI | Required `0.2.0` on every record | Old records need an explicit upgrade, not implicit coercion |
| Arbitrary `unit_id` | `u-<sha256>` formula | Stable across runs, independent of scanner output |
| Arbitrary `finding_id` | `f-<sha256>` formula over unit/rule/version/offset/digest | Duplicate detection and reconciliation are deterministic |
| `finding.line` optional | Required; `line_end` optional | External harness line matching is explicit |
| `execution.required_scanners_missing` | Removed | Scanner selection belongs to orchestration, not source-unit coverage |
| `policy.requested_policy_ids` | Structured `requests` | Requested/applied distinction is auditable |
| `policy.applied_blocks` boolean proof | Added `request_id`, `enforcement_method`, reason equality | A block cannot be claimed without a linked request and unit |
| Result counts | Added required-scope subset and `evidence_valid`, `coverage`, engine/ruleset/adapter fields, `records` | Result is self-contained and independently checkable |
| CI exit enum included `64`, `130` | CI event only permits `0`, `10`, `20`, `30` | Usage/interrupt exits are scanner-process outcomes, not CI acceptance decisions |
| No config schema | `config.schema.json` | Unified global/repository/CLI effective policy with origin |

## Versioning policy

- `0.x` revisions are pre-production. A breaking change increments the minor version and must document the change here.
- Once production records exist, incompatible changes require a new major schema version and a tested migration. Readers must reject unknown major versions.
- Adding an optional field is compatible only if old readers can ignore it safely; all v0.2 record schemas currently use `additionalProperties: false`, so additions are still explicit revisions.
- Rule-set changes are versioned separately from engine and schema versions. A rule change can change findings without changing the record schema.
- `effective_policy_digest` covers the canonical effective-policy array. It is not a hash of the raw TOML file; provenance separately identifies source and origin.
- Legacy `security.config` is migrated at the configuration boundary only. There is no dual-loading and no record-level legacy parser.

## Upgrade procedure for v0.1 drafts

Because v0.1 was never production data:

1. Treat v0.1 records as historical design evidence.
2. Rebuild fixtures and examples from the v0.2 schemas and identity formulas.
3. Recompute counts, result classification, record digests and CI decisions.
4. Do not relabel a v0.1 record as v0.2 by changing only `schema_version`; the cross-record validator will reject it.

If a future operator holds real v0.1 records, a dedicated migration tool must preserve original evidence, emit new IDs and dispositions with an auditable parent reference, and never rewrite raw findings in place. That tool is not in CP0.

## Configuration compatibility

The unified entry point is `.rncscanner.toml`. A repository with both `.rncscanner.toml` and `security.config` fails with `CONFIG_DUAL_SOURCE`; the loader never chooses one by file order. Legacy mapping is limited to the reviewed fields in [config-migration.md](../architecture/config-migration.md). Unknown or unsafe legacy fields fail closed.

## External harness compatibility

The external harness consumes line-addressed normalized findings and truth manifests at scoring schema version `1`. CP0's byte offsets and policy records are not core external-harness fields; the handoff exports line identity plus safe byte metadata and keeps policy/result provenance in a sidecar. See [harness-handoff.md](harness-handoff.md). This is a compatibility adapter, not a second scoring model.
