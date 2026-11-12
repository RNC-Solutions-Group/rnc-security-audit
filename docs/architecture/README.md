# RNC Scanner architecture contracts

The documents below are the **current design specifications** for RNC Scanner and the reporting/CI boundary of RNC Security Audit. They describe implemented CP2-CP4 behavior and preserved contract targets.

1. [Detection engine](detection-engine.md) — implemented input adapter boundary, rules, normalized detection events, deterministic behavior and resource controls.
2. [Adaptive matching](adaptive-matching.md) — implemented portable multi-strategy architecture and provenance.
3. [Provider credential catalog](adr-015-provider-credential-catalog.md) — CP3 schema `0.2.0`, offline validators and confidence semantics; CP4 extends the catalog and generic/private-key handling.
4. [Read-only Git history](adr-016-read-only-git-history.md) — CP4 process boundary, traversal safety and history source identity.
5. [Configuration](configuration.md) — implemented global/repository/CLI precedence, mandatory caps and legacy migration.
6. [Policy](policy.md) — implemented no-read blocks, post-scan exemptions, origin and collision precedence.
7. [Reporting](reporting.md) — implemented reconciliation, sanitized/private boundaries and exports.
8. [Execution status](execution-status.md) — implemented immutable five-way classification, required/optional coverage, precedence, CI acceptance and exit codes.

Supporting contracts and decisions:

- [Architecture decisions](decisions.md) — approved decisions and the register.
- [ADR-007: production detector language](adr-007-detector-language.md) — Rust selection and tradeoffs.
- [ADR-009: portable matching](adr-009-portable-matching.md), [ADR-010: reference equivalence](adr-010-reference-regex-equivalence.md), [ADR-011: planner/fallback](adr-011-planner-fallback.md), [ADR-012: deferred accelerators](adr-012-deferred-accelerators.md), [ADR-013: CI acceptance authority](adr-013-ci-acceptance-authority.md), [ADR-014: root-contained acquisition](adr-014-root-contained-acquisition.md), [ADR-015: provider catalog](adr-015-provider-credential-catalog.md), [ADR-016: Git history](adr-016-read-only-git-history.md).
- [Configuration](configuration.md) and [migration](config-migration.md) — `.rncscanner.toml`, global mandatory caps, explicit legacy `security.config` mapping and fail-closed conflicts.
- [Evidence privacy](evidence-privacy.md) — content/evidence/finding digest distinctions, public boundary and keyed-HMAC evaluation.
- [Threat model](threat-model.md) — confidential evidence, authorization and fail-closed boundaries.
- [Machine-readable schemas](../contracts/README.md) — six record schemas plus the unified configuration schema at `0.2.0`.
- [Contract compatibility](../contracts/compatibility.md) — v0.1 to v0.2 changes and migration policy.
- [Independent harness handoff](../contracts/harness-handoff.md) — tested external scoring boundary and outstanding integration tasks.

## Contract rules shared by all modules

- The detector emits evidence. Its output is not edited by policy; policy emits new dispositions linked to detection IDs.
- Pre-scan blocks must have **verified non-access** or cannot be recorded as successfully applied.
- Each final outcome derives from evidence validation, required coverage, findings and policy — not from the external process return code alone.
- The final result code never changes to satisfy CI. CI records its own acceptance decision and OS exit separately.
- Configuration and rule-set versions/fingerprints make scan outcomes reproducible.
- The scanner does not grade its own detection accuracy; the independent synthetic harness owns ground-truth evaluation.
- Required and optional coverage are counted separately. Optional gaps are disclosed but do not silently become required failures.
- Findings retain byte offsets and line identity; policy dispositions never rewrite evidence.
- Provider-format recognition is not proof that a credential is active or complete. The catalog records that limitation per family.

## Versioning plan

Each result carries `schema_version`, `engine_version`, `ruleset_id`/digest, adapter identity, and effective-policy fingerprint. Incompatible schema changes require a new schema major version or a documented pre-production minor revision. Rule changes may change detections even when the engine implementation does not change; benchmark both independently.
