# RNC Scanner architecture contracts

The documents below are the **current design specifications** for RNC Scanner and the reporting/CI boundary of RNC Security Audit. They describe implemented CP2 behavior and preserved contract targets.

1. [Detection engine](detection-engine.md) â€” implemented CP2 input adapter boundary, rules, normalized detection events, deterministic behavior and resource controls.
2. [Adaptive matching](adaptive-matching.md) â€” implemented portable multi-strategy architecture and provenance.
4. [Configuration](configuration.md) â€” implemented global/repository/CLI precedence, mandatory caps and legacy migration.
5. [Policy](policy.md) â€” implemented no-read blocks, post-scan exemptions, origin and collision precedence.
6. [Reporting](reporting.md) â€” implemented reconciliation, sanitized/private boundaries and exports.
7. [Execution status](execution-status.md) â€” implemented immutable five-way classification, required/optional coverage, precedence, CI acceptance and exit codes.

Supporting contracts and decisions:

- [Architecture decisions](decisions.md) â€” approved decisions and the register.
- [ADR-007: production detector language](adr-007-detector-language.md) â€” Rust selection and tradeoffs.
- [ADR-009: portable matching](adr-009-portable-matching.md), [ADR-010: reference equivalence](adr-010-reference-regex-equivalence.md), [ADR-011: planner/fallback](adr-011-planner-fallback.md), [ADR-012: deferred accelerators](adr-012-deferred-accelerators.md), [ADR-013: CI acceptance authority](adr-013-ci-acceptance-authority.md), [ADR-014: root-contained acquisition](adr-014-root-contained-acquisition.md).
- [Configuration](configuration.md) and [migration](config-migration.md) â€” `.rncscanner.toml`, global mandatory caps, explicit legacy `security.config` mapping and fail-closed conflicts.
- [Evidence privacy](evidence-privacy.md) â€” content/evidence/finding digest distinctions, public boundary and keyed-HMAC evaluation.
- [Threat model](threat-model.md) â€” confidential evidence, authorization and fail-closed boundaries.
- [Machine-readable schemas](../contracts/README.md) â€” six record schemas plus the unified configuration schema at `0.2.0`.
- [Contract compatibility](../contracts/compatibility.md) â€” v0.1 to v0.2 changes and migration policy.
- [Independent harness handoff](../contracts/harness-handoff.md) â€” tested external scoring boundary and outstanding integration tasks.

## Contract rules shared by all modules

- The detector emits evidence. Its output is not edited by policy; policy emits new dispositions linked to detection IDs.
- Pre-scan blocks must have **verified non-access** or cannot be recorded as successfully applied.
- Each final outcome derives from evidence validation, required coverage, findings and policy â€” not from the external process return code alone.
- The final result code never changes to satisfy CI. CI records its own acceptance decision and OS exit separately.
- Configuration and rule-set versions/fingerprints make scan outcomes reproducible.
- The scanner does not grade its own detection accuracy; the independent synthetic harness owns ground-truth evaluation.
- Required and optional coverage are counted separately. Optional gaps are disclosed but do not silently become required failures.
- Findings retain byte offsets and line identity; policy dispositions never rewrite evidence.

## Versioning plan

Each result carries `schema_version`, `engine_version`, `ruleset_id`/digest, adapter identity, and effective-policy fingerprint. Incompatible schema changes require a new schema major version or a documented pre-production minor revision. Rule changes may change detections even when the engine implementation does not change; benchmark both independently.

