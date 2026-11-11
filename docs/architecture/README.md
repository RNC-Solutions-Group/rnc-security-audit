# RNC Scanner architecture contracts

The four documents below are the **current design specifications** for RNC Scanner and the reporting/CI boundary of RNC Security Audit. They are normative design targets; CP0 validates their executable contracts but does not claim a production scanner.

1. [Detection engine](detection-engine.md) — implemented CP1 input adapter boundary, rules, normalized detection events, deterministic behavior and resource controls.
2. [Policy](policy.md) — global/repository/CLI configuration, no-read blocks, post-scan exemptions, origin and precedence.
3. [Reporting](reporting.md) — independent records, reconciliation, redaction, finding scoring versus harness grading, exports.
4. [Execution status](execution-status.md) — immutable five-way classification, required/optional coverage, precedence, CI acceptance and exit codes.

CP0 supporting contracts:

- [Architecture decisions](decisions.md) — approved decisions and the register.
- [ADR-007: production detector language](adr-007-detector-language.md) — Rust selection and tradeoffs.
- [Configuration migration](config-migration.md) — `.rncscanner.toml`, explicit legacy `security.config` mapping and fail-closed conflicts.
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

## Versioning plan

Each result carries `schema_version`, `engine_version`, `ruleset_id`/digest, adapter identity, and effective-policy fingerprint. Incompatible schema changes require a new schema major version or a documented pre-production minor revision. Rule changes may change detections even when the engine implementation does not change; benchmark both independently.
