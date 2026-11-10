# RNC Scanner architecture contracts

The four documents below are the **current design specifications** for RNC Scanner and the reporting/CI boundary of RNC Security Audit. They are normative design targets until reviewed and versioned; they do not claim implementation.

1. [Detection engine](detection-engine.md) — input adapter boundary, rules, normalized detection events, deterministic behavior.
2. [Policy](policy.md) — global/repository/CLI configuration, no-read blocks, post-scan exemptions, origin and precedence.
3. [Reporting](reporting.md) — independent records, reconciliation, redaction, finding scoring versus harness grading, exports.
4. [Execution status](execution-status.md) — immutable five-way classification, precedence, coverage, CI acceptance and exit codes.

## Contract rules shared by all modules

- The detector emits evidence. Its output is not edited by policy; policy emits new dispositions linked to detection IDs.
- Pre-scan blocks must have **verified non-access** or cannot be recorded as successfully applied.
- Each final outcome derives from evidence validation, coverage, findings and policy—not from the external process return code alone.
- The final result code never changes to satisfy CI. CI records its own acceptance decision and OS exit separately.
- Configuration and rule-set versions/fingerprints must make scan outcomes reproducible.
- The scanner does not grade its own detection accuracy; the independent synthetic harness owns ground-truth evaluation.

## Versioning plan

Each result carries `schema_version`, `engine_version`, `ruleset_id`/digest, adapter identity, and effective-policy fingerprint. Incompatible schema changes require a new schema major version. Rule changes may change detections even when the engine implementation does not change; benchmark both independently.
