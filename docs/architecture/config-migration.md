# Unified configuration and legacy migration

> **CP0 decision: one versioned effective configuration, entry point `.rncscanner.toml`, with explicit `security.config` migration.** A reference loader and migration validator exist; the production policy engine belongs to CP2.

## Effective configuration

Global, repository and CLI settings are parsed once into a validated, versioned effective policy. The runner and engine receive typed immutable projections, not independent access to untrusted TOML files. The machine-readable contract is `docs/contracts/schemas/config.schema.json`, schema version `0.2.0`.

| Origin | Entry point | Migration intent |
| --- | --- | --- |
| Global | `config/settings.toml` (original audit design) | Global catalog/policy layer; mandatory controls remain global |
| Repository | `.rncscanner.toml` | Canonical repository entry point |
| Repository legacy | `security.config` | Read only through the explicit migration path below; never silently alongside `.rncscanner.toml` |
| CLI | `--block`, `--exempt`, `--accept-results` | Run-scoped validated additions; cannot override mandatory global restrictions |

**One source of truth:** if both `.rncscanner.toml` and `security.config` exist, the loader fails with `CONFIG_DUAL_SOURCE`. It never chooses by file order and never merges the two formats. The reference implementation is `tools/cp0/config_migration.py`; fixtures are under `tests/fixtures/config/`.

## Merge and precedence rules

- Ordinary scalar override: CLI > repository > global **only when the setting is marked overridable**.
- Additive policy entries merge by stable policy ID with source provenance; conflicting meanings for the same ID are rejected.
- Mandatory organization rules cannot be overridden by a lower-trust repository or CLI. A mandatory policy must have origin `global`; the validator rejects `mandatory: true` on repository/CLI origin.
- No-read blocks and post-detection exemptions are separate namespaces and cannot alias.
- Unknown settings, malformed files, unsafe reporting and unmappable legacy fields fail closed.
- CLI cannot authorize remote network targets, arbitrary shell commands or unsafe file access.
- `follow_symlinks` is fixed to `false` in the v0.2 configuration schema. Any future opt-in is a separate reviewed security change.

## Legacy `security.config` migration — supported subset

The reference migration accepts only this reviewed subset. Any other top-level or nested key fails with `LEGACY_UNSUPPORTED`.

```toml
version = 1

[secret_detection]
enabled = true
ruleset = "synthetic-v1"
ruleset_digest = "sha256:..."

[exclusions]
paths = ["vendor/**", "generated/**"]

[limits]
max_file_bytes = 1048576
max_total_bytes = 8388608
timeout_ms = 120000
max_findings = 1000

[reporting]
sanitized = true

[ci]
accepted_result_codes = [1, 2]
```

Mapping:

| Legacy field | Effective configuration | Notes |
| --- | --- | --- |
| `version` | Must equal `1` | No other legacy version is guessed |
| `secret_detection.enabled` | Must be `true` | A disabled scanner is not a scan policy; migration fails |
| `secret_detection.ruleset` + `ruleset_digest` | `ruleset.id`, `ruleset.digest` | Digest is required; migration cannot invent rule provenance |
| `exclusions.paths` | `policy.blocks` with policy `LEGACY-SECURITY-CONFIG`, origin `repository` | Paths are selectors; enforcement is not assumed by migration |
| `limits.*` | `scan.*` | Positive integers; absent values take safe defaults |
| `reporting.sanitized` | `reporting.sanitized_only` | Must be `true`; unsafe legacy reporting fails |
| `ci.accepted_result_codes` | `ci.accepted_result_codes` | Only `1`–`3`; `4`/`5` are never accepted |

The migration records `migrated: true` in provenance. It does not claim that any legacy path was actually blocked; that is proven later by execution records and verified non-access evidence.

## Validation gates

1. `.rncscanner.toml` validates against `config.schema.json`.
2. Both config files present → explicit failure, no merge.
3. Legacy supported subset maps to a validated effective policy with origin preserved.
4. Legacy unknown fields, unsafe reporting or invalid CI codes fail closed.
5. Mandatory global restrictions cannot be relaxed by repository/CLI origin.
6. Accepted result codes are unique, sorted, restricted to `1`–`3`; default remains `{1, 2}`.
7. Limits are positive and `max_total_bytes >= max_file_bytes`.

The production loader may add richer global catalogs later, but it must preserve these invariants and the single-source rule.
