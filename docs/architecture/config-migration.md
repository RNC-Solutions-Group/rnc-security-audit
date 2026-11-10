# Unified configuration and migration contract

> CP0 design only; no config loader or migration command has been shipped.

## Proposed effective configuration

Global, repository and CLI settings are parsed and validated once into a versioned effective policy. The runner/engine receive typed immutable projections, not independent access to untrusted TOML files.

| Origin | Existing/planned entry point | Migration intent |
| --- | --- | --- |
| Global | `config/settings.toml` from original audit design | Retain as global catalog/policy layer with explicit schema version |
| Repository | Legacy `security.config` TOML | Documented explicit migration into the unified scanner/audit config schema |
| Repository | Proposed `.rncscanner.toml` | Candidate standardized repository entry point; name still subject to CP0 review |
| CLI | `--block`, `--exempt`, `--accept-results` | Run-scoped validated additions; cannot override mandatory global restrictions |

**One source of truth:** never silently load both `security.config` and `.rncscanner.toml` and let file order decide. If both exist before migration completes, fail with an actionable conflict message or require an explicit selected source. Do not discard existing scanner selections, target confirmations, report destinations or safety settings from the previous design.

## Merge and precedence rules

- Ordinary scalar override: CLI > repository > global **only when the setting is marked overridable**.
- Additive policy entries: merge by stable policy ID with source provenance; reject conflicts on same ID whose meaning differs.
- Mandatory organization rules: deny override, even from CLI; violations are an explicit configuration failure.
- No-read exclusions and post-detection exemptions occupy different namespaces and cannot alias each other.
- Legacy config fields without an exact mapping are recorded as unsupported and require review; never guess or drop them.
- CLI cannot authorize remote network targets, arbitrary shell commands or unsafe file access.

## Migration acceptance

1. A representative legacy config maps to an equivalent validated effective policy where semantics are known.
2. A conflicting dual-file setup stops with a precise error; it does not quietly choose either file.
3. Provenance is preserved across global/repo/CLI layers and in published safe summaries.
4. A mandatory global restriction cannot be relaxed by lower-trust inputs.
5. Unknown, malformed or unsafe settings fail closed; no authorization is inferred from `.env` path references.

CP0 locks these rules; the actual migration implementation belongs after schemas are accepted and versioned.
