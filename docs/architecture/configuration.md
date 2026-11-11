# Unified configuration

> **Implemented in CP2.** One immutable effective configuration is loaded before discovery.

## Sources

| Source | Selection | Trust |
| --- | --- | --- |
| Global | `--global-config PATH`; optional | Highest; may declare mandatory policies and acceptance caps |
| Repository | `--config PATH`, else `.rncscanner.toml` or `security.config` under the scan root | May narrow but not broaden global controls |
| CLI | explicit flags | Run-scoped; may narrow or add requests |

If `.rncscanner.toml` and `security.config` both exist and no explicit config is given, the loader fails with a dual-source error. The two formats are never silently merged.

## Precedence

- **Overridable scalar settings:** CLI > repository > global.
- **Resource caps:** effective value is the most restrictive (minimum) across global, repository and CLI. A lower-trust source cannot enlarge a global cap.
- **Accepted result codes:** default is `{1,2}`. A global list is the mandatory cap and may include `3`. Repository configuration may only narrow to a subset of the default/global cap; it cannot independently add `3`. An explicit CLI list may broaden the default when no global cap exists, but must remain a subset of a global cap. Per-code provenance records `default`, `global`, `repository` or `cli`. `INCOMPLETE`/`FAILED` are never acceptable. See [ADR-013](adr-013-ci-acceptance-authority.md).
- **Mandatory policies:** only global configuration may set `mandatory = true`. Repository and CLI cannot remove global blocks or exemptions; policy requests are additive. A SHA-256 policy declaration conflict is rejected.
- **Reporting safety:** `sanitized_only` and `redaction_fail_closed`, if present, must be true. `follow_symlinks` must be false.

## Repository file shape

```toml
schema_version = "0.2.0"

[ruleset]
id = "rnc-synthetic-v1"
# version/digest are optional but, when present, must match the selected bundle

[scan]
max_file_bytes = 8388608
max_total_bytes = 67108864
timeout_ms = 300000
max_findings = 10000
mode = "auto"          # auto | whole | stream
strategy = "auto"      # auto | regex | regexset | prefilter
follow_symlinks = false

[policy]
[[policy.blocks]]
policy_id = "REPO-SECRETS"
selector = "secrets/**"
reason = "repository policy"

[[policy.exemptions]]
policy_id = "REPO-FIXTURE"
selector = "rule:synthetic-aws;path:tests/fixtures/**"
reason = "approved synthetic fixture"
# expires_unix = 1800000000
# version = "1"
# mandatory is forbidden outside global configuration

[ci]
# Repository configuration may narrow, never broaden beyond the global/default cap.
accepted_result_codes = [1, 2]
```

Unknown fields are rejected. All configuration values are validated before source discovery.

## Legacy migration

`security.config` version 1 supports only the reviewed subset: `secret_detection` (`enabled=true`, `ruleset`, `ruleset_digest`), `exclusions.paths`, `limits`, sanitized reporting and completed-result acceptance. Unsupported fields fail; unsupported legacy reporting cannot be migrated. Exclusions become repository-origin pre-scan block requests under `LEGACY-SECURITY-CONFIG`.

## Provenance

The private evidence bundle records the configuration source, per-setting origins (`global`, `repository`, `cli`), per-code CI acceptance authority and the effective policy ledger. Policy digests are content-bound: selectors, expiration, origin, mandatory status and version all participate; declaration order does not. Policy entries carry origin/version/digest/mandatory. Protected values are never printed in sanitized output.

## Selector grammar

Policy path selectors are a declared segment glob:

- `*` matches within a segment (`*`, zero or more characters);
- `?` matches one character;
- `**` matches zero or more whole path segments;
- all other characters are literal, case-sensitive;
- character classes, braces and backslash escapes are not supported;
- selectors must be relative, NFC, forward-slash only, without `.`/`..`/empty segments, absolute prefixes, drive/UNC syntax, control characters or trailing space/dot.

Selectors match already-canonical discovered locators. They never rewrite a locator. Exemption selectors use `kind:value` clauses: `finding:`, `fingerprint:`, `rule:`, `path:`, and the composite `rule:...;path:...`. Finding/fingerprint selectors must stand alone.
