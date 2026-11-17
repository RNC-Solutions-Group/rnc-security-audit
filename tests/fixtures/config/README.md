# Configuration migration fixtures

These TOML files exercise the CP0 reference loader and are not production policy.

| Directory | Purpose |
| --- | --- |
| `unified/` | Valid `.rncscanner.toml` with rule-set provenance, repository block, limits and CI default |
| `legacy/` | Supported `security.config` version 1 migrating two path exclusions |
| `dual/` | Both files present; must fail with `CONFIG_DUAL_SOURCE` |
| `invalid-unsafe/` | Legacy unsanitized reporting; must fail closed |
| `invalid-unknown/` | Legacy orchestrator scanner field outside the reviewed subset; must fail closed |

Rule-set and policy digests are illustrative `sha256:` values, not hashes of real rules or policies.
