# CP0 threat model and evidence boundaries

> Initial source-only RNC Scanner scope. This does not authorize active testing or remote service access. **CP0 now includes executable contract, corpus and harness checks; production input/policy/reporting controls remain unimplemented.**

## Assets and trust boundaries

| Asset/boundary | Risk | Required control |
| --- | --- | --- |
| Source files and potential real secrets | Confidential data exposure | Explicit local-scope authorization, read-only input, avoid unnecessary network access |
| Pre-scan block policy | Content read despite claimed exclusion | Verified no-read enforcement **before** engine ingestion; unsupported block is a coverage error |
| Rule bundle and config | Malicious patterns/command injection | Versioned trusted rules, bounded resource use, typed arguments, no arbitrary shell commands |
| Unified/legacy configuration | Silent dual-loading or weakened mandatory controls | Single-source loader, explicit migration subset, global-only mandatory policies, fail-closed unknown fields |
| Private execution/detection evidence | Raw tokens or sensitive locations leaked | Private output outside public repo, least privilege, deliberate retention, no implicit upload |
| Sanitized reporting/CI logs | Redaction failure | Fail closed; no public report if redaction/evidence validation fails |
| Result/CI separation | CI silently rewrites result or accepts incomplete scan | Result digest linkage; separate acceptance event; `4`/`5` never accepted |
| Execution backend | Unsafe runtime access or cleanup | Read-only mounts where applicable, resource caps, cleanup only run-owned resources |
| Independent harness | False accuracy claims or leaked answer key | Separate scoring/manifest from detector; synthetic stub explicitly excluded from product builds; pinned external revision |
| Benchmark evidence | Misleading language comparison or host-dependent data | Equivalent rules/fixtures/output, same runner, pinned toolchains, repeated runs, raw artifact retained rather than fabricated summary |
| Public repository artifacts | Secret/path leakage in tests or generated evidence | Harmless synthetic markers only; publication check rejects secret-shaped values, locators and absolute paths |

## Threat cases CP0/CP1 must cover

1. Symlink escape, circular symlinks, path traversal or case normalization defeating a no-read block.
2. Files changing between enumeration and access (TOCTOU); evidence should identify what was actually read.
3. Oversized files, pathological patterns, binary/encoding ambiguity, archives/decompression bombs (archives deferred until scoped).
4. Missing or malformed evidence being misreported as `CLEAN`.
5. A post-scan exemption being misrepresented as a block that prevented content access.
6. Scanner-specific exit codes interpreted as operational failures (or crashes incorrectly treated as findings).
7. Raw secrets in exceptions, logs, CI annotations, Markdown/SARIF renderers, or retention artifacts.
8. A repository config disabling an organization-mandatory check or promoting passive checks to active scanning.

## Non-goals of CP0

No real credentials in fixtures; no credential validity checks against providers; no exploitation, unsolicited web scanning, automatic secret remediation, broad network access or cloud storage. CP0 produces design proofs and generated **synthetic** evidence only.

Any security controls not implemented in CP0 remain requirements rather than claimed protections. Vulnerability research and red-team adapters are later, separately authorized work.


## CP2 hardening addendum

- **Ancestor substitution:** Unix uses `openat`/`O_NOFOLLOW` chains for root-relative reads; Windows canonicalizes, rejects reparse points and documents its narrower ancestor-race guarantee.
- **Report redirection:** destinations resolve against the working directory, must be outside the canonical root, reject symlinks/reparse points/directories/non-regular files, and publish through a same-directory temporary file plus atomic replacement.
- **Repository CI authority:** a repository cannot authorize `ACTIONABLE`; only a global cap or explicit trusted CLI invocation can broaden default acceptance.
- **Policy work:** recursive `**` matching is dynamic-programming bounded; selector count, segment count, path depth, discovery entries, discovery time and policy work are finite. Exhaustion is a failed discovery.
- **Policy identity:** policy declaration digests bind content (selectors, expiration, origin, mandatory status, version), not declaration order or ID/version alone.
