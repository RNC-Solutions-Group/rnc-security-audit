# CP0 threat model and evidence boundaries

> Initial source-only RNC Scanner scope. This does not authorize active testing or remote service access.

## Assets and trust boundaries

| Asset/boundary | Risk | Required control |
| --- | --- | --- |
| Source files and potential real secrets | Confidential data exposure | Explicit local-scope authorization, read-only input, avoid unnecessary network access |
| Pre-scan block policy | Content read despite claimed exclusion | Verified no-read enforcement **before** engine ingestion; unsupported block is a coverage error |
| Rule bundle and config | Malicious patterns/command injection | Versioned trusted rules, bounded resource use, typed arguments, no arbitrary shell commands |
| Private execution/detection evidence | Raw tokens or sensitive locations leaked | Private output outside public repo, least privilege, deliberate retention, no implicit upload |
| Sanitized reporting/CI logs | Redaction failure | Fail closed; no public report if redaction/evidence validation fails |
| Execution backend | Unsafe runtime access or cleanup | Read-only mounts where applicable, resource caps, cleanup only run-owned resources |
| Independent harness | False accuracy claims or leaked answer key | Separate scoring/manifest from detector; synthetic stub explicitly excluded from product builds |

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
