# Evidence digest and privacy boundary

> **CP0 correction / CP1 requirement.** No raw credential bytes, and no low-entropy credential-derived digest, may appear in ordinary CLI logs or public reports. The CP1 implementation follows this boundary.

## Four different hashes

| Value | Definition | Purpose | Exposure |
| --- | --- | --- | --- |
| `content_sha256` | SHA-256 of the inspected file bytes | File-content integrity and TOCTOU evidence | Private record; a file may itself contain a secret, so do not publish blindly |
| `evidence_digest` | SHA-256 of exactly the matched bytes | Private evidence matching and duplicate detection | Private record only |
| `finding_id` | SHA-256 over unit ID, rule ID/version, byte range and `evidence_digest` | Stable finding identity across repeated runs | Private correlation identity; **not** a public report field |
| Record digest | SHA-256 over canonical JSON record content | Tamper-evident execution/finding/policy/result linkage | Private unless the record is separately sanitized; the public result may expose only its own record digests |

Unkeyed SHA-256 is appropriate for **integrity**, not for hiding a low-entropy value. An attacker who can guess a credential can test guesses against an unkeyed digest. This is why `evidence_digest` and `finding_id` are not publication-safe.

## Public boundary

The v0.2 result and CI decision are publication-safe summaries. They contain counts, classification, coverage, reason codes and record digests — **not** match bytes, locators, evidence digests or finding IDs.

Execution, finding and policy records are private evidence. The CP1 CLI therefore:

- defaults to a safe human-readable summary with counts only;
- writes full normalized findings only to an explicit private JSON destination;
- never prints match bytes, `evidence_digest` or `finding_id` in ordinary logs;
- treats a findings JSON file as private evidence subject to the same retention rules as a raw report.

## Keyed correlation — evaluated, not implemented

HMAC-SHA-256 is the appropriate construction if a future CP2 integration needs to correlate the same finding across trust boundaries without revealing an unkeyed digest.

A keyed design must define:

1. a 32-byte random key held outside the repository (environment secret, OS keyring or protected file);
2. a domain-separated message such as `rnc-evidence-v1\0<unit_id>\0<rule_id>\0<start>\0<end>`;
3. key rotation and retention semantics;
4. who can compute and who can verify the correlation value;
5. a non-secret public identifier for reports, preferably a random run-scoped opaque ID rather than any credential-derived hash.

CP0/CP1 do **not** implement HMAC because there is no approved cross-trust-boundary correlation use case yet. Adding key management without one would create operational risk without a security benefit. CP2 owns that decision if external harness/report correlation requires it.

## Recommendations

- Keep `evidence_digest` unkeyed only inside the private evidence boundary; it is a matching/linkage digest, not a secret-hiding mechanism.
- Do not expose `finding_id` as a public identifier. If reports need case IDs, generate CSPRNG opaque IDs at the reporting boundary.
- Do not include digests in CI annotations, console summaries, public Markdown/SARIF or unredacted artifacts.
- Preserve `content_sha256` for integrity; use HMAC only for the cross-trust correlation use case.
- Log only counts, rule IDs, byte/line ranges in private diagnostics, and reason codes. Never log matched bytes.
- A future schema revision may add `public_finding_id`; it must not be derived from matched bytes.

## Verification

CP1 tests must prove:

- default CLI summary contains no marker bytes, `evidence_digest` or `finding_id`;
- private JSON output contains no raw matched marker bytes;
- public/result-safe documents reject secret-shaped values and private keys;
- findings and digests are not emitted to CI logs or public artifacts by the CP1 workflow.


## CP2 publication hardening

Private evidence is written outside the canonical scan root and never to stdout. Publication uses a secure temporary file and atomic replacement; Unix uses `openat`/`O_NOFOLLOW`/`renameat` with `0600`, while Windows uses reparse checks and `MoveFileExW` with ACL inheritance. A failed or interrupted publication leaves the prior file untouched and exits `30`. Sanitized output never includes finding IDs, evidence digests, locators, policy selectors or matched bytes.

CP4B candidate context (full-match span, identifier, delimiter and quote style) is validation-only. It is never serialized into private or sanitized reports and does not alter finding coordinates or evidence digests.
