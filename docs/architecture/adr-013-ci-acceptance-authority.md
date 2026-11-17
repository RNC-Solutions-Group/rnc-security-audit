# ADR-013 — Trusted CI acceptance authority

- **Status:** Accepted for CP2 hardening
- **Date:** 11 November 2026

## Context

CP2 originally intersected every configured acceptance list, which meant a repository could add `ACTIONABLE (3)` when no global/CLI list existed. A repository is the object being scanned and is lower-trust; it must not decide that its own actionable credential findings are CI-acceptable.

## Decision

- Default accepted results are `1 CLEAN` and `2 POLICY_APPLIED`.
- A global configuration may broaden acceptance to include `3 ACTIONABLE`; its list is the mandatory cap.
- An explicit CLI `--accept-result 3` is trusted operator intent and may broaden the default when no global cap exists.
- Repository configuration may only narrow acceptance to a subset of the default/global cap. A repository-only attempt to add `3` fails configuration loading.
- When a global cap exists, repository and CLI lists must be subsets of it. A CLI cannot bypass a mandatory global prohibition.
- `4 INCOMPLETE` and `5 FAILED` are never configurable as accepted.
- Effective provenance records the authority for each accepted code (`default`, `global`, `repository`, or `cli`).

The scan result code itself is never changed by acceptance policy; only the separate CI decision and process exit change.

## Consequences

- A repository cannot self-authorize actionable findings.
- Operators can explicitly accept actionable findings through global policy or a trusted CLI invocation.
- A repository can still narrow acceptance for its own pipeline, which cannot make the scanner less strict.
- Configuration that attempts an unauthorized broadening fails closed with exit `64`.

## Validation

`config::tests::repository_alone_cannot_authorize_actionable`, `config::tests::cli_or_global_can_authorize_actionable`, `config::tests::repository_cannot_broaden_global_acceptance_or_enable_links`, and CP2 policy-check scenarios.
