# ADR-015: Separately versioned provider credential catalog

**Status:** Implemented for CP3; corrective update `2026.11.2`; final CI green; operator merge pending
**Date:** 11 November 2026
**Supersedes:** none. Extends ADR-009/010/011 without changing the reference regex backend.

## Context

CP0–CP2 proved the acquisition, matching, policy, evidence and CI contracts with
original synthetic markers such as `RNC_SYNTH_KEY_AWS_*`. Those rules are
correct regression probes, but they do not represent production credential
formats. Changing them in place would destroy established synthetic truth and
make historical verification ambiguous.

The scanner also requires every rule to have a finite maximum match length so
that whole-file and streaming execution remain bounded. A production catalog
therefore needs explicit candidate bounds, not just a regex.

## Decision

1. Keep `rules/rnc-synthetic-v0.json` and `rules/rnc-synthetic-v1.json` on
   schema `0.1.0`, with their established digests and truth unchanged.
2. Add schema `0.2.0` for first-party provider rules. Each rule declares
   provider, family, credential type, context basis, capture group, validator
   sequence, confidence, finite `max_match_bytes`, `max_candidate_bytes`,
   fixture set and documentation provenance.
3. Keep the Rust `regex` backend authoritative. RegexSet and Aho-Corasick remain
   interchangeable strategies behind the existing candidate-equivalence gate;
   an unsupported plan falls back explicitly to regex.
4. Use data-only rules and reusable offline validators. No provider rule is
   hard-coded into the matching engine, and no validator performs network
   access.
5. Classify a structurally valid candidate as format-valid; mark values that
   cannot be verified offline as plausible. Low-confidence findings are retained
   in the raw detection ledger rather than silently dropped.
6. Permit a provider-shaped value to be claimed by a dedicated rule instead of
   the low-confidence generic fallback. The generic validator rejects values
   handled by a provider-specific rule.

## Consequences

- Existing synthetic digests and regression truth remain stable.
- The provider catalog can be versioned, audited and scored independently.
- A recognized format is evidence of shape, never proof that a credential is
  active, authorized, complete or non-revoked.
- Provider rules increase regex compilation and matching cost. The benchmark
  records the measured cost rather than removing validators to recover it.
- Experimental families remain explicitly labeled; unsupported families are not
  advertised as covered.
- A rule that cannot execute correctly on a portable strategy must fall back or
  fail explicitly. It must not disappear from output silently.

## Validation

- `rules/rnc-providers-v1.json` validates against
  [`provider-rule-bundle.schema.json`](../contracts/rules/provider-rule-bundle.schema.json).
- Independent truth is authored outside the scanner root and verified against
  source bytes.
- Tier 2/3 fixtures are scored by exact byte range under `whole`/`stream` and
  `regex`/`regexset`/`prefilter`/`auto`.
- The pinned external harness receives a separate line-addressed handoff; its
  same-line ambiguity is recorded rather than used for the authoritative score.

## Amendment: CP3 corrective review (11 November 2026)

The initial catalog conflated all documented AWS IAM unique-ID prefixes with
access-key credentials. It also did not recognize the stateless GitHub App
installation-token `ghs_APPID_JWT` format, and its Gitleaks comparison matcher
did not enforce one-to-one occurrence assignment.

The amendment is deliberately narrow:

1. `aws-access-key-id` now recognizes only `AKIA` and `ASIA`. The eight ordinary
   IAM resource prefixes (`AIDA`, `AGPA`, `AIPA`, `ANPA`, `ANVA`, `APKA`, `AROA`,
   `ASCA`) are not credential findings.
2. `ABIA` and `ACCA` have distinct rule identities and credential types because
   they are sensitive identifiers, but neither is presented as an ordinary
   access key or as proof of a complete usable credential.
3. `github-app-installation-token` recognizes legacy opaque and stateless
   installation tokens. The stateless JWT is treated as opaque; only documented
   framing and alphabet are checked. `github-oauth-app-token` no longer claims
   `ghs_`.
4. The Gitleaks comparator uses deterministic one-to-one byte reconciliation.
   Path and position must match; duplicates, wrong position/file/family,
   ambiguity and unknown rules do not become TP.
5. The rule bundle/schema validators were extended additively for the new
   validator names. Existing CP0-CP2 synthetic bundles and provider truth
   manifests remain unchanged.

Consequences: the catalog moves to ruleset version `2026.11.2`, 19 rules and 12
families. Ten additional AWS taxonomy cases, legacy/modern GitHub installation
tests, an independently authored Tier 4 challenge and comparator negative
controls were added. Historical Tier 2/Tier 3 scores remain recorded; corrected
comparator scores are reported separately. No finding is promoted to
active-credential verification.
