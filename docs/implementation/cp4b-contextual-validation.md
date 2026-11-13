# CP4B — contextual candidate validation

> **Status:** Implementation, scanner-owned regression and CI validation
> complete; operator review pending. CP4B is a focused COA 2 enhancement,
> not a new detection framework or format parser. The independent harness owns
> external accuracy evaluation; no scanner-side benchmark or accuracy claim is
> made here.

## Baseline and scope

| Field | Value |
| --- | --- |
| Starting baseline | `93b4dda909cb3b41606a4d0f36c8ef9d06b77fde` |
| Development branch | `feat/cp4` |
| Pull request | PR #11 |
| Implementation head | `67056b5` (code and regression); final documentation head is recorded in the PR |
| Ruleset | `2026.11.5`, digest `sha256:901008d7cf64ee7387599eb13720bc3b78a2ab8868aae6e779fea1843c22dfb9` |
| Merge/release | None; operator authority only |

CP4B corrects four independently established generic-detection behaviors:

1. hex-shaped credentials rejected solely by length;
2. `BASE`-qualified names such as `secret_key_base` excluded;
3. JavaScript callback arguments captured as credentials;
4. comment/CSV prose captured as assignments.

It retains the matching backends, source adapters, finding schema, policy and
result semantics, structured database components and private/sanitized report
boundary.

## WP1 — behavior-neutral candidate context

The matcher already knew the full regex match and every capture group, then
discarded everything except the value span. CP4B adds an internal
`CandidateContext` with:

- exact full-match span in `MatchCandidate`;
- exact captured value span (unchanged finding span);
- optional assignment identifier span;
- derived delimiter and quote style;
- whether the match is an explicit `define(...)` call.

Rules may declare optional `identifier_capture_group`. Load-time validation
requires assignment context, a valid distinct group and a finite maximum length.
The provider schema remains `0.2.0`; the new property is additive and is bound by
the ruleset digest.

The generic value capture groups were renumbered explicitly rather than being
left to drift:

| Rule | Identifier group | Value groups |
| --- | ---: | --- |
| `generic-secret-assignment` | 1 | 3, 4, 5, 6 |
| `generic-array-assignment` | 1 | 3, 4, 5, 6 |
| `generic-multiline-assignment` | 1 | 2 |
| `generic-xml-assignment` | 1 | 2 |
| `generic-sql-password` | none | 1 |

A dedicated test exercises double-quoted, single-quoted, backtick and unquoted
alternatives for both the secret and array rules and verifies exact values,
offsets and recomputed finding IDs.

### Behavior-neutral evidence

WP1 was committed before any rule declared `identifier_capture_group`. The
CP4A binary and the WP1 binary were run over the same independently authored
20-finding neutral corpus (generic formats, PHP define/array, XML, SQL, Django,
provider and database URI cases). The private reports were byte-identical:

`sha256:9b830f7687bba9dd5da429acacd39ed211ad1e303d23d582f6b79ae8500292af`

Focused CP4 and CP4A suites also passed unchanged. This establishes that adding
the context plumbing did not alter evidence, IDs or results before the
behavioral rules were enabled.

## WP2 — assignment syntax gate

The generic gate runs only for rules that declare an identifier capture:

- `,` is rejected unless the match is an explicit `define(...)` call.
- An unquoted value containing `(` is rejected for `=`, `:`, `=>` and `:=`.
  Quoted Django values and XML element values are unaffected.
- Commented-out assignments with a supported operator remain eligible; comments
  are not blanket-suppressed.

This rejects `function(err` callback captures and `Risk: name, name` prose while
preserving `define('DB_PASSWORD', '...')`, `$password = '...'`,
`$config['password'] = '...'` and `<password>...</password>`.

Bare CSV key/value rows are deliberately outside the generic assignment syntax.
A future dedicated CSV rule would be a separate, evidence-based capability.

## WP3 — qualified names

The controlled qualifier now includes `BASE` with an optional separator:

- `secret_key_base` accepted;
- `secretKeyBase` accepted;
- `timePasswordChanged`, `password_hash`, `password_hint`, `checksum` and
  noncredential metadata rejected.

The matcher still does not restore an arbitrary trailing-name wildcard. The
qualifier is applied consistently to all four generic assignment name patterns,
and the CP4B name matrix guards against drift.

## WP4 — context-aware hexadecimal validation

`looks_like_password_hash` is now two decisions:

1. explicit hash prefixes are always rejected;
2. hex-only values of length 32, 40, 64, 96 or 128 are rejected only when the
   assignment identifier contains a digest marker (`hash`, `digest`,
   `checksum`, `sha1`, `sha256`, `sha512`, `md5`, `bcrypt`, `argon2`, `pbkdf2`,
   `scrypt`, `fingerprint`).

If no identifier context is available, length alone does not reject a value.
Accepted hex candidates receive `HEX_CREDENTIAL_SHAPE`, remain
`PLAUSIBLE_UNVERIFIED`, and remain low confidence. They are not provider-validated
and do not claim liveness.

Verified behavior:

| Case | Result |
| --- | --- |
| `api_key = <32/64/96 hex>` | accepted, low, `HEX_CREDENTIAL_SHAPE` |
| `oauth_token = "<40 hex>"` | accepted |
| `secret_key_base = <128 hex>` | accepted |
| `secretKeyBase = <128 hex>` | accepted |
| `password = <32 hex>` | accepted as plausible/unverified |
| `sha256_password = <64 hex>` | rejected |
| `hash_password = <64 hex>` | rejected |
| `password_hash`, `password_hint`, `checksum`, timestamp | no candidate |
| explicit bcrypt/`sha256:` value | rejected |
| `request_id`, UUID | no candidate |
| SQL `PASSWORD '<64 hex>'` | accepted as plausible/unverified |

A bare `password` field containing 32 hex is intentionally retained as a
low-confidence candidate, because length alone cannot prove it is a stored hash.
Digest-named fields are rejected only when that semantic context is available.

## WP5 — engine integrity and compatibility

Ordinary syntax rejection remains a candidate rejection and does not make a unit
uninspected. Invalid rule metadata fails at load. Internally inconsistent
candidate spans or missing required identifier captures surface as
`EVIDENCE_INTEGRITY`, mark the unit uninspected and prevent a completed report
from claiming full coverage.

Source evidence remains unchanged:

- finding span = exact captured value bytes;
- SHA-256 = exact captured bytes;
- line mapping and finding-ID formula unchanged;
- structured database password components unchanged and private-only;
- `CandidateContext` is never serialized;
- sanitized reports contain no context, component or raw value data.

### Generic finding-ID migration

Actual behavior changes require new generic rule versions. The following rule
identities migrate from `2026.11.3` to `2026.11.5`:

- `generic-secret-assignment`
- `generic-array-assignment`
- `generic-multiline-assignment`
- `generic-xml-assignment`
- `generic-sql-password`

Every finding from these rules receives a new `finding_id` because
`rule_version` is part of the documented identity formula. Accepted values retain
their exact offsets and evidence digests. Provider-specific, private-key and
database rule versions and finding IDs are unchanged.

## WP6 — regression evidence

New independently authored fixtures cover:

- hexadecimal positive/negative matrix and `BASE` names;
- callback, comment, CSV/metadata prose;
- commented-out assignments and PHP `define`;
- XML, bracket, SQL, quoted/unquoted and punctuation values;
- every generic value-capture alternative;
- exact offsets, SHA-256 and finding-ID recomputation;
- streaming overlap boundary;
- filesystem and read-only Git-history acquisition;
- whole/stream and `regex`/`regexset`/`prefilter`/`auto`;
- private/sanitized isolation and database component exactness.

Local results:

| Gate | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| warnings-denied Clippy | PASS |
| `cargo test --workspace --all-targets --locked` | PASS, 139 tests on Windows |
| CP4B contextual suite | 8/8 |
| CP4 Git-history suite | 9/9, including contextual history |
| CP0 contracts | 74/74 |
| CP1 synthetic rules | 5/5 |
| CP3 catalog/scoring/security | 55/55 |
| CP3 provider integration | 24/24 cases, all modes/strategies, exact truth |
| CP4A structured evidence | 4/4 integration + 6 unit tests |
| Windows private-report ACL | PASS |

### CI and cross-platform evidence

The code validation head `1b5fbff` passed all **32** PR checks:

| Workflow | Run | Result |
| --- | --- | --- |
| CP0 contracts, corpus and harness | [43324852498](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/43324852498) | Success |
| CP1 Rust detection engine | [43324852655](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/43324852655) | Success |
| CP2 integrated scanner | [43324852636](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/43324852636) | Success |
| CP3 provider detection and accuracy | [43324852630](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/43324852630) | Success |
| CP4 detection expansion and history | [43324852518](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/43324852518) | Success, all 8 jobs |

The matrix includes Ubuntu, Windows and macOS Rust tests, static musl builds,
dependency audits, CP3 exact-byte integration, the retired-benchmark CI state,
and Ubuntu/Windows development-package smoke. The documentation-only final head
does not alter the scanner binary.

## Residual limitations

- Candidate context is local syntax, not a format parser; it does not use file
  extensions or establish that a credential is active.
- CSV key/value credentials are not covered by the generic assignment rule.
- A bare password-named field containing 32 hex may be a stored digest; it is
  retained only as low-confidence, unverified evidence.
- Generic findings remain subject to the existing operational-review caveat.
- Candidate-level diagnostics are intentionally not implemented in CP4B.
- The independent harness has not re-evaluated this scanner commit. No accuracy
  or performance claim is made by the scanner repository.
