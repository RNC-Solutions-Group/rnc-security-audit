# CP4 generic credential extraction

> **Status:** Implemented and regression-tested; CI evidence is recorded in
> [CP4 validation](cp4-validation.md). CP4B adds bounded candidate context,
> assignment-syntax checks, `BASE` qualifiers and context-aware hex
> classification; see [CP4B contextual validation](cp4b-contextual-validation.md).
> A generic finding is a contextual candidate, **not** proof that a credential
> is active or complete.

## Purpose

CP3's single generic rule covered a narrow set of assignment beginnings and
unquoted values. CP4 expands extraction across common configuration syntaxes
and authorization contexts while keeping the result explicitly unverified and
subject to false-positive controls.

The rule remains a credential detector, not a DLP or sensitive-string detector.
It does not intentionally report payment-card data, email addresses, public
keys, certificates or ordinary identifiers.

## Implemented rules

| Rule | Context | Value forms | Validator | Confidence |
| --- | --- | --- | --- | --- |
| `generic-secret-assignment` | `.env`, shell, JSON, YAML, TOML, INI, XML-adjacent source, PHP `define`/variable assignments | double-quoted, single-quoted, backtick and unquoted; escaped characters; spaces inside quotes | `GENERIC_ASSIGNED_SECRET` | low / plausible only |
| `generic-array-assignment` | PHP/JavaScript bracket assignment such as `$config['password'] = ...` | same four value forms | `GENERIC_ASSIGNED_SECRET` | low / plausible only |
| `generic-multiline-assignment` | YAML block scalar (`|` or `>`) | 1-10 bounded indented lines | `MULTILINE_ASSIGNED_SECRET` | low / plausible only |
| `generic-xml-assignment` | XML element such as `<password>...</password>` | single-line text content | `GENERIC_ASSIGNED_SECRET` | low / plausible only |
| `generic-sql-password` | `CREATE USER ... PASSWORD`, `IDENTIFIED BY/WITH`, `ENCRYPTED PASSWORD` | quoted SQL literal | `SQL_PASSWORD` | low / plausible only |
| `http-basic-authorization` | `Authorization` / `Proxy-Authorization: Basic ...` | bounded base64 | `HTTP_BASIC_AUTH` | low / plausible only |
| `http-bearer-opaque` | `Authorization: Bearer ...` | opaque bounded token | `HTTP_BEARER_OPAQUE` | low / plausible only |
| `credential-url-userinfo` | `http`, `https` or `ftp` URL userinfo | `user:password@host` | `URL_USERINFO` | low / plausible only |

The existing `database-connection-credential` rule continues to cover
password-bearing PostgreSQL, MySQL/MariaDB, MongoDB, Redis and AMQP connection
URIs. JWT Bearer tokens continue to use the structured `jwt-bearer-token` rule.

## Assignment-name context

The assignment rules recognize names containing password, client, JWT or
session secret, secret key/token/value, API key/token/secret, access token, auth
token, bearer token, private-key name or credential keywords. Name matching is
case-insensitive and tolerates common separators and camel case.

A controlled qualifier follows the recognised family:
`VALUE`, `SECRET`, `KEY`, `PROD`, `DEV`, `STAGING`, `TEST`, numeric `1`/`2`, or
`BASE`. The `BASE` form accepts both `secret_key_base` and `secretKeyBase`. There
is no arbitrary trailing-name wildcard; names such as `timePasswordChanged`,
`password_hash` and `password_hint` remain outside the grammar.

It deliberately does **not** treat every name containing `key` as sensitive.
`PUBLIC_KEY`, `NORMAL_SETTING`, path settings, feature flags and similar names
do not enter the generic value validator merely because a keyword is present.

A type/declaration prefix, `export`, shell `-e`, PHP `define(...)`, bracket
array syntax and optional surrounding quotes are recognized. Multiple
assignments on one line are supported through semicolon/brace boundaries;
comma is a syntax-gated delimiter and is accepted only for `define(...)`.

## Candidate context and syntax

CP4B retains the exact regex full-match span, value capture and assignment
identifier in an internal `CandidateContext`. The current delimiter and quote
style are derived from the bytes immediately before the value; the rule may
declare `identifier_capture_group` to identify the name span. Context is
validation-only: it is never serialized, and the finding continues to point at
the exact captured value bytes.

The generic assignment syntax gate applies these bounded rules:

- comma is not a generic assignment operator; `,` is accepted only in an
  explicit `define(...)` call. This rejects callback arguments, CSV-style prose
  and comma-separated metadata lists without suppressing ordinary commented-out
  assignments such as `# password = "..."`.
- an unquoted value containing `(` is rejected when the delimiter is `=`, `:`,
  `=>` or `:=`. Quoted values, including Django `SECRET_KEY` values containing
  brackets and parentheses, are unaffected. XML element values use `>` and are
  outside this specific call-expression check.
- comments are not automatically nonsecret. A commented assignment with a
  supported operator and credential-shaped value remains eligible.

The gate does not parse languages or use file extensions. Bare CSV key/value
rows are outside the generic assignment contract; a future dedicated format rule
would be required if that syntax is to be supported.

## Value validation

`GENERIC_ASSIGNED_SECRET` and `MULTILINE_ASSIGNED_SECRET` apply reusable,
offline checks:

- length bounds (6-512 bytes for a single value; 4 KiB for a multiline block);
- UTF-8 and control-character rejection;
- leading/trailing whitespace rejection;
- variable references (`${...}`, `$VAR`, `%VAR%`, `{{...}}`, `$(...)`,
  `process.env`, `os.getenv`, `vault:`, `secretRef`);
- placeholder wrappers (`<password>`, `${PASSWORD}`, `__PASSWORD__`,
  `your_key`) and known documentation values;
- common benign settings and low-entropy repeated values;
- explicit password-hash formats (bcrypt, Argon2, scrypt, PBKDF2 and `sha*:`,
  `md5:`, `{sha}`, `{ssha}` prefixes);
- hex-only values of 32/40/64/96/128 characters only when the assignment
  identifier contains an explicit digest marker such as `hash`, `digest`,
  `checksum`, `sha256`, `md5`, `bcrypt` or `fingerprint`; length alone is not a
  rejection reason. Accepted values receive the `HEX_CREDENTIAL_SHAPE` note and
  remain plausible/unverified;
- URI, template and nonliteral structures;
- provider-shaped values that are handled by a dedicated provider rule;
- known provider placeholders.

Accepted generic values are always `PLAUSIBLE_UNVERIFIED` and low confidence.
No generic validator claims a credential is active, authorized, complete or
non-revoked.

Escaped values are decoded for validation only. The finding retains the original
source byte span; decoded bytes never replace source coordinates or evidence.

## Authorization decoding

- **HTTP Basic** decodes bounded base64, requires a non-empty user and password,
  rejects controls, unresolved variables, placeholders and common benign
  passwords, and marks the result plausible only.
- **Opaque Bearer** accepts a bounded token alphabet, rejects JWT-shaped values
  (the structured JWT rule owns those), provider-shaped values and placeholders,
  and does not decode or trust claims.
- **URL userinfo** requires a bounded user:password pair, valid percent encoding
  and non-variable, non-placeholder values. The URL is never fetched.
- **Database URIs** retain the CP3 validator and add no network operation.

## Regression coverage

The Rust `cp4_detection` suite covers:

- `.env`, JSON (including multiple assignments on one line), YAML, TOML, INI,
  PHP `define`, PHP variable and bracket assignment, XML, SQL, CRLF and LF;
- double, single, backtick and unquoted values; spaces inside quotes; escaped
  quotes; empty values; environment references; comments and placeholders;
- Unicode surrounding text, invalid UTF-8 surrounding bytes, a 600-byte value
  that exceeds the value bound, and a secret crossing the streaming overlap
  boundary;
- HTTP Basic, opaque Bearer, explicit `X-API-Key` assignment, URL userinfo and
  database URI userinfo;
- whole-file/streaming and all four matching strategies with identical
  canonical findings.

Negative controls require zero findings for empty values, variable references,
`password`, documentation placeholders, `PASSWORD_HINT`, `PUBLIC_KEY`,
`NORMAL_SETTING`, path/URI settings, a malformed/oversized value and common
nonsecret settings. These tests are scanner correctness tests, not an
independent accuracy corpus.

The CP4B `cp4b_contextual` suite additionally asserts exact values, offsets,
digests and finding IDs for:

- 32/40/64/96/128-character hexadecimal credentials, including
  `secret_key_base` and `secretKeyBase`;
- digest-named, checksum, timestamp, explicit-hash, identifier and UUID
  negatives;
- callback and comment/CSV prose rejection;
- commented-out assignment preservation and PHP `define(...)`;
- XML, bracket, SQL and unquoted/quoted value alternatives;
- whole/stream and all four strategies, a streaming overlap boundary, Git
  history, and private/sanitized component isolation.

## Limitations

- Assignment context can be present in documentation, examples or generated
  code. A low-confidence generic finding requires operator review.
- Name-based extraction cannot distinguish every semantic variant (for example
  a password field in a UI model from a deployed credential). Value and
  placeholder checks reduce but do not eliminate this.
- YAML block scalars are bounded to 10 lines; larger blocks are unsupported
  rather than scanned without bound.
- TOML triple-quoted strings and complex interpolation are not implemented.
- SQL parsing is context-pattern based, not a full SQL grammar.
- Escaped decoding supports common JSON/source escapes, not arbitrary language
  runtime semantics.
- A bare `password = <32 hex>` is accepted as a low-confidence plausible
  credential. A stored digest in a merely password-named field cannot be
  distinguished without a hash/digest marker; operator review remains required.
- Comma-separated key/value rows and CSV credentials are outside the generic
  assignment syntax. A dedicated CSV rule would require separate evidence and
  authorization.
- Candidate context is local syntax, not a language or format parser. It does
  not use file extensions and does not prove that a value is active.
- CP4B generic rule versions are `2026.11.5`; generic finding IDs migrate even
  when an accepted value's span and digest are unchanged. Provider, private-key
  and database finding identities do not change.
- Generic confidence does not imply provider verification.
