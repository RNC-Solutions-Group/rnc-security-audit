# CP5 detection backlog and disposition

> **Status:** CP5 recovered the two highest-confidence identifier families.
> Remaining items require separate evidence, fixtures and operator authorization.
> The independent harness remains the scoring authority.

## Recovered in CP5

| Candidate | CP5 result |
| --- | --- |
| WordPress authentication material | New `wordpress-auth-key-salt` rule for `AUTH_KEY`, `SECURE_AUTH_KEY`, `LOGGED_IN_KEY`, `NONCE_KEY`, `AUTH_SALT`, `SECURE_AUTH_SALT`, `LOGGED_IN_SALT`, `NONCE_SALT` and `WP_SALT_n` in PHP `define()`, assignment, Kubernetes data and quoted representations |
| HMAC/signing identifiers | `SIGNING_KEY`, `JWT_SIGNING_KEY`, `PAYMENTS_SIGNING_KEY`, `HMAC_KEY`, `HMAC_SECRET` and camelCase/hyphenated variants added to the generic assignment identifier family |

Value-verified local recovery is recorded in
[CP5 validation](cp5-validation.md). These are local target-level checks, not
independently certified scores.

## Still deferred

| Candidate | Remaining gap | Required treatment |
| --- | --- | --- |
| Application HMAC container/value cases | Nine RNC Lab filesystem targets remain in SQLite/container or unresolved `SECRET_KEY` representations | Structured-container traversal or bounded decoder with exact source-span truth |
| Positional/encoded passwords | `.pgpass`, `.netrc`, `.git-credentials`, Docker auth, FileZilla/JetBrains encodings and SQL password columns | Bounded field-role parsers; avoid one-off regexes |
| Application-password aliases | `APP_KEY`, `IRC_PASS`, `MLAB_PASS` and similar reviewed qualifiers | Reviewed alias family with negative fixtures; no generic `PASS` rule |
| Structured containers | Archives, SQLite/BSON and binary containers | Bounded expansion with member-level source attribution; never count a container as inspected |
| TOTP seeds | `otpauth`/seed contexts | Structured URI/parameter parsing with exact component offsets |
| Provider token gaps | Levain mailgun/xai/fireworks/databricks/etc. | Provider-specific rules and validators with independent fixtures |
| Private-key formats | PKCS#12, PPK, additional PEM containers | Binary/structural validators with public/certificate negatives |
| Encrypted browser credentials | Firefox/Chrome encrypted fields | Requires separate key material; out of scanner scope |
| Password-hash representations | `/etc/shadow`, `.htpasswd` | Format-aware support or explicit unsupported disposition |
| URL/connection-string passwords | Some forms remain unparsed | Extend the existing URI component extractor without weakening identity |
| Duplicate history delivery | Repeated occurrences across commits | Resolve at occurrence identity/reporting boundary, not by cross-commit dedupe |
| ANSI/masked/bot-auth false positives | Existing controls | Continue reviewed negative fixtures; no blanket suppression |

## PEM scoring discrepancy

The independent harness identified a PEM scoring discrepancy affecting 53 of 59
observed PEM findings. This remains a **cross-scanner scoring investigation**, not
a scanner rule change. Do not modify the independent benchmark oracle in CP5.

## Boundaries

- No broad recall-only loosening.
- No bare `KEY`, `SALT`, `PASS` or high-entropy global rule.
- Each future candidate requires exact-byte positive and negative fixtures before
  implementation.
- The independent harness remains the scoring authority; local target checks are
  diagnostic evidence only.
