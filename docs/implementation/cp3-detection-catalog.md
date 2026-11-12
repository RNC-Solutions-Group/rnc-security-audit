# CP3 detection catalog

> **Historical CP3 evidence.** This document records the 19-rule catalog and
> ruleset `2026.11.2` as validated for CP3. The current CP4 catalog is separate:
> [CP4 detection catalog](cp4-detection-catalog.md). The historical synthetic
> truth and CP3 evidence remain unchanged.
>
> **Scope:** Implemented first-party provider-format detection. Recognition of a
> format is **not** proof that a credential is active, complete, authorized or
> non-revoked. All validators are offline.

Ruleset: [`rules/rnc-providers-v1.json`](../../rules/rnc-providers-v1.json)
Schema: [`provider-rule-bundle.schema.json`](../contracts/rules/provider-rule-bundle.schema.json)
Rules: **19** across **12 families**
Ruleset version: `2026.11.2`
Current digest: `sha256:3ddd1e0aee36ecadb67ee8a2032fbe3a6047803bb56c0d45d65f85851c9b2142`

Positive counts are exact occurrences in the controlled Tier 2, held-out Tier 3
and independently authored challenge corpora. They are not universal prevalence
or production-accuracy claims.

## AWS identifier taxonomy

AWS uses the same 20-character unique-ID shape for several unrelated resources.
The catalog no longer treats every IAM unique-ID prefix as an access key.

| Prefix | AWS resource type | Catalog treatment | Rule identity | Credential classification | Confidence |
| --- | --- | --- | --- | --- | --- |
| `AKIA` | Long-term access key | Credential identifier; reported as an access key ID | `aws-access-key-id` | `access-key-id` | high |
| `ASIA` | Temporary AWS STS access key ID | Credential identifier; reported as an access key ID. Only unique with its secret and session token | `aws-access-key-id` | `access-key-id` | high |
| `ABIA` | AWS STS service bearer token access key ID | Dedicated sensitive-identifier rule; not an ordinary access key. Reports the identifier, not the complete bearer token | `aws-sts-service-bearer-token-id` | `service-bearer-token-id` | medium |
| `ACCA` | Context-specific credential | Dedicated sensitive-identifier rule. AWS public documentation does not define the complete credential or usable scope | `aws-context-specific-credential-id` | `context-specific-credential-id` | medium |
| `AIDA` | IAM user | Ordinary resource identifier; **not emitted** | none | none | n/a |
| `AGPA` | IAM group | Ordinary resource identifier; **not emitted** | none | none | n/a |
| `AIPA` | EC2 instance profile | Ordinary resource identifier; **not emitted** | none | none | n/a |
| `ANPA` | Managed policy | Ordinary resource identifier; **not emitted** | none | none | n/a |
| `ANVA` | Managed policy version | Ordinary resource identifier; **not emitted** | none | none | n/a |
| `APKA` | Public key | Ordinary resource identifier; **not emitted** | none | none | n/a |
| `AROA` | IAM role | Ordinary resource identifier; **not emitted** | none | none | n/a |
| `ASCA` | Certificate | Ordinary resource identifier; **not emitted** | none | none | n/a |

The `AKIA`/`ASIA` rule and validators reject the other eight prefixes. `ABIA` and
`ACCA` have distinct rule identities, credential types, validators and
`PLAUSIBLE_UNVERIFIED` validation notes. None of these values proves possession
of a usable credential. The AWS taxonomy suite is
[`tests/cp3/aws-identifier-taxonomy.json`](../../tests/cp3/aws-identifier-taxonomy.json).

## GitHub App installation tokens

| Format | Recognition | Validation | Status |
| --- | --- | --- | --- |
| Legacy opaque `ghs_` token | `ghs_` plus exactly 36 alphanumerics | Length, charset, placeholder, entropy | Supported |
| Stateless `ghs_APPID_JWT` token | `ghs_` + bounded app ID + `_` + three bounded base64url segments separated by exactly two dots | Documented framing and alphabet only; modern tokens are opaque and marked `PLAUSIBLE_UNVERIFIED` | Supported |
| OAuth `gho_`, user-to-server `ghu_`, refresh `ghr_` | Separate `github-oauth-app-token` rule | Existing bounded validation | Preserved |
| Unrecognized `ghs_` variants | Not emitted | Explicitly rejected | Unsupported |

The stateless format is documented at approximately 520 characters, but the rule
does not require that exact length. It accepts bounded variable lengths, does not
verify a signature or issuer, does not trust embedded JWT claims and never calls
GitHub. The recommended upstream regex is broader than the validator; this
catalog deliberately requires the documented three-segment structure to avoid
turning every `ghs_` string into a credential.

## Full catalog

| Provider | Family / credential type | Rule | Detection basis | Offline validators | Confidence | Positives T2 / T3 / challenge | Negative and near-miss coverage | Status |
| --- | --- | --- | --- | --- | --- | ---: | --- | --- |
| AWS | `aws-credentials` / access key ID | `aws-access-key-id` | `AKIA` or `ASIA` + 16 uppercase alphanumerics, byte-boundary and ANSI-aware | Length, prefix, charset, placeholder, entropy downgrade | high | 4 / 1 / 3 | Docs example, short value, unknown prefix, all eight resource prefixes, invalid characters | Implemented |
| AWS | `aws-credentials` / STS service bearer token ID | `aws-sts-service-bearer-token-id` | `ABIA` + 16 uppercase alphanumerics | Length, charset, placeholder, identifier-only plausible note | medium | 0 / 0 / 1 | Access-key prefixes, resource prefixes, malformed length, docs placeholder | Implemented; identifier-only |
| AWS | `aws-credentials` / context-specific credential ID | `aws-context-specific-credential-id` | `ACCA` + 16 uppercase alphanumerics | Length, charset, placeholder, identifier-only plausible note | medium | 0 / 0 / 1 | Access-key prefixes, resource prefixes, malformed length, docs placeholder | Implemented; identifier-only |
| AWS | `aws-credentials` / secret access key | `aws-secret-access-key` | Assignment-name context + 40-character base64 alphabet | Length, charset, placeholder, entropy downgrade | high | 1 / 0 / 1 | Docs example, wrong length, bare value without context | Implemented |
| AWS | `aws-credentials` / Terraform resource secret | `aws-secret-access-key-terraform` | Bounded `aws_iam_access_key` resource context | Same as above | high | 0 / 0 / 0 | Non-AWS Terraform blocks, bare `secret =` outside resource context; one Levain Terraform positive detected externally | Experimental integration |
| Google Cloud | `google-cloud-api-key` / API key | `google-api-key` | Documented `AIza` + 35 base64url characters | Prefix, length, charset, placeholder, entropy downgrade | high | 2 / 1 / 0 | All-A placeholder, wrong prefix/length | Implemented |
| GitHub | `github-token` / classic PAT | `github-classic-pat` | `ghp_` + 36 alphanumerics | Prefix, length, charset, placeholder, entropy downgrade | high | 5 / 2 / 1 | Short value, docs example, wrong prefix | Implemented |
| GitHub | `github-token` / fine-grained PAT | `github-fine-grained-pat` | `github_pat_` + 82 token characters | Prefix, length, charset, placeholder, entropy downgrade | high | 1 / 1 / 0 | Short value, wrong prefix, placeholder | Implemented |
| GitHub | `github-token` / OAuth, user-to-server or refresh token | `github-oauth-app-token` | `gho_`/`ghu_`/`ghr_` + bounded body | Prefix, length, charset, long-variant downgrade | medium | 1 / 0 / 0 | Short value, wrong prefix, docs placeholder, `ghs_` tokens excluded | Implemented |
| GitHub | `github-token` / App installation token | `github-app-installation-token` | Legacy opaque and stateless `ghs_APPID_JWT` structures | Legacy length/charset; modern segment framing/base64url; placeholder, entropy | high | 0 / 0 / 3 | Short value, missing segment, missing app separator, malformed dots, placeholder, oversize | Implemented; modern structure-only |
| GitLab | `gitlab-pat` / personal/group/project token | `gitlab-personal-access-token` | `glpat-` + 20 token characters | Prefix, length, charset, placeholder, entropy downgrade | high | 1 / 1 / 0 | Project ID, short token, trailing-hyphen edge | Implemented |
| Stripe | `stripe-secret-key` / secret API key | `stripe-secret-api-key` | `sk_`/`rk_` + live/test + bounded body | Prefix, length, charset, placeholder, entropy downgrade | high | 1 / 1 / 0 | Publishable `pk_` key, short key, placeholder | Implemented |
| Slack | `slack-token` / bot, user, app or refresh token | `slack-token` | `xox[baprs]-`/`xapp-` + bounded body | Prefix, length, trailing hyphen, placeholder, entropy downgrade | medium | 1 / 1 / 0 | Wrong `xoxq` prefix, short token, malformed tail | Implemented |
| SendGrid | `sendgrid-api-key` / API key | `sendgrid-api-key` | `SG.` + 22 + `.` + 43 base64url characters | Exact segments, length, charset, placeholder, entropy downgrade | high | 1 / 1 / 0 | Wrong segment lengths, short value | Implemented |
| npm | `npm-token` / auth token | `npm-auth-token` | `npm_` + 36 alphanumerics | Prefix, length, charset, placeholder, entropy downgrade | high | 2 / 1 / 2 | Legacy value, short token, placeholder | Implemented |
| PEM | `pem-private-key` / private-key container | `pem-private-key` | Bounded multiline private-key BEGIN/END labels, indentation and CRLF tolerant | Label match, base64, minimum decoded size, key-family/DER shape, OpenSSH magic | high | 3 / 1 / 0 | Public key, certificate, malformed base64, mismatched labels, repeated placeholder body | Implemented; structural only |
| JWT | `jwt-bearer` / bearer token | `jwt-bearer-token` | Explicit `Bearer` authorization context + three bounded segments | Base64url, JSON header/payload, `alg`, signature encoding, unsigned downgrade | medium | 1 / 1 / 0 | Bare JWT without Bearer, malformed JSON, invalid signature encoding | Experimental |
| Database | `database-connection-string` / userinfo | `database-connection-credential` | Known DB URI scheme + userinfo with password + bounded host | Split fields, length, percent encoding, variables, placeholders, entropy downgrade | medium | 1 / 1 / 1 | URL without credentials, `${VAR}`, `__PASSWORD__`, `<password>`, malformed percent encoding | Experimental |
| Generic | `generic-secret-assignment` / assigned secret | `generic-secret-assignment` | Assignment-name context, bounded value, ANSI/command-line prefixes | Variables, placeholders, common values, provider-shaped rejection, entropy downgrade | low | 2 / 2 / 1 | `"password"`, `${VAR}`, all-same, provider-shaped value, public values | Experimental; low confidence |

The challenge corpus is separately authored, not generated by
`tools/cp3/fixtures.py`. It is reported separately and is not combined with
Tier 2/Tier 3 to form a universal accuracy percentage.

## Explicitly unsupported or out of scope

- AWS resource identifiers `AIDA`, `AGPA`, `AIPA`, `ANPA`, `ANVA`, `APKA`,
  `AROA` and `ASCA` as credential findings. They are ordinary IAM resource IDs.
  `ABIA`/`ACCA` are reported only by their dedicated identifier rules.
- A complete AWS STS service bearer token. The catalog recognizes the `ABIA`
  access-key-ID component, not a complete bearer token or its service scope.
- The complete semantics of an `ACCA` context-specific credential. Public AWS
  documentation does not define its usable scope.
- AWS secret keys without an assignment or recognized Terraform resource context.
- Google service-account JSON, OAuth refresh tokens and project identifiers.
- GitHub token families without a recognized prefix; arbitrary or malformed
  `ghs_` strings and fixed-length assumptions.
- GitLab route/job/deploy tokens not using `glpat-`.
- Stripe publishable keys; Slack webhook URLs; Twilio, SendGrid subaccounts and
  other provider families not listed above.
- Public keys, certificates and generic PEM text. Only private-key containers
  are in scope.
- Bare JWTs without an explicit Bearer context.
- Password-only strings with no assignment context.
- Git-history input. RNC Scanner currently scans an authorized working tree.
- Live validation, decryption, provider API calls and credential redemption.

## Confidence semantics

- **high:** a documented, tightly bounded format plus structural validation.
  This remains format confidence, not proof of active access.
- **medium:** a documented family with variable segments/lengths, a
  service-scoped identifier, or a structured credential that cannot be verified
  offline.
- **low:** a generic assignment that is plausible but not provider-specific.
- A candidate that is structurally plausible but not independently verifiable is
  labeled `PLAUSIBLE_UNVERIFIED` in the finding's `validation` array and has its
  confidence downgraded. It is not silently discarded.
- A candidate that fails structural validation or is a known placeholder is not
  emitted.

## Fixture safety

All committed values are deterministic synthetic strings. The private-key
fixtures are structurally shaped DER/OpenSSH containers with deliberately
inconsistent RSA values; they are not usable keys and no active credential was
generated or committed. Provider-shaped source bytes are committed as a hex
bundle and materialized only in temporary test roots where necessary. The
independently authored challenge source is built at test time from harmless
synthetic values.
