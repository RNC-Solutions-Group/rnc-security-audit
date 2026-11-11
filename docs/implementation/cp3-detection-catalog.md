# CP3 detection catalog

> **Scope:** Implemented first-party provider-format detection. Recognition of a
> format is **not** proof that a credential is active, complete, authorized or
> non-revoked. All validators are offline.

Ruleset: [`rules/rnc-providers-v1.json`](../../../rules/rnc-providers-v1.json)
Schema: [`provider-rule-bundle.schema.json`](../../contracts/rules/provider-rule-bundle.schema.json)
Rules: **16** across **12 families**
Current digest: `sha256:e2900d9095a6f32240ea7a3e2e25e138fb5f57e35decc426efbd1e3d8f24a658`

Positive counts are exact occurrences in the controlled Tier 2 corpus and the
separately authored held-out Tier 3 corpus. Negative coverage is documented by
the fixture set and validator tests; it is not a claim that every possible
benign lookalike has been exhaustively enumerated.

| Provider | Family / credential type | Rules | Detection basis | Offline validators | Confidence | Positives T2 / T3 | Negative and near-miss coverage | Status |
| --- | --- | --- | --- | --- | --- | ---: | --- | --- |
| AWS | `aws-credentials` / access key ID | `aws-access-key-id` | Documented IAM prefixes + 16 uppercase alphanumerics, byte-boundary and ANSI-aware | Length, prefix, character set, placeholder, entropy downgrade | high | 4 / 1 | Docs example, short value, unknown prefix | Implemented |
| AWS | `aws-credentials` / secret access key | `aws-secret-access-key` | Assignment-name context + 40-character base64 alphabet | Length, charset, placeholder, entropy downgrade | high | 1 / 0 | Docs example, wrong length, bare value without context | Implemented |
| AWS | `aws-credentials` / Terraform resource secret | `aws-secret-access-key-terraform` | Bounded `aws_iam_access_key` resource context | Same as above | high | 0 / 0 | Non-AWS Terraform blocks, bare `secret =` outside resource context; one Levain Terraform positive detected externally | Experimental integration |
| Google Cloud | `google-cloud-api-key` / API key | `google-api-key` | Documented `AIza` + 35 base64url characters | Prefix, length, charset, placeholder, entropy downgrade | high | 2 / 1 | All-A placeholder, wrong prefix/length | Implemented |
| GitHub | `github-token` / classic PAT | `github-classic-pat` | `ghp_` + 36 alphanumerics | Prefix, length, charset, placeholder, entropy downgrade | high | 5 / 2 | Short value, docs example, wrong prefix | Implemented |
| GitHub | `github-token` / fine-grained PAT | `github-fine-grained-pat` | `github_pat_` + 82 token characters | Prefix, length, charset, placeholder, entropy downgrade | high | 1 / 1 | Short value, wrong prefix, placeholder | Implemented |
| GitHub | `github-token` / OAuth or app token | `github-oauth-app-token` | `gho_`/`ghu_`/`ghs_`/`ghr_` + bounded body | Prefix, length, charset, long-variant downgrade | medium | 1 / 0 | Short value, wrong prefix, docs placeholder | Experimental |
| GitLab | `gitlab-pat` / personal/group/project token | `gitlab-personal-access-token` | `glpat-` + 20 token characters | Prefix, length, charset, placeholder, entropy downgrade | high | 1 / 1 | Project ID, short token, trailing-hyphen edge | Implemented |
| Stripe | `stripe-secret-key` / secret API key | `stripe-secret-api-key` | `sk_`/`rk_` + live/test + bounded body | Prefix, length, charset, placeholder, entropy downgrade | high | 1 / 1 | Publishable `pk_` key, short key, placeholder | Implemented |
| Slack | `slack-token` / bot, user, app or refresh token | `slack-token` | `xox[baprs]-`/`xapp-` + bounded body | Prefix, length, trailing hyphen, placeholder, entropy downgrade | medium | 1 / 1 | Wrong `xoxq` prefix, short token, malformed tail | Implemented |
| SendGrid | `sendgrid-api-key` / API key | `sendgrid-api-key` | `SG.` + 22 + `.` + 43 base64url characters | Exact segments, length, charset, placeholder, entropy downgrade | high | 1 / 1 | Wrong segment lengths, short value | Implemented |
| npm | `npm-token` / auth token | `npm-auth-token` | `npm_` + 36 alphanumerics | Prefix, length, charset, placeholder, entropy downgrade | high | 2 / 1 | Legacy value, short token, placeholder | Implemented |
| PEM | `pem-private-key` / private-key container | `pem-private-key` | Bounded multiline private-key BEGIN/END labels, indentation and CRLF tolerant | Label match, base64, minimum decoded size, key-family/DER shape, OpenSSH magic | high | 3 / 1 | Public key, certificate, malformed base64, mismatched labels, repeated placeholder body | Implemented; structural only |
| JWT | `jwt-bearer` / bearer token | `jwt-bearer-token` | Explicit `Bearer` authorization context + three bounded segments | Base64url, JSON header/payload, `alg`, signature encoding, unsigned downgrade | medium | 1 / 1 | Bare JWT without Bearer, malformed JSON, invalid signature encoding | Experimental |
| Database | `database-connection-string` / userinfo | `database-connection-credential` | Known DB URI scheme + userinfo with password + bounded host | Split fields, length, percent encoding, variables, placeholders, entropy downgrade | medium | 1 / 1 | URL without credentials, `${VAR}`, `__PASSWORD__`, `<password>`, malformed percent encoding | Experimental |
| Generic | `generic-secret-assignment` / assigned secret | `generic-secret-assignment` | Assignment-name context, bounded value, ANSI/command-line prefixes | Variables, placeholders, common values, provider-shaped rejection, entropy downgrade | low | 2 / 2 | `"password"`, `${VAR}`, all-same, provider-shaped value, public values | Experimental; low confidence |

## Explicitly unsupported or out of scope

- AWS secret keys without an assignment or recognized Terraform resource context.
- Google service-account JSON, OAuth refresh tokens and project identifiers.
- GitHub token families without a recognized prefix; new token lengths are
  reported as plausible when they match the bounded prefix family.
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
- **medium:** a documented family with variable segments/lengths, or a
  structured credential that cannot be verified offline.
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
generated or committed.
