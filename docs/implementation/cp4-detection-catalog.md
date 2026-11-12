# CP4 detection catalog

> **Status:** Implemented CP4 catalog. Recognition of a format is **not** proof
> that a credential is active, complete, authorized or non-revoked. All
> validators are offline; no provider API is called.

Ruleset: [`rules/rnc-providers-v1.json`](../../../rules/rnc-providers-v1.json)  
Schema: [`provider-rule-bundle.schema.json`](../../contracts/rules/provider-rule-bundle.schema.json)  
Rules: **37** across **22 families**  
Ruleset version: `2026.11.3`  
Current digest: `sha256:4956b11f44090d472aa9254ed6489cf3dcf24e01816d724a07123703e6e1dc7e`

The digest binds every rule's provider/family/credential/context metadata,
`value_capture_groups`, fixture set and provenance. Existing CP3 synthetic
bundles and their historical truth are unchanged.

## What CP4 added

CP4 expands three areas:

1. **Generic credential extraction** across configuration syntaxes and
   authorization contexts, with a reusable plausible-only validator. See
   [generic credentials](cp4-generic-credentials.md).
2. **Private-key representations**: escaped PEM, base64-wrapped PEM, PGP secret
   armor and log-embedded PEM, in addition to the CP3 raw PEM container. See
   [private-key handling](cp4-private-keys.md).
3. **Provider families** with official vendor format evidence: Azure Storage
   connection-string account keys, Tailscale key-prefix family, Groq, xAI,
   Perplexity, Doppler service tokens, Slack incoming webhook URLs and
   OpenAI-labelled `sk-` keys. Weakly documented families are explicitly
   experimental.

The existing CP3 catalog remains the baseline for AWS, Google Cloud, GitHub,
GitLab, Stripe, Slack tokens, SendGrid, npm, JWT, database URIs and PEM. The CP3
catalog history is preserved in [CP3 detection catalog](cp3-detection-catalog.md).

## Full catalog

The `Tests` column counts independent positive / negative cases in the CP4
regression suite or, for CP3 rules, the controlled Tier 2/3/challenge suites.
`Status` distinguishes implemented, experimental and identifier-only rules.

| Provider | Family | Rule | Credential type | Validators | Confidence | Tests +/− | Status |
| --- | --- | --- | --- | --- | --- | ---: | --- |
| AWS | `aws-credentials` | `aws-access-key-id` | access key ID | `AWS_ACCESS_KEY_ID` | high | 8 / 20 taxonomy | Implemented |
| AWS | `aws-credentials` | `aws-sts-service-bearer-token-id` | service bearer token ID | `AWS_SERVICE_BEARER_TOKEN_ID` | medium | 1 / 4 | Identifier-only |
| AWS | `aws-credentials` | `aws-context-specific-credential-id` | context-specific credential ID | `AWS_CONTEXT_SPECIFIC_CREDENTIAL_ID` | medium | 1 / 4 | Identifier-only |
| AWS | `aws-credentials` | `aws-secret-access-key` | secret access key | `AWS_SECRET_ACCESS_KEY` | high | 3 / 4 | Implemented |
| AWS | `aws-credentials` | `aws-secret-access-key-terraform` | Terraform resource secret | `AWS_SECRET_ACCESS_KEY` | high | 1 / 2 | Experimental integration |
| Google Cloud | `google-cloud-api-key` | `google-api-key` | API key | `GOOGLE_API_KEY` | high | 3 / 4 | Implemented |
| GitHub | `github-token` | `github-classic-pat` | classic PAT | `GITHUB_CLASSIC_PAT` | high | 8 / 5 | Implemented |
| GitHub | `github-token` | `github-fine-grained-pat` | fine-grained PAT | `GITHUB_FINE_GRAINED_PAT` | high | 2 / 4 | Implemented |
| GitHub | `github-token` | `github-oauth-app-token` | OAuth/user/refresh token | `GITHUB_OAUTH_TOKEN` | medium | 1 / 4 | Implemented |
| GitHub | `github-token` | `github-app-installation-token` | App installation token | `GITHUB_APP_INSTALLATION_TOKEN` | high | 4 / 10 | Implemented; modern structure-only |
| GitLab | `gitlab-pat` | `gitlab-personal-access-token` | personal/group/project PAT | `GITLAB_PAT` | high | 2 / 4 | Implemented |
| Stripe | `stripe-secret-key` | `stripe-secret-api-key` | secret API key | `STRIPE_SECRET_KEY` | high | 2 / 3 | Implemented |
| Slack | `slack-token` | `slack-token` | bot/user/app/refresh token | `SLACK_TOKEN` | medium | 2 / 4 | Implemented |
| Slack | `slack-webhook` | `slack-incoming-webhook` | incoming webhook URL | `SLACK_WEBHOOK` | medium | 1 / 3 | Implemented; URL structure-only |
| SendGrid | `sendgrid-api-key` | `sendgrid-api-key` | API key | `SENDGRID_API_KEY` | high | 2 / 3 | Implemented |
| npm | `npm-token` | `npm-auth-token` | auth token | `NPM_TOKEN` | high | 5 / 4 | Implemented |
| Azure | `azure-storage` | `azure-storage-account-key` | storage account key | `AZURE_STORAGE_ACCOUNT_KEY` | high | 1 / 4 | Implemented |
| Tailscale | `tailscale-key` | `tailscale-key` | auth/API/OAuth/SCIM/webhook key | `TAILSCALE_KEY` | medium | 1 / 4 | Implemented; prefix family |
| Groq | `groq-api-key` | `groq-api-key` | API key | `GROQ_API_KEY` | medium | 1 / 4 | Experimental; prefix only |
| xAI | `xai-api-key` | `xai-api-key` | API key | `XAI_API_KEY` | medium | 1 / 4 | Experimental; example-shaped |
| Perplexity | `perplexity-api-key` | `perplexity-api-key` | API key | `PERPLEXITY_API_KEY` | low | 1 / 4 | Experimental; prefix only |
| Doppler | `doppler-service-token` | `doppler-service-token` | service token | `DOPPLER_SERVICE_TOKEN` | medium | 1 / 4 | Experimental; segment structure |
| OpenAI | `openai-api-key` | `openai-api-key` | API key | `OPENAI_API_KEY` | low | 1 / 4 | Experimental; labelled assignment only |
| PEM | `pem-private-key` | `pem-private-key` | private-key container | `PEM_PRIVATE_KEY` | high | 3 / 8 | Implemented; structural |
| PEM | `pem-private-key` | `pem-private-key-escaped` | escaped private-key container | `ESCAPED_PEM_PRIVATE_KEY` | medium | 1 / 3 | Implemented; structural |
| PEM | `pem-private-key` | `pem-private-key-base64` | base64-wrapped private key | `BASE64_PEM_PRIVATE_KEY` | medium | 1 / 3 | Implemented; structural |
| PGP | `pgp-private-key` | `pem-private-key-pgp` | PGP secret-key armor | `PGP_PRIVATE_KEY` | medium | 1 / 4 | Implemented; structural, plausible |
| Generic | `generic-secret-assignment` | `generic-secret-assignment` | assigned secret | `GENERIC_ASSIGNED_SECRET` | low | 17 / 12 | Implemented; plausible only |
| Generic | `generic-assignment` | `generic-array-assignment` | bracket assignment | `GENERIC_ASSIGNED_SECRET` | low | 1 / 3 | Implemented; plausible only |
| Generic | `generic-assignment` | `generic-multiline-assignment` | YAML block scalar | `MULTILINE_ASSIGNED_SECRET` | low | 1 / 3 | Implemented; plausible only |
| Generic | `generic-assignment` | `generic-xml-assignment` | XML element value | `GENERIC_ASSIGNED_SECRET` | low | 2 / 3 | Implemented; plausible only |
| Generic | `generic-assignment` | `generic-sql-password` | SQL password literal | `SQL_PASSWORD` | low | 1 / 3 | Implemented; plausible only |
| Generic | `generic-assignment` | `http-basic-authorization` | HTTP Basic credentials | `HTTP_BASIC_AUTH` | low | 1 / 3 | Implemented; plausible only |
| Generic | `generic-assignment` | `http-bearer-opaque` | opaque Bearer token | `HTTP_BEARER_OPAQUE` | low | 1 / 3 | Implemented; plausible only |
| Generic | `generic-assignment` | `credential-url-userinfo` | URL userinfo | `URL_USERINFO` | low | 1 / 3 | Implemented; plausible only |
| Database | `database-connection-string` | `database-connection-credential` | URI userinfo | `DATABASE_URI` | medium | 3 / 5 | Experimental |

The generic family has two family names for historical compatibility:
`generic-secret-assignment` is the CP3 rule identity, and `generic-assignment`
groups the CP4 context-specific rules. Both are generic-credential categories,
not verified provider credentials.

## Provider evidence and uncertainty

Only official vendor documentation was used. Partial formats are implemented
conservatively and marked experimental; no rule is justified by a third-party
scanner catalog.

| Family | Official evidence | Implementation decision |
| --- | --- | --- |
| Azure Storage | 512-bit account key; `AccountKey=` connection-string grammar | Require `AccountKey=` context and 64-byte base64 decoding; high-confidence shape |
| Tailscale | `tskey-` plus documented type prefix family; body length not fixed | Require documented type prefix, bound the body, plausible only |
| Groq | `gsk_` prefix shown; length/alphabet not specified | Bound 20-156 chars, entropy floor, plausible only |
| xAI | Official example `xai-` + 80 alphanumerics; no normative length statement | Match the documented example shape, plausible only |
| Perplexity | `pplx-` prefix; documented example is a synthetic placeholder | Require longer bounded body and entropy; experimental |
| Doppler | `dp.st.` plus dot-separated segments; no fixed length | Require segment structure, final segment ≥16 chars; experimental |
| Slack webhook | Official host/path shape `T.../B.../<secret>`; lengths illustrative | Require shape, reject placeholder webhook paths; URL is the secret |
| OpenAI | Official docs show only `sk-` and do not state length/project prefixes | Require an OpenAI-labelled assignment and `sk-` prefix; experimental; project/service-account prefixes are not claimed as verified |

### Deliberately unsupported or deferred

These were researched but are **not** implemented as provider-specific rules
because the vendor does not document a reliable offline format:

- Mailgun API keys (no documented prefix/length/alphabet);
- Pinecone API keys (no documented value format; UUIDs are identifiers);
- Databricks personal access tokens (opaque `token_value`);
- HashiCorp Vault tokens (vendor explicitly calls structure undocumented);
- Terraform Cloud/Enterprise API tokens (no documented prefix/length);
- Airtable personal access tokens (length/structure documented, but no
  documented alphabet/prefix; generic detection would be speculative);
- Azure SAS fields beyond the account-key connection-string case;
- OpenAI project/service-account-specific prefixes.

These families may still be found by generic assignment context when a value is
present in a credential-named field, but they do not receive a provider identity
or provider-specific claim. Reporting them as unsupported is preferable to
inventing broad signatures.

## Classification boundaries

CP4 does not add payment-card numbers, email addresses, public keys,
certificates, ordinary cloud resource identifiers or general PII to the core
credential catalog. `AIDA`, `AGPA`, `AIPA`, `ANPA`, `ANVA`, `APKA`, `AROA` and
`ASCA` remain non-credential identifiers. AWS `ABIA` and `ACCA` remain
identifier-only sensitive identifiers.

## Confidence and validation notes

- `FORMAT_VALID` means the offline structural checks passed; it does not mean
  the credential is active.
- `PLAUSIBLE_UNVERIFIED` is used for opaque, variable-length, prefix-only,
  context-only or structurally unverified values.
- A rule with `medium` or `low` declared confidence can be further downgraded
  when validation is plausible only.
- Provider format changes can make a formerly valid shape obsolete. The ruleset
  version and digest are part of every execution record.

## Regression evidence

The Rust `cp4_detection` suite verifies all new generic, private-key and provider
positives and negatives across whole/stream modes and `regex`/`regexset`/
`prefilter`/`auto`. The CP3 catalog truth remains exact at **27/27**, **15/15**
and **14/14** across all eight combinations; no historical truth was changed.
CP4's Git-history suite adds seven commit/path occurrence tests.
