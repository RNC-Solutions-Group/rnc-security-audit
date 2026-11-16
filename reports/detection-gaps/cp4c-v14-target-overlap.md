# CP4C, V14 and V16 target-level detection overlap

This is a shared comparison over exact oracle target IDs from the retained current-scoring reports. Gitleaks master and Betterleaks 1.8.1 are included as external comparators. It does not replace either scanner's standalone report, and it does not treat raw string similarity as a match.

## Scanner coverage

| Scanner | Expected | Matched | Missed | Recall | Unique successes | Only-scanner misses |
| --- | --- | --- | --- | --- | --- | --- |
| RNC Scanner CP4C | 1125 | 570 | 555 | 50.67% | 30 | 158 |
| RNC-Mod V14 | 1125 | 591 | 534 | 52.53% | 0 | 0 |
| RNC-Mod V16 | 1125 | 592 | 533 | 52.62% | 1 | 0 |
| Gitleaks master | 1125 | 589 | 536 | 52.36% | 0 | 0 |
| Betterleaks 1.8.1 | 1125 | 717 | 408 | 63.73% | 26 | 5 |

All-scanner misses: **368** (282 risk-bearing, 86 oracle-informative). These are the targets no compared scanner credited; risk-bearing cases are the strongest candidates for a corpus/source question rather than a single scanner defect.

## Common misses

| Lane | Common misses |
| --- | --- |
| levain | 21 |
| leaky_filesystem | 132 |
| leaky_git | 27 |
| rnclab_filesystem | 187 |
| rnclab_git | 1 |

| Category | Common misses |
| --- | --- |
| password | 229 |
| unknown_credential | 66 |
| private_key | 19 |
| api_key | 18 |
| provider_token | 16 |
| otp_seed | 12 |
| hmac_secret | 6 |
| payment_data | 2 |

Examples: `LEV-S06-K01`, `LEV-S07-K01`, `LEV-S11-K01`, `LEV-S11-K02`, `LEV-S22-K01`, `LEV-S22-K02`, `LEV-S26-K01`, `LEV-S27-K02`, `LEV-S29-K01`, `LEV-S29-K06`, `LEV-S30-K02`, `LEV-S30-K04`.

## Unique misses and complementary coverage

| Scanner | Only this scanner missed | Example target IDs |
| --- | --- | --- |
| RNC Scanner CP4C | 158 | `LEV-S05-K01`, `LEV-S15-K01`, `LEV-S17-K01`, `LEV-S20-K01`, `LEV-S21-K01`, `LEV-S27-K04`, `LEV-S28-K03`, `LEV-S29-K02` |
| RNC-Mod V14 | 0 | - |
| RNC-Mod V16 | 0 | - |
| Gitleaks master | 0 | - |
| Betterleaks 1.8.1 | 5 | `RNC-SL-POS-000018`, `RNC-SL-POS-000066`, `RNC-SL-POS-000094`, `RNC-SL-POS-000231`, `RNC-SL-POS-000564` |

A target listed here is credited by every other compared scanner and missed by this scanner. It is the strongest evidence of a scanner-specific coverage gap rather than an unreadable source or an oracle ambiguity.

## CP4C misses found by another scanner

### RNC-Mod V14 - 160 of 555 CP4C misses

| Category | Count |
| --- | --- |
| password | 62 |
| hmac_secret | 58 |
| provider_token | 33 |
| private_key | 3 |
| unknown_credential | 3 |
| api_key | 1 |

| Target | Lane | Category | Subtype | Root cause | Found by | Sample location |
| --- | --- | --- | --- | --- | --- | --- |
| LEV-S05-K01 | levain | private_key | rsa_private_key_pkcs1 | FORMAT_UNSUPPORTED | betterleaks, gitleaks, v14, v16 | 005-gpg-secret-key-export.log:4 |
| LEV-S15-K01 | levain | provider_token | twilio_api_key_sid | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 015-twilio-sdk-error.log:8 |
| LEV-S17-K01 | levain | provider_token | mailgun_api_key | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 017-mailgun-delivery-log.log:2 |
| LEV-S20-K01 | levain | private_key | rsa_private_key_pkcs1 | FORMAT_UNSUPPORTED | betterleaks, gitleaks, v14, v16 | 020-ssh-private-key-in-log.log:5 |
| LEV-S21-K01 | levain | private_key | rsa_private_key_pkcs1 | FORMAT_UNSUPPORTED | betterleaks, gitleaks, v14, v16 | 021-gcp-service-account-json.log:5 |
| LEV-S27-K04 | levain | provider_token | fireworks_api_key | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 027-ai-gateway-upstream-errors.log:5 |
| LEV-S28-K03 | levain | provider_token | elevenlabs_api_key | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 028-inference-worker-traceback.log:7 |
| LEV-S29-K02 | levain | provider_token | databricks_pat | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 029-platform-cli-auth-failures.log:3 |
| LEV-S29-K03 | levain | provider_token | grafana_service_account_token | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 029-platform-cli-auth-failures.log:4 |
| LEV-S29-K04 | levain | provider_token | planetscale_token | RULE_ABSENT | gitleaks, v14, v16 | 029-platform-cli-auth-failures.log:5 |
| LEV-S30-K01 | levain | provider_token | rubygems_api_key | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 030-ci-publish-step-output.log:2 |
| LEV-S30-K03 | levain | provider_token | sonarqube_token | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 030-ci-publish-step-output.log:6 |

### RNC-Mod V16 - 161 of 555 CP4C misses

| Category | Count |
| --- | --- |
| password | 62 |
| hmac_secret | 58 |
| provider_token | 34 |
| private_key | 3 |
| unknown_credential | 3 |
| api_key | 1 |

| Target | Lane | Category | Subtype | Root cause | Found by | Sample location |
| --- | --- | --- | --- | --- | --- | --- |
| LEV-S05-K01 | levain | private_key | rsa_private_key_pkcs1 | FORMAT_UNSUPPORTED | betterleaks, gitleaks, v14, v16 | 005-gpg-secret-key-export.log:4 |
| LEV-S15-K01 | levain | provider_token | twilio_api_key_sid | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 015-twilio-sdk-error.log:8 |
| LEV-S17-K01 | levain | provider_token | mailgun_api_key | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 017-mailgun-delivery-log.log:2 |
| LEV-S20-K01 | levain | private_key | rsa_private_key_pkcs1 | FORMAT_UNSUPPORTED | betterleaks, gitleaks, v14, v16 | 020-ssh-private-key-in-log.log:5 |
| LEV-S21-K01 | levain | private_key | rsa_private_key_pkcs1 | FORMAT_UNSUPPORTED | betterleaks, gitleaks, v14, v16 | 021-gcp-service-account-json.log:5 |
| LEV-S27-K04 | levain | provider_token | fireworks_api_key | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 027-ai-gateway-upstream-errors.log:5 |
| LEV-S28-K03 | levain | provider_token | elevenlabs_api_key | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 028-inference-worker-traceback.log:7 |
| LEV-S29-K02 | levain | provider_token | databricks_pat | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 029-platform-cli-auth-failures.log:3 |
| LEV-S29-K03 | levain | provider_token | grafana_service_account_token | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 029-platform-cli-auth-failures.log:4 |
| LEV-S29-K04 | levain | provider_token | planetscale_token | RULE_ABSENT | gitleaks, v14, v16 | 029-platform-cli-auth-failures.log:5 |
| LEV-S30-K01 | levain | provider_token | rubygems_api_key | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 030-ci-publish-step-output.log:2 |
| LEV-S30-K03 | levain | provider_token | sonarqube_token | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 030-ci-publish-step-output.log:6 |

### Gitleaks master - 160 of 555 CP4C misses

| Category | Count |
| --- | --- |
| password | 62 |
| hmac_secret | 58 |
| provider_token | 33 |
| private_key | 3 |
| unknown_credential | 3 |
| api_key | 1 |

| Target | Lane | Category | Subtype | Root cause | Found by | Sample location |
| --- | --- | --- | --- | --- | --- | --- |
| LEV-S05-K01 | levain | private_key | rsa_private_key_pkcs1 | FORMAT_UNSUPPORTED | betterleaks, gitleaks, v14, v16 | 005-gpg-secret-key-export.log:4 |
| LEV-S15-K01 | levain | provider_token | twilio_api_key_sid | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 015-twilio-sdk-error.log:8 |
| LEV-S17-K01 | levain | provider_token | mailgun_api_key | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 017-mailgun-delivery-log.log:2 |
| LEV-S20-K01 | levain | private_key | rsa_private_key_pkcs1 | FORMAT_UNSUPPORTED | betterleaks, gitleaks, v14, v16 | 020-ssh-private-key-in-log.log:5 |
| LEV-S21-K01 | levain | private_key | rsa_private_key_pkcs1 | FORMAT_UNSUPPORTED | betterleaks, gitleaks, v14, v16 | 021-gcp-service-account-json.log:5 |
| LEV-S27-K04 | levain | provider_token | fireworks_api_key | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 027-ai-gateway-upstream-errors.log:5 |
| LEV-S28-K03 | levain | provider_token | elevenlabs_api_key | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 028-inference-worker-traceback.log:7 |
| LEV-S29-K02 | levain | provider_token | databricks_pat | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 029-platform-cli-auth-failures.log:3 |
| LEV-S29-K03 | levain | provider_token | grafana_service_account_token | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 029-platform-cli-auth-failures.log:4 |
| LEV-S29-K04 | levain | provider_token | planetscale_token | RULE_ABSENT | gitleaks, v14, v16 | 029-platform-cli-auth-failures.log:5 |
| LEV-S30-K01 | levain | provider_token | rubygems_api_key | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 030-ci-publish-step-output.log:2 |
| LEV-S30-K03 | levain | provider_token | sonarqube_token | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 030-ci-publish-step-output.log:6 |

### Betterleaks 1.8.1 - 184 of 555 CP4C misses

| Category | Count |
| --- | --- |
| password | 85 |
| hmac_secret | 58 |
| provider_token | 33 |
| private_key | 3 |
| unknown_credential | 3 |
| api_key | 2 |

| Target | Lane | Category | Subtype | Root cause | Found by | Sample location |
| --- | --- | --- | --- | --- | --- | --- |
| LEV-S05-K01 | levain | private_key | rsa_private_key_pkcs1 | FORMAT_UNSUPPORTED | betterleaks, gitleaks, v14, v16 | 005-gpg-secret-key-export.log:4 |
| LEV-S15-K01 | levain | provider_token | twilio_api_key_sid | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 015-twilio-sdk-error.log:8 |
| LEV-S17-K01 | levain | provider_token | mailgun_api_key | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 017-mailgun-delivery-log.log:2 |
| LEV-S20-K01 | levain | private_key | rsa_private_key_pkcs1 | FORMAT_UNSUPPORTED | betterleaks, gitleaks, v14, v16 | 020-ssh-private-key-in-log.log:5 |
| LEV-S21-K01 | levain | private_key | rsa_private_key_pkcs1 | FORMAT_UNSUPPORTED | betterleaks, gitleaks, v14, v16 | 021-gcp-service-account-json.log:5 |
| LEV-S27-K04 | levain | provider_token | fireworks_api_key | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 027-ai-gateway-upstream-errors.log:5 |
| LEV-S28-K03 | levain | provider_token | elevenlabs_api_key | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 028-inference-worker-traceback.log:7 |
| LEV-S29-K02 | levain | provider_token | databricks_pat | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 029-platform-cli-auth-failures.log:3 |
| LEV-S29-K03 | levain | provider_token | grafana_service_account_token | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 029-platform-cli-auth-failures.log:4 |
| LEV-S29-K05 | levain | provider_token | supabase_access_token | RULE_ABSENT | betterleaks | 029-platform-cli-auth-failures.log:6 |
| LEV-S30-K01 | levain | provider_token | rubygems_api_key | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 030-ci-publish-step-output.log:2 |
| LEV-S30-K03 | levain | provider_token | sonarqube_token | RULE_ABSENT | betterleaks, gitleaks, v14, v16 | 030-ci-publish-step-output.log:6 |

## V14/V16 misses found by another scanner

### RNC-Mod V14

**RNC Scanner CP4C:** 139 of 534 RNC-Mod V14 misses; password=126, provider_token=5, api_key=4, hmac_secret=3, unknown_credential=1.
**Betterleaks 1.8.1:** 135 of 534 RNC-Mod V14 misses; password=133, provider_token=1, api_key=1.

### RNC-Mod V16

**RNC Scanner CP4C:** 139 of 533 RNC-Mod V16 misses; password=126, provider_token=5, api_key=4, hmac_secret=3, unknown_credential=1.
**Betterleaks 1.8.1:** 135 of 533 RNC-Mod V16 misses; password=133, provider_token=1, api_key=1.

## Betterleaks-only coverage relative to CP4C and V14

**26** targets are credited by Betterleaks but by neither CP4C nor V14.

| Category | Count |
| --- | --- |
| password | 24 |
| provider_token | 1 |
| api_key | 1 |

| Subtype | Count |
| --- | --- |
| database_password | 15 |
| application_password | 8 |
| supabase_access_token | 1 |
| generic_api_key | 1 |
| admin_password | 1 |

Examples: `LEV-S29-K05`, `leaky-repo:db/mongoid.yml:4:risk`, `RNC-SL-POS-000029`, `RNC-SL-POS-000031`, `RNC-SL-POS-000032`, `RNC-SL-POS-000034`, `RNC-SL-POS-000035`, `RNC-SL-POS-000036`, `RNC-SL-POS-000037`, `RNC-SL-POS-000038`, `RNC-SL-POS-000106`, `RNC-SL-POS-000201`, `RNC-SL-POS-000295`, `RNC-SL-POS-000443`, `RNC-SL-POS-000445`.

This is the most useful external-detection signal for both RNC scanners, but it is not a drop-in rule. Betterleaks has a different rule vocabulary, different source scope and a different negative oracle. Inspect the exact Betterleaks rule and the oracle target representation before copying a pattern.

## Different rules for the same target

541 targets are credited by at least two scanners with different rule IDs.

| Target | Subtype | Rule IDs |
| --- | --- | --- |
| LEV-S01-K02 | aws_secret_access_key | betterleaks:generic-api-key; cp4c:aws-secret-access-key; gitleaks:generic-api-key; v14:generic-api-key; v16:generic-api-key |
| LEV-S01-K03 | stripe_secret_key | betterleaks:stripe-access-token; cp4c:stripe-secret-api-key; gitleaks:stripe-access-token; v14:stripe-access-token; v16:stripe-access-token |
| LEV-S01-K04 | application_secret | betterleaks:generic-api-key; cp4c:generic-secret-assignment; gitleaks:generic-api-key; v14:generic-api-key; v16:generic-api-key |
| LEV-S02-K01 | github_personal_access_token | betterleaks:github-pat; cp4c:github-classic-pat; gitleaks:github-pat; v14:github-pat; v16:github-pat |
| LEV-S02-K02 | application_secret | betterleaks:generic-api-key; cp4c:generic-secret-assignment; gitleaks:generic-api-key; v14:generic-api-key; v16:generic-api-key |
| LEV-S03-K01 | github_personal_access_token | betterleaks:curl-auth-header; cp4c:github-fine-grained-pat; gitleaks:github-fine-grained-pat; v14:github-fine-grained-pat; v16:github-fine-grained-pat |
| LEV-S07-K02 | application_secret | betterleaks:generic-api-key; cp4c:generic-secret-assignment; gitleaks:generic-api-key; v14:generic-api-key; v16:generic-api-key |
| LEV-S09-K01 | url_password | betterleaks:generic-credential-uri; cp4c:database-connection-credential |
| LEV-S12-K01 | application_secret | betterleaks:generic-api-key; cp4c:generic-secret-assignment; gitleaks:generic-api-key; v14:generic-api-key; v16:generic-api-key |
| LEV-S12-K02 | sendgrid_api_key | betterleaks:sendgrid-api-token; cp4c:sendgrid-api-key; gitleaks:sendgrid-api-token; v14:sendgrid-api-token; v16:sendgrid-api-token |
| LEV-S13-K01 | slack_bot_token | betterleaks:slack-bot-token; cp4c:slack-token; gitleaks:slack-bot-token; v14:slack-bot-token; v16:slack-bot-token |
| LEV-S13-K02 | slack_webhook_url | betterleaks:slack-webhook-url; cp4c:slack-incoming-webhook; gitleaks:slack-webhook-url; v14:slack-webhook-url; v16:slack-webhook-url |
| LEV-S14-K01 | google_api_key | betterleaks:gcp-api-key; cp4c:google-api-key; gitleaks:gcp-api-key; v14:gcp-api-key; v16:gcp-api-key |
| LEV-S16-K01 | npm_access_token | betterleaks:npm-access-token; cp4c:npm-auth-token; gitleaks:npm-access-token; v14:npm-access-token; v16:npm-access-token |
| LEV-S18-K01 | azure_storage_key | betterleaks:azure-storage-account-key; cp4c:azure-storage-account-key; gitleaks:generic-api-key; v14:generic-api-key; v16:generic-api-key |
| LEV-S19-K01 | jwt | betterleaks:jwt; cp4c:jwt-bearer-token; gitleaks:jwt; v14:jwt; v16:jwt |
| LEV-S23-K01 | github_personal_access_token | betterleaks:github-oauth; cp4c:github-oauth-app-token; gitleaks:github-oauth; v14:github-oauth; v16:github-oauth |
| LEV-S24-K02 | aws_secret_access_key | betterleaks:generic-api-key; cp4c:aws-secret-access-key-terraform; gitleaks:generic-api-key; v14:generic-api-key; v16:generic-api-key |
| LEV-S25-K01 | stripe_secret_key | betterleaks:stripe-access-token; cp4c:stripe-secret-api-key; gitleaks:stripe-access-token; v14:stripe-access-token; v16:stripe-access-token |
| LEV-S25-K02 | npm_access_token | betterleaks:npm-access-token; cp4c:npm-auth-token; gitleaks:npm-access-token; v14:npm-access-token; v16:npm-access-token |

Different rules can be equally correct: a provider-specific rule and a generic assignment rule may both capture the same target. The comparison treats oracle-target credit as the common unit; it does not rank scanners by rule-name similarity.

## CP4C versus V14/V16

- **Neither CP4C nor V14:** 395 targets.
- **Neither CP4C nor V16:** 394 targets.
- **Neither V14 nor V16:** 533 targets.

CP4C and V14/V16 share a large password/WordPress gap but differ sharply on HMAC/signing-family identifiers: CP4C misses all 31 Git `application_signing_key` targets, while V14/V16 miss only one. Conversely, V14/V16 leave more WordPress salts and database passwords uncredited. The practical development priority is therefore different for each scanner even where the target sets overlap.

## High-value complementary opportunities

- Betterleaks' 438/640 filesystem and 158/160 Git RNC Lab results establish a detection ceiling that neither RNC scanner reaches. Start with the Betterleaks-only target families, then verify the rule's false-positive behavior against the same trap corpus.
- V14/V16 recover most HMAC/signing-key targets that CP4C misses; CP4C's provider-specific rules and generic assignment matcher recover some targets that V14/V16 miss. A shared oracle-target review can separate a rule-family change from a source-acquisition change.
- The all-scanner misses are not proof of an impossible target. They are the right first set for source-level inspection and scanner instrumentation.

## Recommended priorities

- **CP4C:** WordPress salt identifiers; SIGNING/HMAC identifier family; password URI/structured representations; TOTP/provider rules; archive/database key extraction.
- **V14/V16:** password value/context coverage (WordPress, database, application); container acquisition; TOTP; PPK/PKCS#12; value-validator A/B cases.
- **Both:** retain the negative oracle, add regression fixtures for every proposed family, and do not claim precision from an incomplete oracle.

## Scope caveat

Gitleaks master, V14/V16 and Betterleaks were run through their registered harness adapters with their own default rule sets. The reports show equivalent filesystem/Git lanes and the same frozen oracle, but equivalent source scope is not assumed. Leaky Git coverage verification is not exposed as `true` by the external adapters; their Git precision/F1 remain uncertified.
