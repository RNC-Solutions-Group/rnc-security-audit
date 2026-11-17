# RNC Scanner CP4C Detection Gap Analysis

> Independent target-level assessment of the current-scoring Windows AMD64 baseline. No scanner rule, oracle, or score was modified.

## Executive summary

RNC Scanner CP4C missed **555 of 1125 expected positive occurrences** (49.33%) across the five applicable lanes. Of those, **468 are risk-bearing** and 87 are oracle-informative references. Risk-bearing recall is **570/1038 (54.91%)**; informative references are never added to that denominator. 187 misses are found by at least one comparison scanner, so the gap is not solely a corpus limitation.

Largest missed families: wordpress_salt (142 risk); database_password (54 risk); application_password (36 risk); application_signing_key (32 risk); application_hmac_key (21 risk); generic_api_key (17 risk).

Confirmed mechanisms account for **333** misses, of which **246** are risk-bearing; **184** are probable and **38** remain unresolved. The largest actionable family is `wordpress_authentication_material` (142 risk-bearing targets).

## Evidence and identity

| Field | Value |
| --- | --- |
| Scanner | RNC Scanner CP4C |
| Registered build | rnc-cp4c |
| Version | 0.1.0 |
| Source commit (manifest metadata, not checked out) | 805e3bb79276b94de636e27024f38773da303b44 |
| Executable SHA-256 | 170bd1df345c4985043ff449051c247f22a1012fe9c054cae5c2edcc190fb1cb |
| Rules/configuration | rules/rnc-cp4c-providers-v1.json |
| Rules SHA-256 | 2eb315fa40553ab1e133322a1f0a014a4593ab2ca6164152149eb59c1197a6b7 |
| Retained report | run/reports/all-windows-baselines/rnc-cp4c/rnc-cp4c-current-baseline-805e3bb79276-default.json |
| Report SHA-256 | ec2f5efe50d3dddd9e0b7b1a1e03628ccd97c748b3cf2b38a7deab806902b1f8 |
| Run ID | 20261115T235444Z-dbf46367 |
| Configuration profile | default |
| Scoring epoch | Current post-scoring-integrity remediation |
| Platform | Windows AMD64 |
| Analysis version | 2.0.0 |

The harness is an independent evaluator. This analysis consumed frozen oracles and retained scanner reports; it did not rebuild either scanner, change a rule, rewrite an oracle, or alter the scoring policy.

## Baseline reconciliation

| Lane | Oracle denominator | Matched | Missed (not credited) | Recall | Risk misses | Informative misses |
| --- | --- | --- | --- | --- | --- | --- |
| Levain credential corpus | 85 | 43 | 42 | 50.59% | 42 | 0 |
| Leaky Repo filesystem | 175 | 32 | 143 | 18.29% | 56 | 87 |
| Leaky Repo Git history | 65 | 28 | 37 | 43.08% | 37 | 0 |
| RNC Synthetic Secrets Lab v3 filesystem | 640 | 347 | 293 | 54.22% | 293 | 0 |
| RNC Synthetic Secrets Lab v3 Git history | 160 | 120 | 40 | 75.00% | 40 | 0 |

The Lane denominators are the frozen oracle positives, not scanner file counts. Leaky Repo filesystem has 175 line-level expected detections; Leaky Git has 65 source occurrences and 53 unique groups; RNC Lab has 640 filesystem and 160 Git occurrences. These denominators are never combined into one recall percentage.

## Complete miss inventory

Every expected target is in `cp4c-target-inventory.csv`; every uncredited target is in `cp4c-missed-targets.csv`; provider context and source location are in the corresponding `-provider-context.csv` and `-location-analysis.csv` files. The Markdown tables below are summaries, not the inventory.

### Concentration by lane

| Lane | Expected | Missed | Risk misses | Cross-scanner found | Recall |
| --- | --- | --- | --- | --- | --- |
| rnclab_filesystem | 640 | 293 | 293 | 106 | 54.22% |
| leaky_filesystem | 175 | 143 | 56 | 11 | 18.29% |
| levain | 85 | 42 | 42 | 21 | 50.59% |
| rnclab_git | 160 | 40 | 40 | 39 | 75.00% |
| leaky_git | 65 | 37 | 37 | 10 | 43.08% |

### Concentration by category

| Category | Expected | Matched | Missed | Risk misses | Recall |
| --- | --- | --- | --- | --- | --- |
| password | 549 | 252 | 297 | 297 | 45.90% |
| informative_reference | 87 | 0 | 87 | 0 | 0.00% |
| hmac_secret | 121 | 57 | 64 | 64 | 47.11% |
| provider_token | 248 | 203 | 45 | 45 | 81.85% |
| private_key | 49 | 28 | 21 | 21 | 57.14% |
| api_key | 37 | 20 | 17 | 17 | 54.05% |
| otp_seed | 12 | 0 | 12 | 12 | 0.00% |
| unknown_credential | 20 | 10 | 10 | 10 | 50.00% |
| payment_data | 2 | 0 | 2 | 2 | 0.00% |

### Concentration by provider

| Provider | Expected | Matched | Missed | Risk misses | Recall |
| --- | --- | --- | --- | --- | --- |
| WordPress | 142 | 0 | 142 | 142 | 0.00% |
| Informative reference | 87 | 0 | 87 | 0 | 0.00% |
| Database service | 227 | 173 | 54 | 54 | 76.21% |
| Application service | 83 | 47 | 36 | 36 | 56.63% |
| Application signing | 32 | 0 | 32 | 32 | 0.00% |
| Unidentified provider token | 41 | 16 | 25 | 25 | 39.02% |
| Application HMAC | 60 | 39 | 21 | 21 | 65.00% |
| Unidentified API provider | 17 | 0 | 17 | 17 | 0.00% |
| Azure Account Key | 22 | 10 | 12 | 12 | 45.45% |
| FTP/SFTP service | 12 | 0 | 12 | 12 | 0.00% |
| TOTP / OTP | 12 | 0 | 12 | 12 | 0.00% |
| PEM / RSA | 22 | 11 | 11 | 11 | 50.00% |
| JWT / application | 20 | 10 | 10 | 10 | 50.00% |
| Unidentified unknown credential | 17 | 7 | 10 | 10 | 41.18% |

### Concentration by root cause

| Root cause | Missed | Risk misses | Confirmed | Probable |
| --- | --- | --- | --- | --- |
| IDENTIFIER_MISMATCH | 257 | 257 | 192 | 65 |
| FORMAT_UNSUPPORTED | 100 | 100 | 9 | 91 |
| INFORMATIVE_REFERENCE | 87 | 0 | 87 | 0 |
| RULE_ABSENT | 48 | 48 | 45 | 3 |
| SOURCE_INSPECTION_UNVERIFIED | 26 | 26 | 0 | 0 |
| CONTEXT_INSUFFICIENT | 22 | 22 | 0 | 22 |
| UNKNOWN | 12 | 12 | 0 | 0 |
| VALIDATOR_REJECTION | 2 | 2 | 0 | 2 |
| CAPTURE_MISMATCH | 1 | 1 | 0 | 1 |

## Required focused investigations

### HMAC and application-signing credentials

| Scanner | Lane | Expected | Matched | Missed | Recall |
| --- | --- | --- | --- | --- | --- |
| RNC Scanner CP4C | filesystem | 80 | 49 | 31 | 61.25% |
| RNC Scanner CP4C | Git | 31 | 0 | 31 | 0.00% |
| RNC-Mod V14 | filesystem | 80 | 76 | 4 | 95.00% |
| RNC-Mod V14 | Git | 31 | 30 | 1 | 96.77% |
| RNC-Mod V16 | filesystem | 80 | 76 | 4 | 95.00% |
| RNC-Mod V16 | Git | 31 | 30 | 1 | 96.77% |
| Gitleaks master | filesystem | 80 | 76 | 4 | 95.00% |
| Gitleaks master | Git | 31 | 30 | 1 | 96.77% |
| Betterleaks 1.8.1 | filesystem | 80 | 76 | 4 | 95.00% |
| Betterleaks 1.8.1 | Git | 31 | 30 | 1 | 96.77% |

**RNC Scanner CP4C HMAC detail.**

| Lane | Target | Subtype | Representation | Identifier | Cause | Confidence | Rule evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| filesystem | RNC-SL-POS-000108 | jwt_signing_key | env_value | JWT_SIGNING_KEY | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000114 | jwt_signing_key | kubernetes_secret_data | jwt-signing-key | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000130 | application_hmac_key | sqlite_table_cell | value | SOURCE_INSPECTION_UNVERIFIED | UNRESOLVED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000135 | application_hmac_key | sqlite_table_cell | value | SOURCE_INSPECTION_UNVERIFIED | UNRESOLVED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000155 | application_hmac_key | python_string_literal | SECRET_KEY | UNKNOWN | UNRESOLVED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000179 | application_hmac_key | json_string | SigningKey | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000190 | application_hmac_key | python_string_literal | SECRET_KEY | UNKNOWN | UNRESOLVED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000203 | application_hmac_key | env_value | JWT_SIGNING_KEY | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000209 | application_hmac_key | kubernetes_secret_data | jwt-signing-key | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000246 | application_hmac_key | json_string | SigningKey | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000257 | application_hmac_key | python_string_literal | SECRET_KEY | UNKNOWN | UNRESOLVED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000274 | application_hmac_key | python_string_literal | SECRET_KEY | UNKNOWN | UNRESOLVED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000297 | jwt_signing_key | env_value | JWT_SIGNING_KEY | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000303 | jwt_signing_key | kubernetes_secret_data | jwt-signing-key | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000381 | application_hmac_key | python_string_literal | SECRET_KEY | UNKNOWN | UNRESOLVED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000413 | application_hmac_key | kubernetes_secret_data | jwt-signing-key | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000447 | jwt_signing_key | env_value | JWT_SIGNING_KEY | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000453 | jwt_signing_key | kubernetes_secret_data | jwt-signing-key | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000462 | application_hmac_key | json_string | SigningKey | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000473 | application_hmac_key | python_string_literal | SECRET_KEY | UNKNOWN | UNRESOLVED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000486 | jwt_signing_key | env_value | JWT_SIGNING_KEY | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000492 | jwt_signing_key | kubernetes_secret_data | jwt-signing-key | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000505 | application_hmac_key | env_value | JWT_SIGNING_KEY | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000511 | application_hmac_key | kubernetes_secret_data | jwt-signing-key | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000523 | application_hmac_key | python_string_literal | SECRET_KEY | UNKNOWN | UNRESOLVED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000536 | jwt_signing_key | env_value | JWT_SIGNING_KEY | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000542 | jwt_signing_key | kubernetes_secret_data | jwt-signing-key | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000578 | application_hmac_key | env_value | JWT_SIGNING_KEY | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000584 | application_hmac_key | kubernetes_secret_data | jwt-signing-key | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000593 | application_hmac_key | json_string | SigningKey | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| filesystem | RNC-SL-POS-000601 | application_hmac_key | json_string | SigningKey | IDENTIFIER_MISMATCH | CONFIRMED | observed-subtype:generic-secret-assignment |
| Git | RNC-SL-POS-000643 | application_signing_key | env_value | SIGNING_KEY | IDENTIFIER_MISMATCH | PROBABLE | observed-representation:generic-secret-assignment |
| Git | RNC-SL-POS-000649 | application_signing_key | env_value | SIGNING_KEY | IDENTIFIER_MISMATCH | PROBABLE | observed-representation:generic-secret-assignment |
| Git | RNC-SL-POS-000655 | application_signing_key | env_value | SIGNING_KEY | IDENTIFIER_MISMATCH | PROBABLE | observed-representation:generic-secret-assignment |
| Git | RNC-SL-POS-000660 | application_signing_key | env_value | SIGNING_KEY | IDENTIFIER_MISMATCH | PROBABLE | observed-representation:generic-secret-assignment |
| Git | RNC-SL-POS-000666 | application_signing_key | env_value | SIGNING_KEY | IDENTIFIER_MISMATCH | PROBABLE | observed-representation:generic-secret-assignment |
| Git | RNC-SL-POS-000671 | application_signing_key | env_value | SIGNING_KEY | IDENTIFIER_MISMATCH | PROBABLE | observed-representation:generic-secret-assignment |
| Git | RNC-SL-POS-000675 | application_signing_key | env_value | SIGNING_KEY | IDENTIFIER_MISMATCH | PROBABLE | observed-representation:generic-secret-assignment |
| Git | RNC-SL-POS-000681 | application_signing_key | env_value | SIGNING_KEY | IDENTIFIER_MISMATCH | PROBABLE | observed-representation:generic-secret-assignment |
| Git | RNC-SL-POS-000686 | application_signing_key | env_value | SIGNING_KEY | IDENTIFIER_MISMATCH | PROBABLE | observed-representation:generic-secret-assignment |

Showing 40 of 62 HMAC misses; the CSV contains every target.

The 31 Git HMAC misses are all `application_signing_key` occurrences with the identifier `SIGNING_KEY` and the `env_value` representation. That is not a Git-ingestion failure: the same identifier and value shape was submitted as an ordinary `.env` file in a controlled local reproduction and was still not detected, while a `SESSION_SECRET` control was credited by `generic-secret-assignment`. The common property is the identifier family, not the Git container.

Filesystem HMAC credits are not proof of a dedicated HMAC rule. In CP4C they are produced by the generic assignment rule when the field name contains a recognized `PASSWORD`, `SECRET_KEY` or `SESSION_SECRET` token. Fields named `HMAC_KEY`, `SIGNING_KEY` and JSON `SigningKey` fall outside that identifier family.

### Password detection

| Subtype | Expected | Matched | Missed | Recall | Risk misses |
| --- | --- | --- | --- | --- | --- |
| wordpress_salt | 126 | 0 | 126 | 0.00% | 126 |
| database_password | 205 | 166 | 39 | 80.98% | 39 |
| application_password | 53 | 25 | 28 | 47.17% | 28 |
| admin_password | 9 | 0 | 9 | 0.00% | 9 |
| key_passphrase | 6 | 0 | 6 | 0.00% | 6 |
| pkcs12_passphrase | 6 | 0 | 6 | 0.00% | 6 |
| ftp_password | 4 | 0 | 4 | 0.00% | 4 |
| smtp_password | 21 | 20 | 1 | 95.24% | 1 |
| http_basic_password | 1 | 0 | 1 | 0.00% | 1 |
| redis_password | 2 | 2 | 0 | 100.00% | 0 |

**Comparison on the RNC Lab password lane.** The table uses each scanner's own current-scoring report and the same target IDs.

| Scanner | Expected | Matched | Missed | Recall |
| --- | --- | --- | --- | --- |
| RNC Scanner CP4C | 433 | 213 | 220 | 49.19% |
| RNC-Mod V14 | 433 | 180 | 253 | 41.57% |
| RNC-Mod V16 | 433 | 180 | 253 | 41.57% |
| Gitleaks master | 433 | 180 | 253 | 41.57% |
| Betterleaks 1.8.1 | 433 | 276 | 157 | 63.74% |

**Largest missed password shapes.**

| Subtype | identifier | representation | Missed | Cross-scanner found | Example target |
| --- | --- | --- | --- |
| application_password \| REDIS_URL \| redis_url | 8 | 8 | RNC-SL-POS-000106 |
| application_password \| command \| compose_command_arg | 8 | 0 | RNC-SL-POS-000115 |
| database_password \| NO_ASSIGNMENT_IDENTIFIER \| log_command_argument | 7 | 0 | RNC-SL-POS-000017 |
| database_password \| sqlalchemy.url \| alembic_url | 7 | 0 | RNC-SL-POS-000154 |
| wordpress_salt \| AUTH_KEY \| php_string_literal | 7 | 7 | RNC-SL-POS-000019 |
| wordpress_salt \| AUTH_SALT \| php_string_literal | 7 | 7 | RNC-SL-POS-000023 |
| wordpress_salt \| LOGGED_IN_KEY \| php_string_literal | 7 | 7 | RNC-SL-POS-000021 |
| wordpress_salt \| LOGGED_IN_SALT \| php_string_literal | 7 | 0 | RNC-SL-POS-000025 |
| wordpress_salt \| NONCE_KEY \| php_string_literal | 7 | 7 | RNC-SL-POS-000022 |
| wordpress_salt \| NONCE_SALT \| php_string_literal | 7 | 0 | RNC-SL-POS-000026 |
| wordpress_salt \| SECURE_AUTH_KEY \| php_string_literal | 7 | 7 | RNC-SL-POS-000020 |
| wordpress_salt \| SECURE_AUTH_SALT \| php_string_literal | 7 | 7 | RNC-SL-POS-000024 |
| wordpress_salt \| WP_SALT_1 \| php_define | 7 | 0 | RNC-SL-POS-000002 |
| wordpress_salt \| WP_SALT_2 \| php_define | 7 | 0 | RNC-SL-POS-000003 |
| wordpress_salt \| WP_SALT_3 \| php_define | 7 | 0 | RNC-SL-POS-000004 |

CP4C's password gap is dominated by WordPress authentication material (`AUTH_KEY`, `SECURE_AUTH_KEY`, `LOGGED_IN_KEY`, `NONCE_KEY`, the four salts and `WP_SALT_n`), followed by database/application passwords whose identifiers or wrappers fall outside `generic-secret-assignment`. The controlled `define('AUTH_KEY', ...)` reproduction was not detected even as a plain PHP file.

### Provider tokens, generic API keys and OTP seeds

| Category | subtype | provider | representation | container | cause | Missed | Capability | Example |
| --- | --- | --- | --- |
| otp_seed \| totp_seed \| TOTP / OTP \| python_string_literal \| ordinary_file \| RULE_ABSENT | 7 | observed-representation:generic-secret-assignment | RNC-SL-POS-000160 |
| api_key \| generic_api_key \| Unidentified API provider \| compose_environment_value \| ordinary_file \| RULE_ABSENT | 5 | observed-subtype:generic-secret-assignment | RNC-SL-POS-000045 |
| api_key \| generic_api_key \| Unidentified API provider \| env_value \| ordinary_file \| RULE_ABSENT | 5 | observed-subtype:generic-secret-assignment | RNC-SL-POS-000040 |
| otp_seed \| totp_seed \| TOTP / OTP \| otpauth_secret \| ordinary_file \| RULE_ABSENT | 5 | no-matching-rule | RNC-SL-POS-000047 |
| provider_token \| azure_storage_account_key \| Microsoft Azure Storage \| json_string \| ordinary_file \| FORMAT_UNSUPPORTED | 5 | provider-rule:azure-storage-account-key | RNC-SL-POS-000176 |
| api_key \| generic_api_key \| Unidentified API provider \| sqlite_table_cell \| database_record \| SOURCE_INSPECTION_UNVERIFIED | 4 | observed-subtype:generic-secret-assignment | RNC-SL-POS-000128 |
| api_key \| generic_api_key \| Unidentified API provider \| bson_string_value \| database_record \| SOURCE_INSPECTION_UNVERIFIED | 1 | observed-subtype:generic-secret-assignment | RNC-SL-POS-000127 |
| api_key \| generic_api_key \| Unidentified API provider \| env_value \| archive_member \| SOURCE_INSPECTION_UNVERIFIED | 1 | observed-subtype:generic-secret-assignment | RNC-SL-POS-000032 |
| api_key \| generic_api_key \| Unidentified API provider \| nuget_clear_text_password \| ordinary_file \| RULE_ABSENT | 1 | observed-subtype:generic-secret-assignment | RNC-SL-POS-000498 |
| provider_token \| sendgrid_api_key \| Twilio SendGrid \| yaml_value \| git_blob \| VALIDATOR_REJECTION | 1 | provider-rule:sendgrid-api-key | RNC-SL-POS-000791 |
| provider_token \| slack_bot_token \| Slack \| kubernetes_secret_data \| ordinary_file \| FORMAT_UNSUPPORTED | 1 | provider-rule:slack-token | RNC-SL-POS-000415 |
| provider_token \| stripe_webhook_secret \| Stripe \| yaml_value \| git_blob \| RULE_ABSENT | 1 | observed-representation:generic-secret-assignment | RNC-SL-POS-000735 |

- Azure `AccountKey` values in JSON/XML key-value fields are outside the connection-string `AccountKey=` form and need a separator-aware field parser.
- Stripe `whsec_` webhook signing secrets have no matching provider rule in this scanner.
- Generic `ak_`/`MINIO_ROOT_USER`-style values are not provider-identifiable from the value alone; a pair-aware assignment context is required rather than a blanket high-entropy rule.
- TOTP seeds require an otpauth/OTP-seed rule and must not be conflated with generic passwords.

### Private keys and encoded key containers

| Subtype | representation | container | Expected | Matched | Missed | Recall |
| --- | --- | --- | --- | --- |
| rsa_private_key_pkcs1 \| putty_ppk_v2 \| ordinary_file | 8 | 0 | 8 | 0.00% |
| tls_private_key_pkcs8 \| pkcs12_der \| binary_file | 4 | 0 | 4 | 0.00% |
| rsa_private_key_pkcs1 \| section_text \| ordinary_file | 3 | 0 | 3 | 0.00% |
| pem_private_key \| source_line \| ordinary_file | 2 | 0 | 2 | 0.00% |
| wallet_seed_phrase \| section_text \| ordinary_file | 2 | 0 | 2 | 0.00% |
| ed25519_private_key_pkcs8 \| pem_pkcs8 \| archive_member | 1 | 0 | 1 | 0.00% |
| putty_ppk_private_key \| putty_ppk_v2 \| git_blob | 1 | 0 | 1 | 0.00% |
| tls_private_key_pkcs8 \| pem_pkcs8 \| archive_member | 1 | 0 | 1 | 0.00% |
| rsa_private_key_pkcs1 \| pem_pkcs1 \| git_blob | 10 | 10 | 0 | 100.00% |
| ec_private_key_sec1 \| pem_sec1 \| ordinary_file | 4 | 4 | 0 | 100.00% |
| ed25519_private_key_pkcs8 \| pkcs8_encrypted_aes256 \| ordinary_file | 3 | 3 | 0 | 100.00% |
| openssh_private_key_rsa \| openssh_private_key_file \| ordinary_file | 2 | 2 | 0 | 100.00% |
| pem_private_key \| pem_block \| git_blob | 2 | 2 | 0 | 100.00% |
| pem_private_key \| pem_block \| ordinary_file | 2 | 2 | 0 | 100.00% |
| openssh_private_key_ed25519 \| kubernetes_ssh_key \| ordinary_file | 1 | 1 | 0 | 100.00% |
| openssh_private_key_ed25519 \| openssh_private_key_file \| ordinary_file | 1 | 1 | 0 | 100.00% |
| rsa_private_key_pkcs8 \| pkcs8_encrypted_aes256 \| ordinary_file | 1 | 1 | 0 | 100.00% |
| tls_private_key_pkcs8 \| kubeconfig_client_key \| ordinary_file | 1 | 1 | 0 | 100.00% |
| tls_private_key_pkcs8 \| kubernetes_tls_key \| ordinary_file | 1 | 1 | 0 | 100.00% |

Most remaining private-key failures are representation or source-acquisition hypotheses: PuTTY PPK v2 and PKCS#12 are not PEM blocks, and the retained reports do not prove that archived PEM members were inspected. Wallet seed phrases are a distinct mnemonic credential and should not be counted as private-key material. Do not mark a public-key-only, SPKI-only, encrypted-container-only or filename-only observation as private-key credit. The existing PEM findings that are credited must remain credited; no historical scoring artifact is being reclassified as a new false negative here.

Private-key passphrases are counted separately as password targets when the oracle models them as such; a passphrase is not interchangeable with the key material.

### Where the misses live

| Source container | Expected | Matched | Missed | Recall | Risk misses |
| --- | --- | --- | --- | --- | --- |
| ordinary_file | 874 | 422 | 452 | 48.28% | 365 |
| git_blob | 225 | 148 | 77 | 65.78% | 77 |
| database_record | 12 | 0 | 12 | 0.00% | 12 |
| archive_member | 10 | 0 | 10 | 0.00% | 10 |
| binary_file | 4 | 0 | 4 | 0.00% | 4 |

**Missed file types.**

| File type | Missed | Risk misses | Cross-scanner found |
| --- | --- | --- | --- |
| env | 133 | 127 | 50 |
| php | 80 | 74 | 42 |
| json | 64 | 26 | 19 |
| log | 49 | 49 | 21 |
| yaml | 45 | 45 | 23 |
| xml | 22 | 15 | 0 |
| shell | 16 | 8 | 4 |
| python | 14 | 14 | 7 |
| config | 12 | 9 | 1 |
| no-extension | 12 | 7 | 4 |
| sql | 12 | 12 | 0 |
| text | 12 | 10 | 0 |
| ppk | 11 | 10 | 0 |
| sqlite | 10 | 10 | 0 |
| ftpconfig | 7 | 4 | 0 |
| ini | 7 | 7 | 0 |
| docker-config | 6 | 4 | 4 |
| netrc | 6 | 6 | 0 |

**Missed representations.**

| Representation | Missed | Risk misses | Cross-scanner found |
| --- | --- | --- | --- |
| php_define | 77 | 74 | 0 |
| json_string | 67 | 24 | 18 |
| php_string_literal | 56 | 56 | 42 |
| env_value | 51 | 51 | 38 |
| assignment | 42 | 18 | 10 |
| section_text | 42 | 42 | 21 |
| kubernetes_secret_data | 24 | 24 | 17 |
| dotenv_value | 20 | 20 | 11 |
| python_string_literal | 14 | 14 | 7 |
| xml_element_or_attribute | 14 | 7 | 0 |
| source_line | 12 | 5 | 0 |
| sql_copy_value | 12 | 12 | 0 |
| sqlite_table_cell | 10 | 10 | 0 |
| putty_ppk_v2 | 9 | 9 | 0 |
| compose_command_arg | 8 | 8 | 0 |
| redis_url | 8 | 8 | 8 |
| alembic_url | 7 | 7 | 0 |
| log_command_argument | 7 | 7 | 0 |

| Inspection state | Expected | Matched | Missed |
| --- | --- | --- | --- |
| INSPECTED_VERIFIED | 916 | 570 | 346 |
| INSPECTION_UNVERIFIED | 209 | 0 | 209 |

| Source capability declaration | Expected | Matched | Missed |
| --- | --- | --- | --- |
| CLAIMED_SUPPORTED | 1099 | 570 | 529 |
| NOT_DECLARED | 26 | 0 | 26 |

26 expected positives live in a non-plaintext container. Of these, 10 are archive members, 12 are database records and 4 are binary key containers.

The retained report contains no unit/member/record evidence for these targets. That does **not** prove the scanner failed to inspect the container. They are therefore classified as `SOURCE_INSPECTION_UNVERIFIED` / `UNRESOLVED`, not as confirmed `SOURCE_UNSUPPORTED`. A validated capability declaration or a source-unit probe that records member inspection is required before that stronger claim is permitted.

Eligible-but-uninspected expected positives with proof: 0. Expected positives whose inspection is not independently verified: 209. The RNC Lab filesystem lane reports 11 uninspected symlink aliases; none of them is an expected positive target in the frozen oracle. That is a scanner coverage caveat, not a positive-recall gap.

### Load-replicated evidence (not canonical accuracy)

| Profile | Median s | Inspected/eligible | Coverage % | Stability | Coverage caveat | Accuracy scored |
| --- | --- | --- | --- | --- | --- | --- |
| legacy-5x | 5.121 | 1809/1810 | 99.94 | STABLE | TOTAL_BYTE_LIMIT | NO |
| legacy-10x | 6.892 | 3609/3610 | 99.97 | STABLE | TOTAL_BYTE_LIMIT | NO |

These corpora are performance replicas. Their repeated files are not additional canonical targets and are excluded from every recall denominator in this report. The x5/x10 runs are still useful for source-coverage anomalies: a replicated file that the scanner excludes by a total-byte limit is a load-scope caveat, not a new oracle target.

- **legacy-5x:** 1809/1810 files inspected; caveat `TOTAL_BYTE_LIMIT`; exemplar uninspected unit(s): `generated/large/payload-07.bin`.
- **legacy-10x:** 3609/3610 files inspected; caveat `TOTAL_BYTE_LIMIT`; exemplar uninspected unit(s): `generated/large/payload-07.bin`.


### False positives, near misses and regression fixtures

| Signal | Value |
| --- | --- |
| RNC Lab filesystem verified false-positive alerts | 10 |
| RNC Lab Git verified false-positive alerts | 3 |
| Levain false positives | 2 |
| Leaky filesystem unexpected findings | 0 |
| Precision certified | NO |

1 missed target(s) have a same-location scanner observation that the scorer did not credit (`UNVERIFIED_EVIDENCE`). These are not silent regex misses.

| Target | Rule | Stage | Reason code |
| --- | --- | --- | --- |
| leaky-repo:db/mongoid.yml:4:risk | database-connection-credential | VALUE | correct location but extracted value is missing or conflicts with expected value; mandatory investigation |

Regression fixtures available for proposed changes: the RNC Lab oracle has 400 negative-ordinary and 202 negative-trap items (162 trap items in the filesystem lane and 40 in Git); Leaky Repo history has 89 reviewed negative references and 30 informative references; Levain has 116 negative sections. These are the first fixtures to run after any identifier, decoder or validator change. The negative oracle is not exhaustive, so a new rule must be evaluated against false-positive alerts as well as recovered positives. No precision claim is made from the absence of an alert.

## Root-cause interpretation

A target is marked `SOURCE_UNSUPPORTED` only when a scanner/source capability declaration or an independently validated capability contract says the source type is unsupported. `SOURCE_INSPECTION_UNVERIFIED` is used when the specific member/record/unit has no retained inspection evidence and no capability declaration; it is not proof of a scanner failure. `SOURCE_NOT_INSPECTED` requires a coverage record, not merely an absent finding. `CAPTURE_MISMATCH` requires a retained same-location observation whose value evidence failed. `SCORING_MISMATCH` requires a usable scanner observation rejected by the scorer. `IDENTIFIER_MISMATCH`, `RULE_ABSENT`, `FORMAT_UNSUPPORTED`, `CONTEXT_INSUFFICIENT`, `VALIDATOR_REJECTION` and `UNKNOWN` are kept distinct because they imply different development work.

See the standalone root-cause dossier for the full evidence and reproduction table.

## Cross-scanner context

| Other scanner | Finds the same missed target | Share of this scanner's misses |
| --- | --- | --- |
| RNC-Mod V14 | 160 | 28.83% |
| RNC-Mod V16 | 161 | 29.01% |
| Gitleaks master | 160 | 28.83% |
| Betterleaks 1.8.1 | 184 | 33.15% |

This is an oracle-target join, not raw string similarity. It demonstrates that the content is present in the same frozen dataset; it does not prove that the other scanner used the same source scope or rule.

## Prioritized improvements

1. **wordpress authentication material** - 142 risk-bearing targets; `IDENTIFIER_MISMATCH`; Add a reviewed WordPress authentication-key/salt identifier family to the generic assignment matcher (AUTH_KEY, SECURE_AUTH_KEY, LOGGED_IN_KEY, NONCE_KEY, AUTH_SALT, SECURE_AUTH_SALT, LOGGED_IN_SALT, NONCE_SALT and WP_SALT_n). Use the existing assignment and high-entropy checks; do not add a bare SALT keyword.
2. **password positional or encoded** - 66 risk-bearing targets; `FORMAT_UNSUPPORTED`; Add bounded parsers for positional credential files (.pgpass, .netrc, .git-credentials), Docker auth, FileZilla/JetBrains encoded fields and SQL COPY/INSERT password columns. Add reviewed identifier aliases only for fields that remain ordinary assignments. Emit findings only when the field role and value shape agree.
3. **hmac and signing identifiers** - 61 risk-bearing targets; `IDENTIFIER_MISMATCH`; Extend the generic assignment identifier family for SIGNING_KEY, HMAC_KEY, HMAC_SECRET and camelCase JSON fields such as SigningKey, while retaining the current assignment-context and value-entropy requirements. Add a JWT_SIGNING_KEY alias rather than a bare KEY rule. The expression-wrapped and JSON subcases need the matching context/decoder work; the identifier change alone recovers the direct assignment subset.
4. **container inspection evidence** - 26 risk-bearing targets; `SOURCE_INSPECTION_UNVERIFIED`; Collect scanner-side candidate diagnostics for this group before proposing a rule change; the retained evidence does not distinguish rule, context and validator causes.
5. **application password identifiers** - 25 risk-bearing targets; `IDENTIFIER_MISMATCH`; Add the missing reviewed application-password aliases (SMTP, FTP, Redis, registry and admin qualifiers) and, where the alias is already recognized, extend the field-role/context association instead of adding a broad rule. Do not add a generic USERNAME or EMAIL rule.

The detailed backlog is in the companion file; it ranks by recoverable count, severity, concentration, context availability, false-positive risk and implementation complexity.

## Limitations

- This is an independent evaluator report. No scanner rule, source file, oracle, or scoring policy was modified.
- Leaky Repo filesystem is a line-level detection benchmark without a complete negative oracle; precision and F1 are not certified.
- Leaky Repo Git precision/F1 are not certified; 65 source occurrences and 53 unique groups are separate denominators.
- Leaky Git source units are marked INSPECTION_UNVERIFIED for adapters that do not return a true coverage attestation; this is not evidence that a unit was skipped.
- RNC Lab precision/F1 are not certified; the 640 filesystem and 160 Git positive denominators are separate and are not combined.
- The 11 RNC Lab symlink aliases are not followed by the scanner. They contain no expected positive target in this oracle, so they do not change the positive recall denominator.
- Provider and subtype labels for Leaky Repo and Levain are source-context inferences because those oracles do not expose the Lab's fine-grained subtype taxonomy. RNC Lab labels come directly from its oracle.
- A miss is not proof that a regular expression failed. Candidate rejection, source acquisition, context association, and value extraction are distinct layers.
- Scanner-side candidate instrumentation is required to turn some PROBABLE or UNRESOLVED causes into confirmed ones.
- CP4C was executed with the experiment-owned --workers auto argument and no profiling, as in the retained baseline.

## Reproduction

```powershell
python -m harness detection-gaps --out-dir reports/detection-gaps
python -m unittest tests.test_detection_gaps -v
```

The generator reads the retained reports and frozen oracles only; it does not execute a scanner or change a dataset.
