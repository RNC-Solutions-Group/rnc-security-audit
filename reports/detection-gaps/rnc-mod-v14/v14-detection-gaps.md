# RNC-Mod V14 Detection Gap Analysis

> Independent target-level assessment of the current-scoring Windows AMD64 baseline. No scanner rule, oracle, or score was modified.

## Executive summary

RNC-Mod V14 missed **534 of 1125 expected positive occurrences** (47.47%) across the five applicable lanes. Of those, **448 are risk-bearing** and 86 are oracle-informative references. Risk-bearing recall is **590/1038 (56.84%)**; informative references are never added to that denominator. 166 misses are found by at least one comparison scanner, so the gap is not solely a corpus limitation.

Largest missed families: database_password (119 risk); wordpress_salt (93 risk); application_password (71 risk); generic_api_key (16 risk); smtp_password (12 risk); ftp_password (12 risk).

Confirmed mechanisms account for **123** misses, of which **37** are risk-bearing; **380** are probable and **31** remain unresolved. The largest actionable family is `wordpress_authentication_material` (93 risk-bearing targets).

## Evidence and identity

| Field | Value |
| --- | --- |
| Scanner | RNC-Mod V14 |
| Registered build | gl-rnc-mod-v14 |
| Version | v8.25.0+dev.7d7492184111 |
| Source commit (manifest metadata, not checked out) | 7d74921841114be7677a423cf60620210e832bf7 |
| Executable SHA-256 | 7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb |
| Rules/configuration | compiled/default |
| Rules SHA-256 | not exposed |
| Retained report | C:\Dev\rnc-benchmark-harness\run\reports\all-windows-baselines\gl-rnc-mod-v14\gl-rnc-mod-v14-current-baseline-7d7492184111-default.json |
| Report SHA-256 | 1480f1bb80ef77dc303fe61527ef7d930823c6287dc92557f6b36115fe02151a |
| Run ID | 20261116T000424Z-080efee1 |
| Configuration profile | default |
| Scoring epoch | Current post-scoring-integrity remediation |
| Platform | Windows AMD64 |
| Analysis version | 1.0.0 |

The harness is an independent evaluator. This analysis consumed frozen oracles and retained scanner reports; it did not rebuild either scanner, change a rule, rewrite an oracle, or alter the scoring policy.

## Baseline reconciliation

| Lane | Oracle denominator | Matched | Missed (not credited) | Recall | Risk misses | Informative misses |
| --- | --- | --- | --- | --- | --- | --- |
| Levain credential corpus | 85 | 49 | 36 | 57.65% | 36 | 0 |
| Leaky Repo filesystem | 175 | 22 | 153 | 12.57% | 67 | 86 |
| Leaky Repo Git history | 65 | 21 | 44 | 32.31% | 44 | 0 |
| RNC Synthetic Secrets Lab v3 filesystem | 640 | 369 | 271 | 57.66% | 271 | 0 |
| RNC Synthetic Secrets Lab v3 Git history | 160 | 130 | 30 | 81.25% | 30 | 0 |

The Lane denominators are the frozen oracle positives, not scanner file counts. Leaky Repo filesystem has 175 line-level expected detections; Leaky Git has 65 source occurrences and 53 unique groups; RNC Lab has 640 filesystem and 160 Git occurrences. These denominators are never combined into one recall percentage.

## Complete miss inventory

Every expected target is in `rnc-mod-v14-target-inventory.csv`; every uncredited target is in `rnc-mod-v14-missed-targets.csv`; provider context and source location are in the corresponding `-provider-context.csv` and `-location-analysis.csv` files. The Markdown tables below are summaries, not the inventory.

### Concentration by lane

| Lane | Expected | Missed | Risk misses | Cross-scanner found | Recall |
| --- | --- | --- | --- | --- | --- |
| rnclab_filesystem | 640 | 271 | 271 | 84 | 57.66% |
| leaky_filesystem | 175 | 153 | 67 | 21 | 12.57% |
| leaky_git | 65 | 44 | 44 | 17 | 32.31% |
| levain | 85 | 36 | 36 | 15 | 57.65% |
| rnclab_git | 160 | 30 | 30 | 29 | 81.25% |

### Concentration by category

| Category | Expected | Matched | Missed | Risk misses | Recall |
| --- | --- | --- | --- | --- | --- |
| password | 549 | 188 | 361 | 361 | 34.24% |
| informative_reference | 87 | 1 | 86 | 0 | 1.15% |
| api_key | 37 | 17 | 20 | 20 | 45.95% |
| provider_token | 248 | 230 | 18 | 18 | 92.74% |
| private_key | 49 | 31 | 18 | 18 | 63.27% |
| otp_seed | 12 | 0 | 12 | 12 | 0.00% |
| hmac_secret | 121 | 112 | 9 | 9 | 92.56% |
| unknown_credential | 20 | 12 | 8 | 8 | 60.00% |
| payment_data | 2 | 0 | 2 | 2 | 0.00% |

### Concentration by provider

| Provider | Expected | Matched | Missed | Risk misses | Recall |
| --- | --- | --- | --- | --- | --- |
| Database service | 227 | 108 | 119 | 119 | 47.58% |
| WordPress | 142 | 49 | 93 | 93 | 34.51% |
| Informative reference | 87 | 1 | 86 | 0 | 1.15% |
| Application service | 83 | 12 | 71 | 71 | 14.46% |
| Unidentified API provider | 17 | 1 | 16 | 16 | 5.88% |
| Unidentified provider token | 41 | 28 | 13 | 13 | 68.29% |
| Unidentified password | 13 | 0 | 13 | 13 | 0.00% |
| SMTP service | 23 | 11 | 12 | 12 | 47.83% |
| FTP/SFTP service | 12 | 0 | 12 | 12 | 0.00% |
| TOTP / OTP | 12 | 0 | 12 | 12 | 0.00% |
| Private-key container | 10 | 0 | 10 | 10 | 0.00% |
| Administrative account | 9 | 0 | 9 | 9 | 0.00% |
| Azure Account Key | 22 | 14 | 8 | 8 | 63.64% |
| PEM / RSA | 22 | 14 | 8 | 8 | 63.64% |

### Concentration by root cause

| Root cause | Missed | Risk misses | Confirmed | Probable |
| --- | --- | --- | --- | --- |
| IDENTIFIER_MISMATCH | 167 | 167 | 0 | 167 |
| FORMAT_UNSUPPORTED | 112 | 112 | 10 | 102 |
| INFORMATIVE_REFERENCE | 86 | 0 | 86 | 0 |
| CONTEXT_INSUFFICIENT | 72 | 72 | 0 | 72 |
| RULE_ABSENT | 35 | 35 | 0 | 35 |
| UNKNOWN | 31 | 31 | 0 | 0 |
| SOURCE_UNSUPPORTED | 26 | 26 | 26 | 0 |
| VALIDATOR_REJECTION | 4 | 4 | 0 | 4 |
| CAPTURE_MISMATCH | 1 | 1 | 1 | 0 |

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

**RNC-Mod V14 HMAC detail.**

| Lane | Target | Subtype | Representation | Identifier | Cause | Confidence | Rule evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| filesystem | RNC-SL-POS-000130 | application_hmac_key | sqlite_table_cell | value | SOURCE_UNSUPPORTED | CONFIRMED | observed-subtype:generic-api-key |
| filesystem | RNC-SL-POS-000135 | application_hmac_key | sqlite_table_cell | value | SOURCE_UNSUPPORTED | CONFIRMED | observed-subtype:generic-api-key |
| filesystem | RNC-SL-POS-000203 | application_hmac_key | env_value | JWT_SIGNING_KEY | VALIDATOR_REJECTION | PROBABLE | observed-subtype:generic-api-key |
| filesystem | RNC-SL-POS-000485 | jwt_signing_key | env_value | SESSION_SECRET | VALIDATOR_REJECTION | PROBABLE | observed-subtype:generic-api-key |
| Git | RNC-SL-POS-000671 | application_signing_key | env_value | SIGNING_KEY | VALIDATOR_REJECTION | PROBABLE | observed-subtype:generic-api-key |

The residual Git HMAC miss and the residual filesystem HMAC misses are value-dependent, not scope-dependent. Controlled standalone-file A/B cases with the same identifier and representation changed the result only when the value changed: one `SIGNING_KEY`, one `JWT_SIGNING_KEY` and one `SESSION_SECRET` value were not detected, while other values for those same fields were detected by `generic-api-key`. This points to a value-shape/entropy/allowlist check; it does not establish a Git bug.

Filesystem HMAC credits are not proof of a dedicated HMAC rule. In CP4C they are produced by the generic assignment rule when the field name contains a recognized `PASSWORD`, `SECRET_KEY` or `SESSION_SECRET` token. Fields named `HMAC_KEY`, `SIGNING_KEY` and JSON `SigningKey` fall outside that identifier family.

### Password detection

| Subtype | Expected | Matched | Missed | Recall | Risk misses |
| --- | --- | --- | --- | --- | --- |
| database_password | 205 | 108 | 97 | 52.68% | 97 |
| wordpress_salt | 126 | 49 | 77 | 38.89% | 77 |
| application_password | 53 | 12 | 41 | 22.64% | 41 |
| smtp_password | 21 | 11 | 10 | 52.38% | 10 |
| admin_password | 9 | 0 | 9 | 0.00% | 9 |
| key_passphrase | 6 | 0 | 6 | 0.00% | 6 |
| pkcs12_passphrase | 6 | 0 | 6 | 0.00% | 6 |
| ftp_password | 4 | 0 | 4 | 0.00% | 4 |
| redis_password | 2 | 0 | 2 | 0.00% | 2 |
| http_basic_password | 1 | 0 | 1 | 0.00% | 1 |

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
| database_password \| DB_PASSWORD \| dotenv_value | 19 | 19 | RNC-SL-POS-000031 |
| database_password \| password \| yaml_value | 12 | 12 | RNC-SL-POS-000667 |
| application_password \| REDIS_URL \| redis_url | 8 | 8 | RNC-SL-POS-000106 |
| application_password \| command \| compose_command_arg | 8 | 0 | RNC-SL-POS-000115 |
| database_password \| DATABASE_URL \| database_url | 8 | 8 | RNC-SL-POS-000105 |
| database_password \| NO_ASSIGNMENT_IDENTIFIER \| log_command_argument | 7 | 0 | RNC-SL-POS-000017 |
| database_password \| sqlalchemy.url \| alembic_url | 7 | 0 | RNC-SL-POS-000154 |
| wordpress_salt \| LOGGED_IN_SALT \| php_string_literal | 7 | 0 | RNC-SL-POS-000025 |
| wordpress_salt \| NONCE_SALT \| php_string_literal | 7 | 0 | RNC-SL-POS-000026 |
| wordpress_salt \| WP_SALT_1 \| php_define | 7 | 0 | RNC-SL-POS-000002 |
| wordpress_salt \| WP_SALT_2 \| php_define | 7 | 0 | RNC-SL-POS-000003 |
| wordpress_salt \| WP_SALT_3 \| php_define | 7 | 0 | RNC-SL-POS-000004 |
| wordpress_salt \| WP_SALT_4 \| php_define | 7 | 0 | RNC-SL-POS-000005 |
| wordpress_salt \| WP_SALT_5 \| php_define | 7 | 0 | RNC-SL-POS-000006 |
| wordpress_salt \| WP_SALT_6 \| php_define | 7 | 0 | RNC-SL-POS-000007 |

The remaining password misses are not explained by one identifier. They combine WordPress salt names, database passwords, SMTP/FTP/administrative fields, URI/SQL/encoded containers and a smaller set of values that fail the generic-api-key value check. The latter is visible because the same identifier and representation is credited for a different value in a controlled standalone-file A/B case.

### Provider tokens, generic API keys and OTP seeds

| Category | subtype | provider | representation | container | cause | Missed | Capability | Example |
| --- | --- | --- | --- |
| otp_seed \| totp_seed \| TOTP / OTP \| python_string_literal \| ordinary_file \| RULE_ABSENT | 7 | observed-representation:generic-api-key | RNC-SL-POS-000160 |
| api_key \| generic_api_key \| Unidentified API provider \| compose_environment_value \| ordinary_file \| RULE_ABSENT | 5 | observed-subtype:generic-api-key | RNC-SL-POS-000045 |
| api_key \| generic_api_key \| Unidentified API provider \| env_value \| ordinary_file \| RULE_ABSENT | 5 | observed-subtype:generic-api-key | RNC-SL-POS-000040 |
| otp_seed \| totp_seed \| TOTP / OTP \| otpauth_secret \| ordinary_file \| RULE_ABSENT | 5 | no-observed-rule | RNC-SL-POS-000047 |
| api_key \| generic_api_key \| Unidentified API provider \| sqlite_table_cell \| database_record \| SOURCE_UNSUPPORTED | 4 | observed-subtype:generic-api-key | RNC-SL-POS-000128 |
| api_key \| generic_api_key \| Unidentified API provider \| bson_string_value \| database_record \| SOURCE_UNSUPPORTED | 1 | observed-subtype:generic-api-key | RNC-SL-POS-000127 |
| api_key \| generic_api_key \| Unidentified API provider \| env_value \| archive_member \| SOURCE_UNSUPPORTED | 1 | observed-subtype:generic-api-key | RNC-SL-POS-000032 |
| provider_token \| twilio_auth_token \| Twilio \| yaml_value \| git_blob \| UNKNOWN | 1 | observed-subtype:generic-api-key | RNC-SL-POS-000777 |

- Twilio auth-token values are not covered by a provider rule; verify the documented shape before adding one.
- Generic `ak_`/`MINIO_ROOT_USER`-style values are not provider-identifiable from the value alone; a pair-aware assignment context is required rather than a blanket high-entropy rule.
- TOTP seeds require an otpauth/OTP-seed rule and must not be conflated with generic passwords.

### Private keys and encoded key containers

| Subtype | representation | container | Expected | Matched | Missed | Recall |
| --- | --- | --- | --- | --- |
| rsa_private_key_pkcs1 \| putty_ppk_v2 \| ordinary_file | 8 | 0 | 8 | 0.00% |
| tls_private_key_pkcs8 \| pkcs12_der \| binary_file | 4 | 0 | 4 | 0.00% |
| pem_private_key \| source_line \| ordinary_file | 2 | 0 | 2 | 0.00% |
| wallet_seed_phrase \| section_text \| ordinary_file | 2 | 0 | 2 | 0.00% |
| ed25519_private_key_pkcs8 \| pem_pkcs8 \| archive_member | 1 | 0 | 1 | 0.00% |
| putty_ppk_private_key \| putty_ppk_v2 \| git_blob | 1 | 0 | 1 | 0.00% |
| tls_private_key_pkcs8 \| pem_pkcs8 \| archive_member | 1 | 0 | 1 | 0.00% |
| rsa_private_key_pkcs1 \| pem_pkcs1 \| git_blob | 10 | 10 | 0 | 100.00% |
| ec_private_key_sec1 \| pem_sec1 \| ordinary_file | 4 | 4 | 0 | 100.00% |
| ed25519_private_key_pkcs8 \| pkcs8_encrypted_aes256 \| ordinary_file | 3 | 3 | 0 | 100.00% |
| rsa_private_key_pkcs1 \| section_text \| ordinary_file | 3 | 3 | 0 | 100.00% |
| openssh_private_key_rsa \| openssh_private_key_file \| ordinary_file | 2 | 2 | 0 | 100.00% |
| pem_private_key \| pem_block \| git_blob | 2 | 2 | 0 | 100.00% |
| pem_private_key \| pem_block \| ordinary_file | 2 | 2 | 0 | 100.00% |
| openssh_private_key_ed25519 \| kubernetes_ssh_key \| ordinary_file | 1 | 1 | 0 | 100.00% |
| openssh_private_key_ed25519 \| openssh_private_key_file \| ordinary_file | 1 | 1 | 0 | 100.00% |
| rsa_private_key_pkcs8 \| pkcs8_encrypted_aes256 \| ordinary_file | 1 | 1 | 0 | 100.00% |
| tls_private_key_pkcs8 \| kubeconfig_client_key \| ordinary_file | 1 | 1 | 0 | 100.00% |
| tls_private_key_pkcs8 \| kubernetes_tls_key \| ordinary_file | 1 | 1 | 0 | 100.00% |

Most remaining private-key failures are format/container gaps: PuTTY PPK v2 and PKCS#12 are not PEM blocks, and archived PEM material never reaches the matcher. Wallet seed phrases are a distinct mnemonic credential and should not be counted as private-key material. Do not mark a public-key-only, SPKI-only, encrypted-container-only or filename-only observation as private-key credit. The existing PEM findings that are credited must remain credited; no historical scoring artifact is being reclassified as a new false negative here.

Private-key passphrases are counted separately as password targets when the oracle models them as such; a passphrase is not interchangeable with the key material.

### Where the misses live

| Source container | Expected | Matched | Missed | Recall | Risk misses |
| --- | --- | --- | --- | --- | --- |
| ordinary_file | 874 | 440 | 434 | 50.34% | 348 |
| git_blob | 225 | 151 | 74 | 67.11% | 74 |
| database_record | 12 | 0 | 12 | 0.00% | 12 |
| archive_member | 10 | 0 | 10 | 0.00% | 10 |
| binary_file | 4 | 0 | 4 | 0.00% | 4 |

**Missed file types.**

| File type | Missed | Risk misses | Cross-scanner found |
| --- | --- | --- | --- |
| env | 141 | 135 | 58 |
| json | 68 | 30 | 23 |
| log | 52 | 52 | 24 |
| yaml | 43 | 43 | 21 |
| php | 42 | 36 | 4 |
| xml | 30 | 23 | 8 |
| python | 18 | 18 | 11 |
| shell | 16 | 8 | 4 |
| text | 13 | 11 | 1 |
| sql | 12 | 12 | 0 |
| config | 11 | 8 | 0 |
| ini | 11 | 11 | 4 |
| ppk | 11 | 10 | 0 |
| sqlite | 10 | 10 | 0 |
| no-extension | 8 | 3 | 0 |
| ftpconfig | 7 | 4 | 0 |
| netrc | 6 | 6 | 0 |
| zip | 5 | 5 | 3 |

**Missed representations.**

| Representation | Missed | Risk misses | Cross-scanner found |
| --- | --- | --- | --- |
| php_define | 77 | 74 | 0 |
| json_string | 61 | 18 | 12 |
| assignment | 50 | 26 | 18 |
| dotenv_value | 49 | 49 | 40 |
| section_text | 36 | 36 | 15 |
| php_string_literal | 16 | 16 | 2 |
| python_string_literal | 16 | 16 | 9 |
| xml_element_or_attribute | 16 | 9 | 2 |
| env_value | 15 | 15 | 2 |
| yaml_value | 14 | 13 | 13 |
| source_line | 12 | 5 | 0 |
| sql_copy_value | 12 | 12 | 0 |
| sqlite_table_cell | 10 | 10 | 0 |
| database_url | 9 | 9 | 9 |
| putty_ppk_v2 | 9 | 9 | 0 |
| browser_encrypted_value | 8 | 8 | 4 |
| compose_command_arg | 8 | 8 | 0 |
| compose_environment_value | 8 | 8 | 3 |

| Inspection disposition | Expected | Matched | Missed |
| --- | --- | --- | --- |
| INSPECTED | 949 | 521 | 428 |
| INSPECTED_UNVERIFIED | 150 | 70 | 80 |
| UNSUPPORTED_CONTAINER | 26 | 0 | 26 |

26 expected positives live in a non-plaintext container. Of these, 10 are archive members, 12 are database records and 4 are binary key containers.

The scanner emitted no finding with a non-null archive member, database row or PKCS#12 container across this run. A miss in this category is therefore classified as `SOURCE_UNSUPPORTED`, not as a regex false negative. An archive file being encountered is not evidence that its members were scanned.

Eligible-but-uninspected expected positives: 0. The RNC Lab filesystem lane reports 11 uninspected symlink aliases; none of them is an expected positive target in the frozen oracle. That is a scanner coverage caveat, not a positive-recall gap.

### Load-replicated evidence (not canonical accuracy)

| Profile | Median s | Inspected/eligible | Coverage % | Stability | Coverage caveat | Accuracy scored |
| --- | --- | --- | --- | --- | --- | --- |
| legacy-5x | 2.556 | 1810/1810 | 100.0 | STABLE | - | NO |
| legacy-10x | 4.294 | 3610/3610 | 100.0 | STABLE | - | NO |

These corpora are performance replicas. Their repeated files are not additional canonical targets and are excluded from every recall denominator in this report. The x5/x10 runs are still useful for source-coverage anomalies: a replicated file that the scanner excludes by a total-byte limit is a load-scope caveat, not a new oracle target.

- No load-profile coverage shortfall was reported by this scanner.


### False positives, near misses and regression fixtures

| Signal | Value |
| --- | --- |
| RNC Lab filesystem verified false-positive alerts | 4 |
| RNC Lab Git verified false-positive alerts | 7 |
| Levain false positives | 3 |
| Leaky filesystem unexpected findings | 0 |
| Precision certified | NO |

5 missed target(s) have a same-location scanner observation that the scorer did not credit (`UNVERIFIED_EVIDENCE`). These are not silent regex misses.

| Target | Rule | Stage | Reason code |
| --- | --- | --- | --- |
| RNC-SL-POS-000617 | pkcs12-file | VALUE | EVIDENCE_CONFLICT |
| RNC-SL-POS-000618 | pkcs12-file | VALUE | EVIDENCE_CONFLICT |
| RNC-SL-POS-000619 | pkcs12-file | VALUE | EVIDENCE_CONFLICT |
| RNC-SL-POS-000620 | pkcs12-file | VALUE | EVIDENCE_CONFLICT |
| RNC-SL-POS-000652 | generic-api-key | VALUE | EVIDENCE_CONFLICT |

Regression fixtures available for proposed changes: the RNC Lab oracle has 400 negative-ordinary and 202 negative-trap items (162 trap items in the filesystem lane and 40 in Git); Leaky Repo history has 89 reviewed negative references and 30 informative references; Levain has 116 negative sections. These are the first fixtures to run after any identifier, decoder or validator change. The negative oracle is not exhaustive, so a new rule must be evaluated against false-positive alerts as well as recovered positives. No precision claim is made from the absence of an alert.

## Root-cause interpretation

A target is marked `SOURCE_UNSUPPORTED` only when the same run produced no credited finding in that container class. `SOURCE_NOT_INSPECTED` requires a coverage record, not merely an absent finding. `CAPTURE_MISMATCH` requires a retained same-location observation whose value evidence failed. `SCORING_MISMATCH` requires a usable scanner observation rejected by the scorer. `IDENTIFIER_MISMATCH`, `RULE_ABSENT`, `FORMAT_UNSUPPORTED`, `CONTEXT_INSUFFICIENT`, `VALIDATOR_REJECTION` and `UNKNOWN` are kept distinct because they imply different development work.

See the standalone root-cause dossier for the full evidence and reproduction table.

## Cross-scanner context

| Other scanner | Finds the same missed target | Share of this scanner's misses |
| --- | --- | --- |
| RNC Scanner CP4C | 139 | 26.03% |
| RNC-Mod V16 | 1 | 0.19% |
| Gitleaks master | 0 | 0.00% |
| Betterleaks 1.8.1 | 135 | 25.28% |

This is an oracle-target join, not raw string similarity. It demonstrates that the content is present in the same frozen dataset; it does not prove that the other scanner used the same source scope or rule.

## Prioritized improvements

1. **wordpress authentication material** - 93 risk-bearing targets; `IDENTIFIER_MISMATCH`; Add a reviewed WordPress authentication-key/salt identifier family to the generic assignment matcher (AUTH_KEY, SECURE_AUTH_KEY, LOGGED_IN_KEY, NONCE_KEY, AUTH_SALT, SECURE_AUTH_SALT, LOGGED_IN_SALT, NONCE_SALT and WP_SALT_n). Use the existing assignment and high-entropy checks; do not add a bare SALT keyword.
2. **database password identifiers** - 76 risk-bearing targets; `CONTEXT_INSUFFICIENT`; Instrument the database-password candidate pipeline and context association before broadening the identifier set. The same subtype and representation is credited for other values, so the decisive difference may be a value check or field-role association, not a missing identifier. Add no broad new pattern until an A/B candidate trace identifies the rejecting stage.
3. **application password identifiers** - 68 risk-bearing targets; `CONTEXT_INSUFFICIENT`; Instrument and extend the application-password field-role/context association. The same subtype, identifier and representation is credited for other values, so a broad identifier rule is not the right first change. Verify whether the candidate was generated and rejected at the value/context stage.
4. **password positional or encoded** - 61 risk-bearing targets; `FORMAT_UNSUPPORTED`; Add bounded parsers for positional credential files (.pgpass, .netrc, .git-credentials), Docker auth, FileZilla/JetBrains encoded fields and SQL COPY/INSERT password columns. Add reviewed identifier aliases only for fields that remain ordinary assignments. Emit findings only when the field role and value shape agree.
5. **password in uri or connection string** - 27 risk-bearing targets; `FORMAT_UNSUPPORTED`; Implement a URI/connection-string password parser for password-only userinfo (redis://:password@host), driver-qualified schemes (postgresql+psycopg2), percent-decoding and SQLAlchemy/Alembic URL settings. Preserve the current database-uri rule for user:password forms.

The detailed backlog is in the companion file; it ranks by recoverable count, severity, concentration, context availability, false-positive risk and implementation complexity.

## Limitations

- This is an independent evaluator report. No scanner rule, source file, oracle, or scoring policy was modified.
- Leaky Repo filesystem is a line-level detection benchmark without a complete negative oracle; precision and F1 are not certified.
- Leaky Repo Git precision/F1 are not certified; 65 source occurrences and 53 unique groups are separate denominators.
- Leaky Git source units are marked INSPECTED_UNVERIFIED for adapters that do not return a true coverage attestation; this is not evidence that a unit was skipped.
- RNC Lab precision/F1 are not certified; the 640 filesystem and 160 Git positive denominators are separate and are not combined.
- The 11 RNC Lab symlink aliases are not followed by the scanner. They contain no expected positive target in this oracle, so they do not change the positive recall denominator.
- Provider and subtype labels for Leaky Repo and Levain are source-context inferences because those oracles do not expose the Lab's fine-grained subtype taxonomy. RNC Lab labels come directly from its oracle.
- A miss is not proof that a regular expression failed. Candidate rejection, source acquisition, context association, and value extraction are distinct layers.
- Scanner-side candidate instrumentation is required to turn some PROBABLE or UNRESOLVED causes into confirmed ones.
- V14/V16 use compiled-in Gitleaks rules; rule presence is inferred from retained findings and controlled reproductions, not from a rule-file inventory.

## Reproduction

```powershell
python -m harness detection-gaps --out-dir reports/detection-gaps
python -m unittest tests.test_detection_gaps -v
```

The generator reads the retained reports and frozen oracles only; it does not execute a scanner or change a dataset.
