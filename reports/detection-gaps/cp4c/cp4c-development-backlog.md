# RNC Scanner CP4C - prioritized development backlog

Ranking is by recoverable risk-bearing target count, operational severity, concentration in a reusable family, availability of provider/context identifiers, cross-scanner evidence, likely false-positive risk and implementation complexity. Informative references are excluded. This is a development proposal, not an implemented detector change.

## Top five recommendations

### 1. Wordpress Authentication Material - 142 recoverable targets

- **Cause:** `IDENTIFIER_MISMATCH`; confidence `CONFIRMED`.
- **Concentration:** 142 misses, 49 already found by at least one comparison scanner; lanes: leaky_filesystem, leaky_git, rnclab_filesystem.
- **Representations:** kubernetes_secret_data, php_define, php_string_literal.
- **Identifiers:** AUTH_KEY, AUTH_SALT, LOGGED_IN_KEY, LOGGED_IN_SALT, NONCE_KEY, NONCE_SALT, SECURE_AUTH_KEY, SECURE_AUTH_SALT, WP_SALT_1, WP_SALT_2.
- **Change:** Add a reviewed WordPress authentication-key/salt identifier family to the generic assignment matcher (AUTH_KEY, SECURE_AUTH_KEY, LOGGED_IN_KEY, NONCE_KEY, AUTH_SALT, SECURE_AUTH_SALT, LOGGED_IN_SALT, NONCE_SALT and WP_SALT_n). Use the existing assignment and high-entropy checks; do not add a bare SALT keyword.
- **False-positive risk:** LOW; **complexity:** LOW.
- **Reuse:** All PHP, .env, Kubernetes Secret and Git occurrences; no provider-network requirement.
- **Examples:** `leaky-repo:web/var/www/public_html/wp-config.php:33:risk, `leaky-repo:web/var/www/public_html/wp-config.php:35:risk, `leaky-repo:web/var/www/public_html/wp-config.php:37:risk, `leaky-repo:web/var/www/public_html/wp-config.php:39:risk, `leaky-repo:web/var/www/public_html/wp-config.php:41:risk, `leaky-repo:web/var/www/public_html/wp-config.php:43:risk, `leaky-repo:web/var/www/public_html/wp-config.php:45:risk, `leaky-repo:web/var/www/public_html/wp-config.php:47:risk.

### 2. Password Positional Or Encoded - 66 recoverable targets

- **Cause:** `FORMAT_UNSUPPORTED`; confidence `PROBABLE`.
- **Concentration:** 66 misses, 5 already found by at least one comparison scanner; lanes: leaky_filesystem, leaky_git, levain, rnclab_filesystem.
- **Representations:** base64_value, compose_command_arg, docker_config_auth, docker_secret_file, dotenv_value, filezilla_base64_password, hash_value, jetbrains_static_key_obfuscated.
- **Identifiers:** NO_ASSIGNMENT_IDENTIFIER, Pass, _authToken, admin, auth, command, git_credentials_url, netrc_password, pgpass_password_field, token.
- **Change:** Add bounded parsers for positional credential files (.pgpass, .netrc, .git-credentials), Docker auth, FileZilla/JetBrains encoded fields and SQL COPY/INSERT password columns. Add reviewed identifier aliases only for fields that remain ordinary assignments. Emit findings only when the field role and value shape agree.
- **False-positive risk:** MEDIUM; **complexity:** HIGH.
- **Reuse:** Several legacy formats share the same field-role model; avoid one-off regexes.
- **Examples:** `LEV-S43-K01, `leaky-repo:.esmtprc:4:risk, `leaky-repo:.git-credentials:1:risk, `leaky-repo:.netrc:1:risk, `leaky-repo:.netrc:2:risk, `leaky-repo:.npmrc:7:risk, `leaky-repo:db/.pgpass:2:risk, `leaky-repo:db/dump.sql:32:risk.

### 3. Hmac And Signing Identifiers - 61 recoverable targets

- **Cause:** `IDENTIFIER_MISMATCH`; confidence `CONFIRMED`.
- **Concentration:** 61 misses, 58 already found by at least one comparison scanner; lanes: levain, rnclab_filesystem, rnclab_git.
- **Representations:** env_value, json_string, kubernetes_secret_data, python_string_literal, section_text.
- **Identifiers:** Authorization, JWT_SIGNING_KEY, PAYMENTS_SIGNING_KEY, SECRET_KEY, SIGNING_KEY, SigningKey, jwt-signing-key.
- **Change:** Extend the generic assignment identifier family for SIGNING_KEY, HMAC_KEY, HMAC_SECRET and camelCase JSON fields such as SigningKey, while retaining the current assignment-context and value-entropy requirements. Add a JWT_SIGNING_KEY alias rather than a bare KEY rule. The expression-wrapped and JSON subcases need the matching context/decoder work; the identifier change alone recovers the direct assignment subset.
- **False-positive risk:** MEDIUM; **complexity:** LOW.
- **Reuse:** Environment files, Python expressions, JSON, YAML and Git snapshots; container work is separate.
- **Examples:** `LEV-S45-K01, `RNC-SL-POS-000108, `RNC-SL-POS-000114, `RNC-SL-POS-000155, `RNC-SL-POS-000179, `RNC-SL-POS-000190, `RNC-SL-POS-000203, `RNC-SL-POS-000209.

### 4. Structured Container - 26 recoverable targets

- **Cause:** `SOURCE_UNSUPPORTED`; confidence `CONFIRMED`.
- **Concentration:** 26 misses, 8 already found by at least one comparison scanner; lanes: rnclab_filesystem.
- **Representations:** bson_string_value, dotenv_value, env_value, log_kv_value, pem_pkcs8, pkcs12_der, sqlite_table_cell.
- **Identifiers:** API_TOKEN, DB_PASSWORD, POSTGRES_PASSWORD, PRIVATE_KEY_BLOCK, REDIS_PASSWORD, RELEASE_DB_PASSWORD, admin_password, api_key, client_secret, db_password.
- **Change:** Add archive-member, SQLite-row/BSON-field and binary-container traversal with bounded expansion and source attribution. Do not count an archive container as inspected unless its members are actually inspected.
- **False-positive risk:** MEDIUM; **complexity:** VERY HIGH.
- **Reuse:** One source-acquisition framework serves archives, databases and nested containers.
- **Examples:** `RNC-SL-POS-000029, `RNC-SL-POS-000030, `RNC-SL-POS-000031, `RNC-SL-POS-000032, `RNC-SL-POS-000033, `RNC-SL-POS-000034, `RNC-SL-POS-000035, `RNC-SL-POS-000036.

### 5. Application Password Identifiers - 25 recoverable targets

- **Cause:** `IDENTIFIER_MISMATCH`; confidence `CONFIRMED`.
- **Concentration:** 25 misses, 8 already found by at least one comparison scanner; lanes: leaky_filesystem, leaky_git, levain, rnclab_filesystem.
- **Representations:** assignment, json_string, redis_config_directive, section_text, source_line, xml_element_or_attribute.
- **Identifiers:** APP_KEY, IRC_PASS, MLAB_PASS, Pass, auth, connection, indexes, pass, root, tFs.
- **Change:** Add the missing reviewed application-password aliases (SMTP, FTP, Redis, registry and admin qualifiers) and, where the alias is already recognized, extend the field-role/context association instead of adding a broad rule. Do not add a generic USERNAME or EMAIL rule.
- **False-positive risk:** MEDIUM; **complexity:** MEDIUM.
- **Reuse:** Environment, YAML, JSON, INI and XML configuration.
- **Examples:** `LEV-S11-K01, `LEV-S26-K01, `leaky-repo:.bash_profile:24:risk, `leaky-repo:.docker/.dockercfg:4:risk, `leaky-repo:.docker/.dockercfg:8:risk, `leaky-repo:.docker/config.json:5:risk, `leaky-repo:.docker/config.json:9:risk, `leaky-repo:.ftpconfig:6:risk.

## Full opportunity table

| Rank | Opportunity | Cause | Risk misses | Cross-found | Confidence | FP risk | Complexity |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | wordpress_authentication_material | IDENTIFIER_MISMATCH | 142 | 49 | CONFIRMED | LOW | LOW |
| 2 | password_positional_or_encoded | FORMAT_UNSUPPORTED | 66 | 5 | PROBABLE | MEDIUM | HIGH |
| 3 | hmac_and_signing_identifiers | IDENTIFIER_MISMATCH | 61 | 58 | CONFIRMED | MEDIUM | LOW |
| 4 | structured_container | SOURCE_UNSUPPORTED | 26 | 8 | CONFIRMED | MEDIUM | VERY HIGH |
| 5 | application_password_identifiers | IDENTIFIER_MISMATCH | 25 | 8 | CONFIRMED | MEDIUM | MEDIUM |
| 6 | provider_token:Unidentified provider token | RULE_ABSENT | 25 | 15 | CONFIRMED | HIGH | MEDIUM |
| 7 | database_password_identifiers | IDENTIFIER_MISMATCH | 17 | 9 | CONFIRMED | MEDIUM | MEDIUM |
| 8 | passphrase_identifiers | IDENTIFIER_MISMATCH | 16 | 0 | CONFIRMED | MEDIUM | LOW |
| 9 | password_in_uri_or_connection_string | FORMAT_UNSUPPORTED | 15 | 8 | PROBABLE | LOW | MEDIUM |
| 10 | private_key_container_or_pem | FORMAT_UNSUPPORTED | 15 | 3 | CONFIRMED | MEDIUM | HIGH |
| 11 | totp_seed | RULE_ABSENT | 12 | 0 | CONFIRMED | MEDIUM | LOW |
| 12 | generic_api_key | RULE_ABSENT | 11 | 1 | CONFIRMED | HIGH | MEDIUM |
| 13 | provider_token:Amazon Web Services (AWS) | CONTEXT_INSUFFICIENT | 7 | 7 | PROBABLE | LOW | LOW |
| 14 | provider_token:Microsoft Azure Storage | FORMAT_UNSUPPORTED | 5 | 5 | PROBABLE | LOW | LOW |
| 15 | encrypted_browser_credentials | FORMAT_UNSUPPORTED | 4 | 0 | CONFIRMED | MEDIUM | HIGH |
| 16 | other:application_secret | IDENTIFIER_MISMATCH | 4 | 1 | PROBABLE | UNKNOWN | UNKNOWN |
| 17 | other:payment_card | IDENTIFIER_MISMATCH | 2 | 0 | PROBABLE | UNKNOWN | UNKNOWN |
| 18 | other:unspecified_credential | IDENTIFIER_MISMATCH | 2 | 0 | PROBABLE | UNKNOWN | UNKNOWN |
| 19 | provider_token:GitHub | CONTEXT_INSUFFICIENT | 2 | 2 | PROBABLE | LOW | LOW |
| 20 | provider_token:npm | CONTEXT_INSUFFICIENT | 2 | 2 | PROBABLE | LOW | LOW |
| 21 | other:confluent_cloud_key | IDENTIFIER_MISMATCH | 1 | 1 | PROBABLE | UNKNOWN | UNKNOWN |
| 22 | other:confluent_cloud_secret | IDENTIFIER_MISMATCH | 1 | 1 | PROBABLE | UNKNOWN | UNKNOWN |
| 23 | other:email | IDENTIFIER_MISMATCH | 1 | 0 | PROBABLE | UNKNOWN | UNKNOWN |
| 24 | other:google_oauth_client_secret | IDENTIFIER_MISMATCH | 1 | 0 | PROBABLE | UNKNOWN | UNKNOWN |
| 25 | other:openai_project_key | IDENTIFIER_MISMATCH | 1 | 0 | PROBABLE | UNKNOWN | UNKNOWN |
| 26 | other:url_password | IDENTIFIER_MISMATCH | 1 | 0 | PROBABLE | UNKNOWN | UNKNOWN |
| 27 | provider_token:Slack | FORMAT_UNSUPPORTED | 1 | 1 | PROBABLE | LOW | LOW |
| 28 | provider_token:Stripe | RULE_ABSENT | 1 | 1 | CONFIRMED | LOW | LOW |
| 29 | provider_token:Twilio SendGrid | VALIDATOR_REJECTION | 1 | 1 | PROBABLE | LOW | LOW |

## Generalization rules

- Prefer a reviewed identifier family or a structured parser over a fixture-specific regex.
- Keep assignment/context and value-shape gates; do not replace them with a global entropy threshold change.
- Add negative fixtures for the same identifier family before enabling a broader rule.
- For archive/database work, keep bounded expansion and source attribution; never count the container as inspected.
- For value-validator causes, reproduce the exact value/identifier A/B before changing a validator; a scanner-side candidate trace is required.

## Recommended sequencing

1. Low-complexity, high-yield identifier families (WordPress salts, signing/HMAC names, passphrases, TOTP).
2. URI/structured password extraction and provider-specific separators (Azure JSON, Stripe webhook).
3. Key-container formats (PPK, PKCS#12) and archive/database source acquisition.
4. Value-validator instrumentation and narrowly scoped corrections.
5. Re-run the full negative oracle after each stage.
