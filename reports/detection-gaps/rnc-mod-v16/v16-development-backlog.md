# RNC-Mod V16 - prioritized development backlog

Ranking is by recoverable risk-bearing target count, operational severity, concentration in a reusable family, availability of provider/context identifiers, cross-scanner evidence, likely false-positive risk and implementation complexity. Informative references are excluded. This is a development proposal, not an implemented detector change.

## Top five recommendations

### 1. Wordpress Authentication Material - 93 recoverable targets

- **Cause:** `IDENTIFIER_MISMATCH`; confidence `PROBABLE`.
- **Concentration:** 93 misses, 0 already found by at least one comparison scanner; lanes: leaky_filesystem, leaky_git, rnclab_filesystem.
- **Representations:** kubernetes_secret_data, php_define, php_string_literal.
- **Identifiers:** AUTH_KEY, AUTH_SALT, LOGGED_IN_KEY, LOGGED_IN_SALT, NONCE_KEY, NONCE_SALT, SECURE_AUTH_KEY, SECURE_AUTH_SALT, WP_SALT_1, WP_SALT_2.
- **Change:** Add a reviewed WordPress authentication-key/salt identifier family to the generic assignment matcher (AUTH_KEY, SECURE_AUTH_KEY, LOGGED_IN_KEY, NONCE_KEY, AUTH_SALT, SECURE_AUTH_SALT, LOGGED_IN_SALT, NONCE_SALT and WP_SALT_n). Use the existing assignment and high-entropy checks; do not add a bare SALT keyword.
- **False-positive risk:** LOW; **complexity:** LOW.
- **Reuse:** All PHP, .env, Kubernetes Secret and Git occurrences; no provider-network requirement.
- **Examples:** `leaky-repo:web/var/www/public_html/wp-config.php:33:risk, `leaky-repo:web/var/www/public_html/wp-config.php:35:risk, `leaky-repo:web/var/www/public_html/wp-config.php:37:risk, `leaky-repo:web/var/www/public_html/wp-config.php:39:risk, `leaky-repo:web/var/www/public_html/wp-config.php:41:risk, `leaky-repo:web/var/www/public_html/wp-config.php:43:risk, `leaky-repo:web/var/www/public_html/wp-config.php:45:risk, `leaky-repo:web/var/www/public_html/wp-config.php:47:risk.

### 2. Database Password Identifiers - 76 recoverable targets

- **Cause:** `CONTEXT_INSUFFICIENT`; confidence `PROBABLE`.
- **Concentration:** 76 misses, 68 already found by at least one comparison scanner; lanes: leaky_filesystem, leaky_git, rnclab_filesystem, rnclab_git.
- **Representations:** assignment, cloud_init_password, compose_environment_value, dotenv_value, github_actions_expression_value, json_string, php_define, php_string_literal.
- **Identifiers:** DB_PASSWORD, MARIADB-0001_PASSWORD, MARIADB-0002_PASSWORD, MARIADB_ROOT_PASSWORD, MONGO-0001_PASSWORD, MONGO-0002_PASSWORD, PASSWORD, POSTGRES-0001_PASSWORD, POSTGRES_PASSWORD, Password.
- **Change:** Instrument the database-password candidate pipeline and context association before broadening the identifier set. The same subtype and representation is credited for other values, so the decisive difference may be a value check or field-role association, not a missing identifier. Add no broad new pattern until an A/B candidate trace identifies the rejecting stage.
- **False-positive risk:** MEDIUM; **complexity:** MEDIUM.
- **Reuse:** A validator/context fix would apply to every database and application format.
- **Examples:** `leaky-repo:db/mongoid.yml:4:risk, `leaky-repo:db/robomongo.json:14:risk, `leaky-repo:db/robomongo.json:27:risk, `leaky-repo:web/var/www/.env:14:risk, `leaky-repo:web/var/www/.env:23:risk, `leaky-repo:web/var/www/public_html/wp-config.php:20:risk, `LH-0103, `LH-0105.

### 3. Application Password Identifiers - 68 recoverable targets

- **Cause:** `CONTEXT_INSUFFICIENT`; confidence `PROBABLE`.
- **Concentration:** 68 misses, 51 already found by at least one comparison scanner; lanes: leaky_filesystem, leaky_git, levain, rnclab_filesystem.
- **Representations:** assignment, dotenv_value, json_string, log_kv_value, log_quoted_value, maven_settings_password, python_string_literal, redis_config_directive.
- **Identifiers:** APP_KEY, AdminPassword, Configuration, EMAIL_HOST_PASSWORD, ENCODED_VALUE_REDACTED, GMAIL_PASSWORD, IRC_PASS, MAIL_PASSWORD, MLAB_PASS, Pass.
- **Change:** Instrument and extend the application-password field-role/context association. The same subtype, identifier and representation is credited for other values, so a broad identifier rule is not the right first change. Verify whether the candidate was generated and rejected at the value/context stage.
- **False-positive risk:** MEDIUM; **complexity:** MEDIUM.
- **Reuse:** Context-model fix applies across configuration formats.
- **Examples:** `LEV-S04-K01, `LEV-S09-K01, `LEV-S10-K01, `LEV-S11-K01, `LEV-S26-K01, `LEV-S40-K01, `leaky-repo:.bash_profile:20:risk, `leaky-repo:.bash_profile:24:risk.

### 4. Password Positional Or Encoded - 61 recoverable targets

- **Cause:** `FORMAT_UNSUPPORTED`; confidence `PROBABLE`.
- **Concentration:** 61 misses, 0 already found by at least one comparison scanner; lanes: leaky_filesystem, leaky_git, levain, rnclab_filesystem.
- **Representations:** base64_value, compose_command_arg, docker_config_auth, docker_secret_file, dotenv_value, filezilla_base64_password, hash_value, jetbrains_static_key_obfuscated.
- **Identifiers:** NO_ASSIGNMENT_IDENTIFIER, Pass, _authToken, admin, auth, command, git_credentials_url, netrc_password, pgpass_password_field, token.
- **Change:** Add bounded parsers for positional credential files (.pgpass, .netrc, .git-credentials), Docker auth, FileZilla/JetBrains encoded fields and SQL COPY/INSERT password columns. Add reviewed identifier aliases only for fields that remain ordinary assignments. Emit findings only when the field role and value shape agree.
- **False-positive risk:** MEDIUM; **complexity:** HIGH.
- **Reuse:** Several legacy formats share the same field-role model; avoid one-off regexes.
- **Examples:** `LEV-S43-K01, `leaky-repo:.esmtprc:4:risk, `leaky-repo:.git-credentials:1:risk, `leaky-repo:.netrc:1:risk, `leaky-repo:.netrc:2:risk, `leaky-repo:.npmrc:7:risk, `leaky-repo:db/.pgpass:2:risk, `leaky-repo:db/dump.sql:32:risk.

### 5. Password In Uri Or Connection String - 27 recoverable targets

- **Cause:** `FORMAT_UNSUPPORTED`; confidence `PROBABLE`.
- **Concentration:** 27 misses, 20 already found by at least one comparison scanner; lanes: rnclab_filesystem.
- **Representations:** alembic_url, database_url, mongodb_uri, redis_url, sqlserver_connection_string.
- **Identifiers:** DATABASE_URL, Default, REDIS_URL, WAREHOUSE_DSN, authSource, sqlalchemy.url.
- **Change:** Implement a URI/connection-string password parser for password-only userinfo (redis://:password@host), driver-qualified schemes (postgresql+psycopg2), percent-decoding and SQLAlchemy/Alembic URL settings. Preserve the current database-uri rule for user:password forms.
- **False-positive risk:** LOW; **complexity:** MEDIUM.
- **Reuse:** All application formats; provider-agnostic and directly reusable.
- **Examples:** `RNC-SL-POS-000105, `RNC-SL-POS-000106, `RNC-SL-POS-000121, `RNC-SL-POS-000123, `RNC-SL-POS-000154, `RNC-SL-POS-000189, `RNC-SL-POS-000200, `RNC-SL-POS-000201.

## Full opportunity table

| Rank | Opportunity | Cause | Risk misses | Cross-found | Confidence | FP risk | Complexity |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | wordpress_authentication_material | IDENTIFIER_MISMATCH | 93 | 0 | PROBABLE | LOW | LOW |
| 2 | database_password_identifiers | CONTEXT_INSUFFICIENT | 76 | 68 | PROBABLE | MEDIUM | MEDIUM |
| 3 | application_password_identifiers | CONTEXT_INSUFFICIENT | 68 | 51 | PROBABLE | MEDIUM | MEDIUM |
| 4 | password_positional_or_encoded | FORMAT_UNSUPPORTED | 61 | 0 | PROBABLE | MEDIUM | HIGH |
| 5 | password_in_uri_or_connection_string | FORMAT_UNSUPPORTED | 27 | 20 | PROBABLE | LOW | MEDIUM |
| 6 | structured_container | SOURCE_UNSUPPORTED | 26 | 8 | CONFIRMED | MEDIUM | VERY HIGH |
| 7 | passphrase_identifiers | IDENTIFIER_MISMATCH | 16 | 0 | PROBABLE | MEDIUM | LOW |
| 8 | private_key_container_or_pem | FORMAT_UNSUPPORTED | 12 | 0 | PROBABLE | MEDIUM | HIGH |
| 9 | provider_token:Unidentified provider token | RULE_ABSENT | 12 | 2 | PROBABLE | HIGH | MEDIUM |
| 10 | totp_seed | RULE_ABSENT | 12 | 0 | PROBABLE | MEDIUM | LOW |
| 11 | generic_api_key | RULE_ABSENT | 10 | 0 | PROBABLE | HIGH | MEDIUM |
| 12 | encrypted_browser_credentials | FORMAT_UNSUPPORTED | 8 | 4 | CONFIRMED | MEDIUM | HIGH |
| 13 | other:application_secret | UNKNOWN | 5 | 2 | PROBABLE | UNKNOWN | UNKNOWN |
| 14 | api_key:Amazon Web Services (AWS) | IDENTIFIER_MISMATCH | 4 | 4 | PROBABLE | UNKNOWN | UNKNOWN |
| 15 | hmac_and_signing_identifiers | VALIDATOR_REJECTION | 4 | 1 | PROBABLE | MEDIUM | LOW |
| 16 | other:payment_card | IDENTIFIER_MISMATCH | 2 | 0 | PROBABLE | UNKNOWN | UNKNOWN |
| 17 | other:unspecified_credential | IDENTIFIER_MISMATCH | 2 | 0 | PROBABLE | UNKNOWN | UNKNOWN |
| 18 | other:email | IDENTIFIER_MISMATCH | 1 | 0 | PROBABLE | UNKNOWN | UNKNOWN |
| 19 | other:google_oauth_client_secret | IDENTIFIER_MISMATCH | 1 | 0 | PROBABLE | UNKNOWN | UNKNOWN |
| 20 | other:openai_project_key | IDENTIFIER_MISMATCH | 1 | 0 | PROBABLE | UNKNOWN | UNKNOWN |
| 21 | other:tailscale_auth_key | IDENTIFIER_MISMATCH | 1 | 1 | PROBABLE | UNKNOWN | UNKNOWN |
| 22 | other:url_password | IDENTIFIER_MISMATCH | 1 | 0 | PROBABLE | UNKNOWN | UNKNOWN |
| 23 | provider_token:Amazon Web Services (AWS) | IDENTIFIER_MISMATCH | 1 | 1 | PROBABLE | LOW | LOW |
| 24 | provider_token:Twilio | UNKNOWN | 1 | 1 | UNRESOLVED | LOW | LOW |
| 25 | provider_token:Twilio SendGrid | IDENTIFIER_MISMATCH | 1 | 1 | PROBABLE | LOW | LOW |
| 26 | provider_token:npm | IDENTIFIER_MISMATCH | 1 | 1 | PROBABLE | LOW | LOW |

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
