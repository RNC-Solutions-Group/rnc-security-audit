# RNC Scanner CP4C - root causes and reproduction evidence

This file separates confirmed mechanisms from probable and unresolved hypotheses. `CONFIRMED` means the retained evidence establishes the mechanism without scanner-side guessing; `PROBABLE` means a controlled or cross-scanner observation strongly supports it but the scanner's internal candidate stage was not inspected; `UNRESOLVED` means the evidence cannot distinguish the listed layers.

## Classification summary

| Root cause | Layer | Misses | Confirmed | Probable | Unresolved |
| --- | --- | --- | --- | --- | --- |
| IDENTIFIER_MISMATCH | IDENTIFIER_LEXICON | 257 | 244 | 13 | 0 |
| FORMAT_UNSUPPORTED | REPRESENTATION_DECODER | 100 | 15 | 85 | 0 |
| INFORMATIVE_REFERENCE | ORACLE_CLASSIFICATION | 87 | 87 | 0 | 0 |
| RULE_ABSENT | RULE_COVERAGE | 48 | 46 | 2 | 0 |
| SOURCE_UNSUPPORTED | SOURCE_ACQUISITION | 26 | 26 | 0 | 0 |
| CONTEXT_INSUFFICIENT | CONTEXT_MODEL | 22 | 0 | 22 | 0 |
| UNKNOWN | UNRESOLVED | 12 | 0 | 0 | 12 |
| VALIDATOR_REJECTION | VALUE_VALIDATOR | 2 | 0 | 2 | 0 |
| CAPTURE_MISMATCH | VALUE_CAPTURE | 1 | 1 | 0 | 0 |

## Confirmed mechanisms

### `CAPTURE_MISMATCH` - 1 targets

Layer: `VALUE_CAPTURE`. Representative evidence: scanner finding exists at the expected source location but value evidence did not match (correct location but extracted value is missing or conflicts with expected value; mandatory investigation).

| Lane | Subtype | Identifier family | Count |
| --- | --- | --- | --- |
| leaky_filesystem | database_password | OTHER | 1 |

Examples: `leaky-repo:db/mongoid.yml:4:risk`.

### `FORMAT_UNSUPPORTED` - 15 targets

Layer: `REPRESENTATION_DECODER`. Representative evidence: the value is an encrypted Firefox login field; decryption requires the separate browser key material and the scanner has no browser-profile decoder.

| Lane | Subtype | Identifier family | Count |
| --- | --- | --- | --- |
| rnclab_filesystem | rsa_private_key_pkcs1 | OTHER | 8 |
| leaky_filesystem | browser_saved_credential | OTHER | 4 |
| leaky_filesystem | password_hash | OTHER | 2 |
| leaky_git | putty_ppk_private_key | OTHER | 1 |

Examples: `leaky-repo:.mozilla/firefox/logins.json:11:risk`, `leaky-repo:.mozilla/firefox/logins.json:27:risk`, `leaky-repo:.mozilla/firefox/logins.json:43:risk`, `leaky-repo:.mozilla/firefox/logins.json:59:risk`, `leaky-repo:etc/shadow:20:risk`, `leaky-repo:web/var/www/public_html/.htpasswd:1:risk`, `LH-0127`, `RNC-SL-POS-000633`, `RNC-SL-POS-000634`, `RNC-SL-POS-000635`, `RNC-SL-POS-000636`, `RNC-SL-POS-000637`.

### `IDENTIFIER_MISMATCH` - 244 targets

Layer: `IDENTIFIER_LEXICON`. Representative evidence: identifier 'MLAB_PASS' is outside the generic password/secret keyword set.

| Lane | Subtype | Identifier family | Count |
| --- | --- | --- | --- |
| rnclab_filesystem | wordpress_salt | WORDPRESS_SALT | 126 |
| rnclab_git | application_signing_key | SIGNING | 31 |
| rnclab_filesystem | application_hmac_key | SIGNING | 12 |
| rnclab_filesystem | jwt_signing_key | SIGNING | 10 |
| leaky_filesystem | wordpress_salt | WORDPRESS_SALT | 8 |
| leaky_git | wordpress_salt | WORDPRESS_SALT | 8 |
| rnclab_filesystem | database_password | OTHER | 6 |
| rnclab_filesystem | key_passphrase | PRIVATE_KEY_PASSPHRASE | 6 |
| rnclab_filesystem | pkcs12_passphrase | PRIVATE_KEY_PASSPHRASE | 6 |
| leaky_filesystem | docker_registry_password | OTHER | 4 |
| leaky_filesystem | ftp_password | PASSWORD | 4 |
| leaky_git | docker_registry_password | OTHER | 4 |

Examples: `leaky-repo:.bash_profile:24:risk`, `leaky-repo:.docker/.dockercfg:4:risk`, `leaky-repo:.docker/.dockercfg:8:risk`, `leaky-repo:.docker/config.json:5:risk`, `leaky-repo:.docker/config.json:9:risk`, `leaky-repo:.ftpconfig:12:risk`, `leaky-repo:.ftpconfig:6:risk`, `leaky-repo:db/dbeaver-data-sources.xml:4:risk`, `leaky-repo:db/robomongo.json:22:risk`, `leaky-repo:filezilla/filezilla.xml:13:risk`, `leaky-repo:filezilla/recentservers.xml:13:risk`, `leaky-repo:filezilla/recentservers.xml:30:risk`.

### `INFORMATIVE_REFERENCE` - 87 targets

Layer: `ORACLE_CLASSIFICATION`. Representative evidence: oracle classifies this occurrence as informative, not a risk-bearing secret.

| Lane | Subtype | Identifier family | Count |
| --- | --- | --- | --- |
| leaky_filesystem | unspecified_credential | OTHER | 58 |
| leaky_filesystem | ftp_password | OTHER | 9 |
| leaky_filesystem | application_password | PASSWORD | 4 |
| leaky_filesystem | github_personal_access_token | OTHER | 4 |
| leaky_filesystem | aws_access_key_id | ACCESS_KEY | 3 |
| leaky_filesystem | smtp_password | OTHER | 3 |
| leaky_filesystem | aws_secret_access_key | OTHER | 2 |
| leaky_filesystem | application_password | OTHER | 1 |
| leaky_filesystem | unspecified_credential | TOKEN | 1 |
| leaky_filesystem | database_password | OTHER | 1 |
| leaky_filesystem | pem_private_key | OTHER | 1 |

Examples: `leaky-repo:.bash_profile:11:informative`, `leaky-repo:.bash_profile:13:informative`, `leaky-repo:.bash_profile:18:informative`, `leaky-repo:.bash_profile:19:informative`, `leaky-repo:.bash_profile:25:informative`, `leaky-repo:.bashrc:104:informative`, `leaky-repo:.bashrc:107:informative`, `leaky-repo:.bashrc:108:informative`, `leaky-repo:.docker/.dockercfg:3:informative`, `leaky-repo:.docker/.dockercfg:7:informative`, `leaky-repo:.docker/config.json:4:informative`, `leaky-repo:.docker/config.json:8:informative`.

### `RULE_ABSENT` - 46 targets

Layer: `RULE_COVERAGE`. Representative evidence: no provider rule or same-subtype credit was observed for twilio_api_key_sid.

| Lane | Subtype | Identifier family | Count |
| --- | --- | --- | --- |
| rnclab_filesystem | totp_seed | OTHER | 12 |
| rnclab_filesystem | generic_api_key | ACCESS_KEY | 10 |
| levain | twilio_api_key_sid | API_KEY | 1 |
| levain | mailgun_api_key | OTHER | 1 |
| levain | xai_api_key | OTHER | 1 |
| levain | fireworks_api_key | OTHER | 1 |
| levain | elevenlabs_api_key | OTHER | 1 |
| levain | doppler_token | OTHER | 1 |
| levain | databricks_pat | OTHER | 1 |
| levain | grafana_service_account_token | OTHER | 1 |
| levain | planetscale_token | OTHER | 1 |
| levain | supabase_access_token | OTHER | 1 |

Examples: `LEV-S15-K01`, `LEV-S17-K01`, `LEV-S27-K02`, `LEV-S27-K04`, `LEV-S28-K03`, `LEV-S29-K01`, `LEV-S29-K02`, `LEV-S29-K03`, `LEV-S29-K04`, `LEV-S29-K05`, `LEV-S29-K06`, `LEV-S30-K01`.

### `SOURCE_UNSUPPORTED` - 26 targets

Layer: `SOURCE_ACQUISITION`. Representative evidence: scanner produced no credited finding in any archive_member unit across the same lane/run.

| Lane | Subtype | Identifier family | Count |
| --- | --- | --- | --- |
| rnclab_filesystem | database_password | DATABASE_PASSWORD | 5 |
| rnclab_filesystem | tls_private_key_pkcs8 | OTHER | 5 |
| rnclab_filesystem | generic_api_key | API_KEY | 4 |
| rnclab_filesystem | database_password | PASSWORD | 2 |
| rnclab_filesystem | generic_api_key | OTHER | 2 |
| rnclab_filesystem | application_hmac_key | OTHER | 2 |
| rnclab_filesystem | admin_password | OTHER | 2 |
| rnclab_filesystem | database_password | OTHER | 2 |
| rnclab_filesystem | ed25519_private_key_pkcs8 | OTHER | 1 |
| rnclab_filesystem | admin_password | PASSWORD | 1 |

Examples: `RNC-SL-POS-000029`, `RNC-SL-POS-000030`, `RNC-SL-POS-000031`, `RNC-SL-POS-000032`, `RNC-SL-POS-000033`, `RNC-SL-POS-000034`, `RNC-SL-POS-000035`, `RNC-SL-POS-000036`, `RNC-SL-POS-000037`, `RNC-SL-POS-000038`, `RNC-SL-POS-000126`, `RNC-SL-POS-000127`.

## Probable and unresolved mechanisms

### `CONTEXT_INSUFFICIENT` - 22 targets

Layer: `CONTEXT_MODEL`. Dominant confidence: `PROBABLE`.

Evidence: provider rule ['aws-secret-access-key'] exists, but no credited finding establishes whether the token shape, provider field, or value validator caused the miss

Examples: `leaky-repo:.bash_profile:12:risk`, `leaky-repo:.bashrc:109:risk`, `leaky-repo:.git-credentials:1:risk`, `leaky-repo:.npmrc:9:risk`, `leaky-repo:cloud/.credentials:4:risk`, `leaky-repo:cloud/.credentials:7:risk`, `leaky-repo:web/ruby/config/master.key:1:risk`, `LH-0002`, `LH-0017`, `LH-0037`, `LH-0080`, `LH-0082`.

### `FORMAT_UNSUPPORTED` - 85 targets

Layer: `REPRESENTATION_DECODER`. Dominant confidence: `PROBABLE`.

Evidence: other private keys were credited, but this representation or subtype is outside the accepted PEM container form

Examples: `LEV-S05-K01`, `LEV-S20-K01`, `LEV-S21-K01`, `LEV-S43-K01`, `leaky-repo:.esmtprc:4:risk`, `leaky-repo:.netrc:1:risk`, `leaky-repo:.netrc:2:risk`, `leaky-repo:.npmrc:7:risk`, `leaky-repo:db/.pgpass:2:risk`, `leaky-repo:db/dump.sql:32:risk`, `leaky-repo:db/dump.sql:33:risk`, `leaky-repo:db/dump.sql:34:risk`.

### `IDENTIFIER_MISMATCH` - 13 targets

Layer: `IDENTIFIER_LEXICON`. Dominant confidence: `PROBABLE`.

Evidence: no matching rule; identifier is outside the generic assignment keyword set

Examples: `LEV-S11-K02`, `LEV-S22-K01`, `LEV-S22-K02`, `LEV-S31-K03`, `LEV-S34-K01`, `LEV-S36-K01`, `LEV-S36-K02`, `LEV-S38-K01`, `LEV-S40-K02`, `LEV-S42-K02`, `LEV-S44-K01`, `leaky-repo:config:10:risk`.

### `RULE_ABSENT` - 2 targets

Layer: `RULE_COVERAGE`. Dominant confidence: `PROBABLE`.

Evidence: no same-subtype private-key target was credited; PEM rule presence must be verified against this subtype

Examples: `LEV-S06-K01`, `LEV-S07-K01`.

### `UNKNOWN` - 12 targets

Layer: `UNRESOLVED`. Dominant confidence: `UNRESOLVED`.

Evidence: a provider or generic rule family exists, but the value/context combination is not covered by retained evidence

Examples: `leaky-repo:.bash_profile:21:risk`, `LH-0007`, `RNC-SL-POS-000155`, `RNC-SL-POS-000190`, `RNC-SL-POS-000257`, `RNC-SL-POS-000274`, `RNC-SL-POS-000381`, `RNC-SL-POS-000473`, `RNC-SL-POS-000523`, `RNC-SL-POS-000712`, `RNC-SL-POS-000758`, `RNC-SL-POS-000792`.

### `VALIDATOR_REJECTION` - 2 targets

Layer: `VALUE_VALIDATOR`. Dominant confidence: `PROBABLE`.

Evidence: a standalone temporary .env containing this exact DB_PASSWORD value was not detected, while the same identifier with a different DB_PASSWORD value was credited

Examples: `RNC-SL-POS-000670`, `RNC-SL-POS-000791`.

## Reproduction evidence

Controlled cases were written only in ignored local storage. No corpus or rule file was changed.

| Case | Scanner | Exit | Findings |
| --- | --- | --- | --- |
| signing_key_671.env | cp4c | 0 | 0 |
| jwt_signing_key_203.env | cp4c | 0 | 0 |
| jwt_signing_key_108.env | cp4c | 0 | 0 |
| session_secret_107_control.env | cp4c | 10 | 1 |
| hmac_secret.env | cp4c | 0 | 0 |
| auth_key_019.php | cp4c | 0 | 0 |
| db_password_670.env | cp4c | 0 | 0 |
| db_password_001_control.env | cp4c | 10 | 1 |
| sendgrid_791.yaml | cp4c | 0 | 0 |
| sendgrid_control.yaml | cp4c | 10 | 1 |
| stripe_webhook_735.yaml | cp4c | 0 | 0 |
| v14_jwt_203.env | v14 | 0 | 0 |
| v14_jwt_108.env | v14 | 1 | 1 |
| v14_session_485.env | v14 | 0 | 0 |
| v14_session_107.env | v14 | 1 | 1 |
| v14_signing_671.env | v14 | 0 | 0 |
| v14_signing_643.env | v14 | 1 | 1 |
| v14_db_670.env | v14 | 0 | 0 |

The critical controls were: (a) CP4C did not detect `SIGNING_KEY` or `JWT_SIGNING_KEY` as a plain `.env` but did detect `SESSION_SECRET`; (b) CP4C did not detect a WordPress `AUTH_KEY` definition; (c) both CP4C and V14 missed selected DB_PASSWORD values as standalone files while crediting a different value with the same identifier and representation; (d) V14 credited one SIGNING_KEY/JWT_SIGNING_KEY/SESSION_SECRET value but not another. These establish identifier-family and value-shape effects, not Git-scope effects.

## Instrumentation still needed

For a miss with no retained candidate, a scanner-side diagnostic must expose whether the rule produced a candidate, whether the value/identifier validator rejected it, and whether source acquisition supplied the bytes. Without that trace, `UNKNOWN` remains the correct classification. Do not convert a `PROBABLE` value-validator finding into a rule change by reducing the global entropy floor.
