# RNC-Mod V16 - root causes and reproduction evidence

This file separates confirmed mechanisms from probable and unresolved hypotheses. `CONFIRMED` means the retained evidence establishes the mechanism without scanner-side guessing; `PROBABLE` means a controlled or cross-scanner observation strongly supports it but the scanner's internal candidate stage was not inspected; `UNRESOLVED` means the evidence cannot distinguish the listed layers.

## Classification summary

| Root cause | Layer | Misses | Confirmed | Probable | Unresolved |
| --- | --- | --- | --- | --- | --- |
| IDENTIFIER_MISMATCH | IDENTIFIER_LEXICON | 167 | 0 | 167 | 0 |
| FORMAT_UNSUPPORTED | REPRESENTATION_DECODER | 112 | 0 | 112 | 0 |
| INFORMATIVE_REFERENCE | ORACLE_CLASSIFICATION | 86 | 86 | 0 | 0 |
| CONTEXT_INSUFFICIENT | CONTEXT_MODEL | 72 | 0 | 72 | 0 |
| RULE_ABSENT | RULE_COVERAGE | 34 | 0 | 34 | 0 |
| UNKNOWN | UNRESOLVED | 31 | 0 | 0 | 31 |
| SOURCE_INSPECTION_UNVERIFIED | SOURCE_ACQUISITION | 26 | 0 | 0 | 26 |
| VALIDATOR_REJECTION | VALUE_VALIDATOR | 4 | 0 | 4 | 0 |
| CAPTURE_MISMATCH | VALUE_CAPTURE | 1 | 0 | 1 | 0 |

## Confirmed mechanisms

### `INFORMATIVE_REFERENCE` - 86 targets

Layer: `ORACLE_CLASSIFICATION`. Representative evidence: oracle classifies this occurrence as informative, not a risk-bearing secret.

| Lane | Subtype | Identifier family | Count |
| --- | --- | --- | --- |
| leaky_filesystem | unspecified_credential | OTHER | 58 |
| leaky_filesystem | ftp_password | OTHER | 9 |
| leaky_filesystem | application_password | PASSWORD | 4 |
| leaky_filesystem | github_personal_access_token | OTHER | 4 |
| leaky_filesystem | aws_access_key_id | ACCESS_KEY | 3 |
| leaky_filesystem | smtp_password | OTHER | 3 |
| leaky_filesystem | application_password | OTHER | 1 |
| leaky_filesystem | unspecified_credential | TOKEN | 1 |
| leaky_filesystem | aws_secret_access_key | OTHER | 1 |
| leaky_filesystem | database_password | OTHER | 1 |
| leaky_filesystem | pem_private_key | OTHER | 1 |

Examples: `leaky-repo:.bash_profile:11:informative`, `leaky-repo:.bash_profile:13:informative`, `leaky-repo:.bash_profile:18:informative`, `leaky-repo:.bash_profile:19:informative`, `leaky-repo:.bash_profile:25:informative`, `leaky-repo:.bashrc:104:informative`, `leaky-repo:.bashrc:107:informative`, `leaky-repo:.bashrc:108:informative`, `leaky-repo:.docker/.dockercfg:3:informative`, `leaky-repo:.docker/.dockercfg:7:informative`, `leaky-repo:.docker/config.json:4:informative`, `leaky-repo:.docker/config.json:8:informative`.

## Probable and unresolved mechanisms

### `CAPTURE_MISMATCH` - 1 targets

Layer: `VALUE_CAPTURE`. Dominant confidence: `PROBABLE`.

Evidence: source inspection is not independently verified by the retained report; the detection hypothesis is evidence-limited. scanner finding exists at the expected source location but value evidence did not match (EVIDENCE_CONFLICT)

Examples: `RNC-SL-POS-000652`.

### `CONTEXT_INSUFFICIENT` - 72 targets

Layer: `CONTEXT_MODEL`. Dominant confidence: `PROBABLE`.

Evidence: source inspection is not independently verified by the retained report; the detection hypothesis is evidence-limited. identifier is recognized, but the value sits in a wrapped, encoded, or structured representation; same-representation credits elsewhere: 16

Examples: `leaky-repo:.bash_profile:20:risk`, `leaky-repo:.bashrc:105:risk`, `leaky-repo:.remote-sync.json:17:risk`, `leaky-repo:.vscode/sftp.json:6:risk`, `leaky-repo:db/robomongo.json:14:risk`, `leaky-repo:db/robomongo.json:27:risk`, `leaky-repo:deployment-config.json:5:risk`, `leaky-repo:sftp-config.json:15:risk`, `leaky-repo:ventrilo_srv.ini:7:risk`, `leaky-repo:ventrilo_srv.ini:8:risk`, `leaky-repo:web/ruby/config/master.key:1:risk`, `leaky-repo:web/var/www/.env:23:risk`.

### `FORMAT_UNSUPPORTED` - 112 targets

Layer: `REPRESENTATION_DECODER`. Dominant confidence: `PROBABLE`.

Evidence: source inspection is not independently verified by the retained report; the detection hypothesis is evidence-limited. no assignment identifier exists; the value is positional, colon-delimited, encoded, or in a command/log argument

Examples: `LEV-S43-K01`, `leaky-repo:.esmtprc:4:risk`, `leaky-repo:.git-credentials:1:risk`, `leaky-repo:.mozilla/firefox/logins.json:11:risk`, `leaky-repo:.mozilla/firefox/logins.json:12:risk`, `leaky-repo:.mozilla/firefox/logins.json:27:risk`, `leaky-repo:.mozilla/firefox/logins.json:28:risk`, `leaky-repo:.mozilla/firefox/logins.json:43:risk`, `leaky-repo:.mozilla/firefox/logins.json:44:risk`, `leaky-repo:.mozilla/firefox/logins.json:59:risk`, `leaky-repo:.mozilla/firefox/logins.json:60:risk`, `leaky-repo:.netrc:1:risk`.

### `IDENTIFIER_MISMATCH` - 167 targets

Layer: `IDENTIFIER_LEXICON`. Dominant confidence: `PROBABLE`.

Evidence: source inspection is not independently verified by the retained report; the detection hypothesis is evidence-limited. no matching rule; identifier is outside the generic assignment keyword set

Examples: `LEV-S01-K01`, `LEV-S04-K01`, `LEV-S09-K01`, `LEV-S10-K01`, `LEV-S11-K01`, `LEV-S11-K02`, `LEV-S22-K01`, `LEV-S22-K02`, `LEV-S24-K01`, `LEV-S26-K01`, `LEV-S29-K07`, `LEV-S31-K03`.

### `RULE_ABSENT` - 34 targets

Layer: `RULE_COVERAGE`. Dominant confidence: `PROBABLE`.

Evidence: source inspection is not independently verified by the retained report; the detection hypothesis is evidence-limited. no same-subtype private-key target was credited; PEM rule presence must be verified against this subtype

Examples: `LEV-S06-K01`, `LEV-S07-K01`, `LEV-S08-K01`, `LEV-S27-K02`, `LEV-S29-K01`, `LEV-S29-K05`, `LEV-S29-K06`, `LEV-S30-K02`, `LEV-S30-K04`, `LEV-S31-K01`, `LEV-S31-K04`, `LEV-S40-K02`.

### `SOURCE_INSPECTION_UNVERIFIED` - 26 targets

Layer: `SOURCE_ACQUISITION`. Dominant confidence: `UNRESOLVED`.

Evidence: the expected positive is inside a archive_member; the retained report does not prove the specific member/record was reached, and no validated capability contract declares the container unsupported

Examples: `RNC-SL-POS-000029`, `RNC-SL-POS-000030`, `RNC-SL-POS-000031`, `RNC-SL-POS-000032`, `RNC-SL-POS-000033`, `RNC-SL-POS-000034`, `RNC-SL-POS-000035`, `RNC-SL-POS-000036`, `RNC-SL-POS-000037`, `RNC-SL-POS-000038`, `RNC-SL-POS-000126`, `RNC-SL-POS-000127`.

### `UNKNOWN` - 31 targets

Layer: `UNRESOLVED`. Dominant confidence: `UNRESOLVED`.

Evidence: source inspection is not independently verified by the retained report; the detection hypothesis is evidence-limited. a provider or generic rule family exists, but the value/context combination is not covered by retained evidence

Examples: `leaky-repo:.bash_profile:21:risk`, `leaky-repo:web/django/settings.py:24:risk`, `leaky-repo:web/var/www/.env:14:risk`, `LH-0007`, `LH-0137`, `LH-0147`, `RNC-SL-POS-000039`, `RNC-SL-POS-000043`, `RNC-SL-POS-000149`, `RNC-SL-POS-000165`, `RNC-SL-POS-000169`, `RNC-SL-POS-000268`.

### `VALIDATOR_REJECTION` - 4 targets

Layer: `VALUE_VALIDATOR`. Dominant confidence: `PROBABLE`.

Evidence: source inspection is not independently verified by the retained report; the detection hypothesis is evidence-limited. a standalone temporary .env with this exact JWT_SIGNING_KEY value was not detected, while a different JWT_SIGNING_KEY value was credited by generic-api-key

Examples: `RNC-SL-POS-000203`, `RNC-SL-POS-000485`, `RNC-SL-POS-000670`, `RNC-SL-POS-000671`.

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
