> **HISTORICAL CP3A REPORT.** The original 61 unique / 73 occurrence proposal is superseded by the [owner-approved oracle](../../datasets/leaky-repo.history-oracle.json): 53 unique / 65 expected source occurrences. The source-validated matcher and retained-report rescoring are now integrated; precision/F1 remain uncertified because reviewed negatives are not exhaustive. See [sign-off](../oracle-review/leaky-history-approved.md).

# CP3A report — Leaky Repo historical oracle discovery

- **Checkpoint:** CP3A
- **Branch:** `test/scan-harness`
- **Reference checkpoint:** CP3 (`67dc0b48df93abeb8b23fe4f1e2228213198f268`)
- **Dataset:** `Plazmaz/leaky-repo` at `2e951359cac53addbee56437da3ffb546e3dfe24`
- **Assignment type:** read-only investigation with proposed documentation only

> **Historical status: PROPOSED, PENDING_OWNER_REVIEW at the time of writing.**
> The owner later approved the final 181-row oracle; runtime integration is now
> implemented. This report remains historical and is not the current source of
> truth.

## Executive summary

The complete pinned history was enumerated and the credential-bearing source
paths were reviewed line by line. The proposed inventory contains **181 candidate
rows**:

| Proposed classification | Rows |
| --- | ---: |
| Positive | 74 |
| Ambiguous | 14 |
| Negative / non-secret | 93 |

The 74 positive rows collapse to **61 unique secret groups** and **73 scoring
occurrences**; one additional positive row is a rename-only lineage record. Five
repeated-placement groups account for twelve duplicate-placement rows.

The historical-only material is small: **no confirmed positive historical-only
secret**, one ambiguous historical-only FileZilla password, and three negative
historical-only rows (a public certificate, a null placeholder, and a placeholder
OAuth token). The `.docker/config` IRC password survives as the current `config`
file through a pure rename and does not create a new occurrence.

Existing scanner output was cross-checked only after the candidate inventory was
built. Provisional matching gives Gitleaks 20 verified-positive, 3 duplicate, 2
supporting-component, and 1 unverified finding; Betterleaks gives 34 verified-
positive, 3 duplicate, 2 supporting-component, 1 ambiguous, and 1 unverified
finding. These are cross-check observations, not certified recall or precision.

## Historical reconnaissance

| Fact | Value |
| --- | ---: |
| Commits inspected | 25 |
| Unique paths reachable from pinned HEAD | 65 |
| Current files | 61 |
| Current filesystem-truth paths line-reviewed | 44 |
| Historical-only / renamed paths | 4 |
| Current truth line units reviewed | 175 |
| Candidate rows produced | 181 |

The four historical-only paths are `.docker/config` (renamed to `config`), the
deleted `misc-keys/cert-example.pem`, and the two renamed benchmark documents.
Only `.docker/config` and the certificate required credential-level review; the
benchmark documents contain no credential-bearing source lines.

Binary `.mozilla/firefox/*.db` browser stores were enumerated but are not
line-scoreable source artifacts. The text `logins.json` was reviewed separately.

### Commit-level findings

| Commit | Finding |
| --- | --- |
| `903a9ca` Initial Commit | Introduces the source credential corpus. 67 positive placements, 13 ambiguous, 89 negative candidate rows. |
| `38f1204` Fixed up a few secrets | Pure `.docker/config` → `config` rename (identical blob); deletes a public CERTIFICATE PEM. No new credential. |
| `9fd86d0` Additional npmrc token format | Adds one npm registry token (positive). |
| `9f1468c` Updated secrets / risk labels | Adds FTP passphrase, VS Code SFTP password, Hub OAuth token; changes Redis password and FileZilla password. Comments added to many files do not create secret occurrences. |
| `87473ec` Added robomongo password | Adds one Robomongo `sshUserPassword` value (positive). |
| `8c99112` EOL fixes | Comment-only change to `cloud/.tugboat`; no new secret value. |
| `226fcb4`, `5cc7931`, `2e95135` and benchmark-only commits | No credential-bearing source-value change. Merge commits integrate already-counted side-branch changes; they do not create new secret identities. |

The 25-commit graph includes merge commits. An unchanged secret appearing in a
merge snapshot is not counted as a new introduction. A side-branch addition is
attributed to the commit that introduced the value, not to the merge that brought
it into `master`.

### Repeated credentials

Five groups have repeated placements (twelve duplicate-placement rows total):

| Group | Placements |
| --- | --- |
| `SG-001` AWS secret component | `.bash_profile` L12, `cloud/.credentials` L4 and L7, `cloud/.s3cfg` L2 |
| `SG-010` Docker auth blob | `.docker/.dockercfg` L4/L8, `.docker/config.json` L5/L9 |
| `SG-013` weak SFTP/FTP password | `.ftpconfig` L6, `.remote-sync.json` L17, `deployment-config.json` L5, `sftp-config.json` L15 |
| `SG-020` repeated weak password | `.netrc` L1/L2, `web/var/www/public_html/config.php` L7 (initial) |
| `SG-041` encoded FileZilla password | `filezilla/recentservers.xml` L10/L24 (initial) |

The `.docker/config` IRC password group (`SG-011`) has an additional rename-only
row at `38f1204`; it is not counted as an occurrence.

### AWS label inversion

`cloud/.s3cfg` labels its two lines `secret_key` and `access_key`, but source-value
comparison shows the labels are inverted relative to the AWS pair used in
`.bash_profile` and `cloud/.credentials`. The CSV classifies the line carrying the
AWS access-key component as **negative/supporting** and the line carrying the
secret component as **positive**. This is a source-label finding, not a scanner
finding.

## Deleted, modified, and historical-only material

- **Modified positive credentials:** Hub OAuth token (placeholder → 40-character
  token) and Redis password (null → non-empty weak password), both in `9f1468c`.
- **Modified ambiguous credential:** FileZilla password (`9f1468c`); the new value
  is explicitly example-style and the old value cannot be adjudicated.
- **Deleted:** `misc-keys/cert-example.pem`, a `CERTIFICATE` block (public
  material), proposed negative. No confirmed private key or password was deleted.
- **Renamed:** `.docker/config` → `config` (identical blob); IRC password persists.
- **Historical-only positive:** **0 confirmed**.
- **Historical-only ambiguous:** old FileZilla password.
- **Historical-only negative:** public certificate, pre-change `REDIS_PASSWORD=null`,
  pre-change Hub OAuth placeholder.

## Candidate false positives and ambiguity

The 93 negative rows are mostly username, email, host, port, path, timestamp,
schema, public-key, certificate, or structural private-key metadata units that the
existing filesystem count treated as informative. They are not proposed as
historical secrets.

The 14 ambiguous rows are:

- four encrypted Firefox password records (`encryptedPassword`);
- old and new FileZilla passwords;
- two unlabeled high-entropy strings;
- literal default password in `.esmtprc`;
- literal default password in `db/.pgpass`;
- literal default password in `db/dbeaver-data-sources.xml`;
- test-style MongoDB connection string;
- default WordPress database password;
- placeholder-style Salesforce password.

These are excluded from proposed positive denominators until the owner decides.

## Existing scanner observations reconciled

Cross-check method: match scanner finding value hash to proposed secret identity
first, then commit/path/line. The oracle was not changed to agree with scanner
output.

| Scanner | Findings | Verified TP | Duplicate | Supporting component | Ambiguous | Unverified | Provisional unique recall | Provisional occurrence recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Gitleaks | 26 | 20 | 3 | 2 | 0 | 1 | 15/61 (24.59%) | 21/73 (28.77%) |
| Betterleaks | 41 | 34 | 3 | 2 | 1 | 1 | 27/61 (44.26%) | 35/73 (47.95%) |

- **Both scanners:** 26 finding signatures.
- **Gitleaks-only:** 0.
- **Betterleaks-only:** 15, mostly weak-password fields that Gitleaks did not
  report.
- **Supporting components:** both scanners report the AWS access-key component in
  `.s3cfg` as a generic secret. It is a credential-pair identifier, not the secret
  component, and is neither certified TP nor FP.
- **Unverified:** both scanners report a private-key finding in
  `misc-keys/cert-key.pem` whose value hash differs from the file-level extraction;
  path/type evidence is strong, but value identity remains unadjudicated.
- **Ambiguous:** Betterleaks' MongoDB connection-string finding maps to the proposed
  ambiguous `test`/`test` credential.

These percentages are **not certified**. The candidate inventory is unapproved,
14 candidates remain ambiguous, supporting components are unresolved, and two
private-key matches are unverified.

## Readiness recommendation

| Metric | Status | Exact unresolved issue |
| --- | --- | --- |
| Unique-secret historical recall | **PARTIAL** | 61 proposed groups require owner approval; 14 ambiguous candidates excluded; private-key value matching unverified |
| Historical occurrence recall | **PARTIAL** | 73 placement occurrences require approval; multiple placements, rename, merge-snapshot deduplication, and commit attribution need confirmation |
| Verified false-positive counts | **BLOCKED** | No owner-approved negative oracle; supporting access-key components and unverified private keys unresolved |
| Precision | **BLOCKED** | Positive inventory is unapproved; material findings remain ambiguous/unverified; supporting components are neither TP nor FP |
| F1 | **BLOCKED** | Depends on certified precision and recall |
| Per-commit detection reporting | **PARTIAL** | Both scanners carry commit identity, but report persistence snapshots; occurrence attribution requires deduplication and merge handling |

No metric is ready for certification from this proposal. The existing 175-item
filesystem denominator remains inapplicable to history. Leaky Repo history stays
`COMPLETED_UNSCORED` / truth `BLOCKED`.

## Owner decisions required

1. Approve, reject, revise, or request investigation for the 74 positive, 14
   ambiguous, and 93 negative candidate rows.
2. Decide whether the old FileZilla password is historical-only positive or
   remains ambiguous.
3. Decide whether password hashes count as positive credential material.
4. Decide the treatment of encrypted Firefox password records.
5. Decide whether literal default passwords and unlabeled high-entropy strings
   enter positive denominators.
6. Confirm the occurrence policy for multiple placements, renames, merge
   snapshots, and modified values.
7. Decide whether AWS access-key components are supporting findings or FPs.
8. Decide whether private-key path/type matches are sufficient despite hash
   mismatch.
9. Only then ratify denominators and precision/F1 eligibility.

## Deliverables

- [`leaky-history-candidates.csv`](../oracle-review/leaky-history-candidates.csv) —
  complete 181-row proposed inventory with stable IDs, commit/blob identity,
  source line, safe identity, classification, rationale, evidence, diff,
  confidence, disposition, and scoring role.
- [`leaky-history-review.md`](../oracle-review/leaky-history-review.md) — readable
  register of every positive/ambiguous candidate, grouped by commit and file.
- [`leaky-history-methodology.md`](../oracle-review/leaky-history-methodology.md) —
  classification, unique/occurrence models, formulas, precision/F1 eligibility,
  scanner cross-check, and readiness.
- [`leaky-history-scanner-crosscheck.csv`](../oracle-review/leaky-history-scanner-crosscheck.csv)
  — finding-level reconciliation for both scanners, with no raw values.

All entries are initially `PENDING_OWNER_REVIEW`. No raw secret value appears in
the committed review files.

## Limitations

- No historical ground truth existed; this is an independently reviewed proposal,
  not an authoritative oracle.
- Path-, line-, and value-based evidence cannot prove that a planted fake value was
  ever live; classifications describe credential role and source context, not
  real-world validity.
- Binary browser databases were not decoded into line-level candidates.
- Scanner duplicate/occurrence matching depends on preprocessing snapshots; the
  harness does not yet implement historical oracle scoring.
- Merge commits and multiple placements need an owner-approved occurrence rule.
- No owner dispositions or authoritative denominators exist yet.

## Final status

**PROPOSED. PENDING_OWNER_REVIEW. STOP.** No authoritative truth manifest,
scoring baseline, adapter, engine, or pinned dataset was changed. CP4 was not
started.
