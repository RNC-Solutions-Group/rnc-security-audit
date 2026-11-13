> **ARCHIVED TRIAGE — SUPERSEDED.** Final owner decisions for all 181 items are in the [approved history oracle](../../datasets/leaky-repo.history-oracle.json), [approval document](leaky-history-approved.md) and updated candidate CSV. The PENDING table below preserves the earlier proposal only.

# CP3A owner-review triage — reduced decision register

**Status:** PROPOSED ONLY — PENDING OWNER REVIEW. This file is a review aid, **not** an approved oracle or a modification to any candidate disposition, score, or benchmark truth.

**Inventory reviewed:** [181 source candidates](leaky-history-candidates.csv) and [scanner cross-check](leaky-history-scanner-crosscheck.csv), based on CP3A commit `3f9a65a71bc9aa5b91e95573c7d2ee76cb42d175`. Source examples were separately checked in the pinned Leaky Repo history. Source-value strings are deliberately not reproduced here.

## Summary: 181 candidate rows → 14 review decisions

Two routine batches account for **137 records** (B01+B02). The remaining **44 records** are distributed across **12 focused decisions**. A group recommendation is not a claim that all underlying values have been manually checked; owner approval is required before machine-authoritative status changes.

| ID | Rows | Recommended owner action | Owner disposition |
| --- | ---: | --- | --- |
| **B01** | 92 | Batch-accept as negative/metadata, after source spot checks; includes public keys, usernames, schema and placeholders. The Tugboat `client_key` looks like a client identifier paired with a separate `api_key`. | PENDING |
| **B02** | 45 | Batch-accept as positives: credential-bearing values in explicitly named fields, medium/high confidence. Sample-check different formats and duplicated placements. | PENDING |
| **B03** | 10 | Accept as positive **by credential role**, despite low entropy or weak strings; strength is not evidence that an assigned credential is non-secret. | PENDING |
| **B04** | 13 | Approve as **password-hash / credential-artifact** positives in a separate reported class; decide expressly whether they count in primary plaintext/token recall. | PENDING |
| **B05** | 2 | Approve as private-key artifacts (SSH PEM + PPK with private material). Example labels do not make syntactically valid private-key material harmless for a synthetic benchmark. | PENDING |
| **B06** | 1 | Approve source as a private-key positive, but **do not credit scanner matching** until full PEM block vs scanner matched-span normalization is adjudicated. | PENDING |
| **B07** | 1 | Keep positive but **relabel to symmetric application encryption key**, not asymmetric private key (Rails `master.key` is a 32-character key). | PENDING |
| **B08** | 2 | Approve secret component positive; classify the standalone AWS access-key ID as supporting identifier. Define explicitly whether an identifier-only alert is an FP for strict credential precision. | PENDING |
| **B09** | 1 | Accept rename-only metadata; no new unique identity or introduction occurrence. Retain for historical lineage. | PENDING |
| **B10** | 4 | Retain encrypted-password records as a distinct credential-artifact class; do not conflate with plaintext secret recall. Decide separate scoring eligibility. | PENDING |
| **B11** | 5 | Recommend positive for all five **assigned authentication fields**, even if value reads `password`, `root` or `test`; synthetic/default credentials are still credential assignments. Confirm exceptions. | PENDING |
| **B12** | 2 | Recommend negative for both: old FileZilla record is anonymous/anonymous authentication, new one an explicitly example-style password. | PENDING |
| **B13** | 1 | Recommend negative/placeholder: Salesforce sample login uses an explicit example-style value. | PENDING |
| **B14** | 2 | Recommend negative for **verified credential** scoring because high entropy alone does not establish credential function; may remain a separate suspicion/entropy diagnostic. | PENDING |

**Totals:** 92 + 45 + 10 + 13 + 2 + 1 + 1 + 2 + 1 + 4 + 5 + 2 + 1 + 2 = **181**, with no overlapping or unassigned source candidates.

## Suggested owner-review workflow

For each batch, mark **APPROVE**, **REVISE**, or **NEEDS_INVESTIGATION**. B01/B02 can be reviewed using a representative sample; all exceptions should be inspected individually or approved by a clearly stated category policy. Do not update the authoritative manifests until review is complete.

### B01 — Routine non-secret / contextual metadata (92)

**Recommendation:** Batch-accept as negative/metadata, after source spot checks; includes public keys, usernames, schema and placeholders. The Tugboat `client_key` looks like a client identifier paired with a separate `api_key`.

**Candidate IDs:** LH-0001, LH-0003, LH-0004, LH-0005, LH-0011, LH-0012, LH-0015, LH-0016, LH-0018, LH-0020, LH-0022, LH-0023, LH-0024, LH-0026
LH-0028, LH-0030, LH-0031, LH-0033, LH-0034, LH-0036, LH-0038, LH-0040, LH-0041, LH-0043, LH-0044, LH-0045, LH-0046, LH-0047
LH-0048, LH-0050, LH-0051, LH-0052, LH-0053, LH-0054, LH-0055, LH-0057, LH-0058, LH-0059, LH-0060, LH-0061, LH-0062, LH-0064
LH-0065, LH-0066, LH-0067, LH-0070, LH-0072, LH-0073, LH-0076, LH-0077, LH-0078, LH-0079, LH-0081, LH-0085, LH-0086, LH-0088
LH-0089, LH-0104, LH-0106, LH-0107, LH-0109, LH-0110, LH-0111, LH-0113, LH-0116, LH-0117, LH-0119, LH-0120, LH-0124, LH-0125
LH-0128, LH-0129, LH-0131, LH-0132, LH-0134, LH-0144, LH-0145, LH-0146, LH-0148, LH-0149, LH-0150, LH-0151, LH-0154, LH-0155
LH-0156, LH-0158, LH-0159, LH-0161, LH-0173, LH-0175, LH-0176, LH-0178

**Suggested status:** `NEGATIVE` (proposal only). **Owner:** `PENDING_OWNER_REVIEW`.

### B02 — Credential values with medium/high source confidence (45)

**Recommendation:** Batch-accept as positives: credential-bearing values in explicitly named fields, medium/high confidence. Sample-check different formats and duplicated placements.

**Candidate IDs:** LH-0002, LH-0006, LH-0007, LH-0008, LH-0009, LH-0010, LH-0013, LH-0014, LH-0017, LH-0019, LH-0021, LH-0025, LH-0027, LH-0029
LH-0071, LH-0080, LH-0082, LH-0087, LH-0090, LH-0105, LH-0108, LH-0118, LH-0121, LH-0135, LH-0136, LH-0137, LH-0140, LH-0141
LH-0142, LH-0143, LH-0147, LH-0152, LH-0157, LH-0162, LH-0163, LH-0164, LH-0165, LH-0166, LH-0167, LH-0168, LH-0169, LH-0171
LH-0179, LH-0180, LH-0181

**Suggested status:** `POSITIVE` (proposal only). **Owner:** `PENDING_OWNER_REVIEW`.

### B03 — Weak-looking but credential-bearing assigned values (10)

**Recommendation:** Accept as positive **by credential role**, despite low entropy or weak strings; strength is not evidence that an assigned credential is non-secret.

**Candidate IDs:** LH-0035, LH-0037, LH-0039, LH-0068, LH-0069, LH-0074, LH-0112, LH-0133, LH-0172, LH-0174

**Suggested status:** `POSITIVE` (proposal only). **Owner:** `PENDING_OWNER_REVIEW`.

### B04 — Password hashes (distinct benchmark class) (13)

**Recommendation:** Approve as **password-hash / credential-artifact** positives in a separate reported class; decide expressly whether they count in primary plaintext/token recall.

**Candidate IDs:** LH-0093, LH-0094, LH-0095, LH-0096, LH-0097, LH-0098, LH-0099, LH-0100, LH-0101, LH-0102, LH-0114, LH-0130, LH-0153

**Suggested status:** `SEPARATE_ARTIFACT_POSITIVE` (proposal only). **Owner:** `PENDING_OWNER_REVIEW`.

### B05 — Complete SSH/PPK private-key material (2)

**Recommendation:** Approve as private-key artifacts (SSH PEM + PPK with private material). Example labels do not make syntactically valid private-key material harmless for a synthetic benchmark.

**Candidate IDs:** LH-0075, LH-0127

**Suggested status:** `POSITIVE` (proposal only). **Owner:** `PENDING_OWNER_REVIEW`.

### B06 — PEM private key with scanner-match normalization issue (1)

**Recommendation:** Approve source as a private-key positive, but **do not credit scanner matching** until full PEM block vs scanner matched-span normalization is adjudicated.

**Candidate IDs:** LH-0126

**Suggested status:** `POSITIVE_MATCH_UNVERIFIED` (proposal only). **Owner:** `PENDING_OWNER_REVIEW`.

**Source:** [original PEM private-key block](https://github.com/Plazmaz/leaky-repo/blob/903a9caba59d2514ca1aab7129fece6be3b9b849/misc-keys/cert-key.pem#L1-L28). The same candidate is value-unverified for both scanners. Compare scanner *matched text* against canonical block content; line 1 matching a header may represent a full-block scanner finding, not an exact value mismatch.

### B07 — Rails master.key mislabeled as asymmetric private key (1)

**Recommendation:** Keep positive but **relabel to symmetric application encryption key**, not asymmetric private key (Rails `master.key` is a 32-character key).

**Candidate IDs:** LH-0139

**Suggested status:** `POSITIVE_RETYPE` (proposal only). **Owner:** `PENDING_OWNER_REVIEW`.

**Source:** [Rails master.key](https://github.com/Plazmaz/leaky-repo/blob/903a9caba59d2514ca1aab7129fece6be3b9b849/web/ruby/config/master.key#L1); a 32-hex-character application encryption key, not a PEM private key. This is a clear type-label correction.

### B08 — AWS access-key identifier and secret-key pair (2)

**Recommendation:** Approve secret component positive; classify the standalone AWS access-key ID as supporting identifier. Define explicitly whether an identifier-only alert is an FP for strict credential precision.

**Candidate IDs:** LH-0083, LH-0084

**Suggested status:** `PAIR_AND_IDENTIFIER_POLICY` (proposal only). **Owner:** `PENDING_OWNER_REVIEW`.

**Source:** [s3cfg original two-line pair](https://github.com/Plazmaz/leaky-repo/blob/903a9caba59d2514ca1aab7129fece6be3b9b849/cloud/.s3cfg#L1-L2). The field *labels are inverted relative to the values*. Never simply score both alerts as separate verified secrets.

### B09 — Identical-blob rename lineage; no new leak (1)

**Recommendation:** Accept rename-only metadata; no new unique identity or introduction occurrence. Retain for historical lineage.

**Candidate IDs:** LH-0170

**Suggested status:** `LINEAGE_ONLY` (proposal only). **Owner:** `PENDING_OWNER_REVIEW`.

### B10 — Encrypted Firefox password records (4)

**Recommendation:** Retain encrypted-password records as a distinct credential-artifact class; do not conflate with plaintext secret recall. Decide separate scoring eligibility.

**Candidate IDs:** LH-0042, LH-0049, LH-0056, LH-0063

**Suggested status:** `SEPARATE_ENCRYPTED_ARTIFACT` (proposal only). **Owner:** `PENDING_OWNER_REVIEW`.

**Source:** [Firefox encryptedPassword records](https://github.com/Plazmaz/leaky-repo/blob/903a9caba59d2514ca1aab7129fece6be3b9b849/.mozilla/firefox/logins.json#L12). Four encrypted credential values are present; no browser decryption is required to classify them as encrypted artifacts. Binary browser databases remain outside the approved line-level scope until explicitly reviewed.

### B11 — Five actual password fields with default/test values (5)

**Recommendation:** Recommend positive for all five **assigned authentication fields**, even if value reads `password`, `root` or `test`; synthetic/default credentials are still credential assignments. Confirm exceptions.

**Candidate IDs:** LH-0032, LH-0091, LH-0092, LH-0103, LH-0160

**Suggested status:** `POSITIVE_PROPOSED` (proposal only). **Owner:** `PENDING_OWNER_REVIEW`.

**Representative sources:** [esmtprc password field](https://github.com/Plazmaz/leaky-repo/blob/903a9caba59d2514ca1aab7129fece6be3b9b849/.esmtprc#L4), [pgpass assignment](https://github.com/Plazmaz/leaky-repo/blob/903a9caba59d2514ca1aab7129fece6be3b9b849/db/.pgpass#L2), [MongoDB URI within production config](https://github.com/Plazmaz/leaky-repo/blob/903a9caba59d2514ca1aab7129fece6be3b9b849/db/mongoid.yml#L4), [WordPress DB_PASSWORD](https://github.com/Plazmaz/leaky-repo/blob/903a9caba59d2514ca1aab7129fece6be3b9b849/web/var/www/public_html/wp-config.php#L17).

### B12 — FileZilla anonymous / explicit example credentials (2)

**Recommendation:** Recommend negative for both: old FileZilla record is anonymous/anonymous authentication, new one an explicitly example-style password.

**Candidate IDs:** LH-0115, LH-0177

**Suggested status:** `NEGATIVE_PROPOSED` (proposal only). **Owner:** `PENDING_OWNER_REVIEW`.

**Source evidence:** [historical FileZilla anonymous login](https://github.com/Plazmaz/leaky-repo/blob/903a9caba59d2514ca1aab7129fece6be3b9b849/filezilla/filezilla.xml#L9-L12); [revised explicit example value](https://github.com/Plazmaz/leaky-repo/blob/2e951359cac53addbee56437da3ffb546e3dfe24/filezilla/filezilla.xml#L11-L13). Neither requires guessing whether the string was a real production credential.

### B13 — Salesforce explicit example-style password (1)

**Recommendation:** Recommend negative/placeholder: Salesforce sample login uses an explicit example-style value.

**Candidate IDs:** LH-0138

**Suggested status:** `NEGATIVE_PROPOSED` (proposal only). **Owner:** `PENDING_OWNER_REVIEW`.

**Source evidence:** [Salesforce sample login](https://github.com/Plazmaz/leaky-repo/blob/903a9caba59d2514ca1aab7129fece6be3b9b849/web/js/salesforce.js#L6).

### B14 — Two unlabeled high-entropy samples (2)

**Recommendation:** Recommend negative for **verified credential** scoring because high entropy alone does not establish credential function; may remain a separate suspicion/entropy diagnostic.

**Candidate IDs:** LH-0122, LH-0123

**Suggested status:** `NEGATIVE_PROPOSED` (proposal only). **Owner:** `PENDING_OWNER_REVIEW`.

**Source evidence:** [HES1/HES2 test strings](https://github.com/Plazmaz/leaky-repo/blob/903a9caba59d2514ca1aab7129fece6be3b9b849/high-entropy-misc.txt#L1-L2). Decide separately if suspicious-but-unverified alerts are useful diagnostic output; do not silently turn them into proven secret TPs.

## Scoring and scope gates — do not skip

1. **Private-key mismatch:** CP3A's 15/61 (Gitleaks) and 27/61 (Betterleaks) provisional *unique* recall counts include one path/type-only `LH-0126` finding. Value-verified matches are **14 groups / 20 occurrence candidates** for Gitleaks and **26 groups / 34 occurrence candidates** for Betterleaks. Do not publish either as certified recall before owner adjudication.
2. **Precision and F1:** Classify each actual scanner finding against the owner-approved inventory, not merely whether it exceeds a per-file count. Do not exclude ambiguous/supporting findings from the precision denominator without an explicit, documented policy. Duplicate policy must be consistent.
3. **Positive inventory completeness:** Verify every reachable source path is inside the approved scoring scope or explicitly excluded; CP3A enumerated 65 unique paths, focused detailed truth review on 44 existing truth paths plus credential-relevant history, and excluded binary Firefox databases from line-level scoring.
4. **Occurrences:** Count introductions and genuinely changed values, not persistence snapshots or pure renames; keep unique identities distinct from per-placement occurrences. No filesystem 175-item denominator for Git history.
5. **Separation of classes:** Report credential/token/private-key recall, hashes, encrypted storage, and suspicious-unlabeled data distinctly. Primary DEFAULT scores must never blend unverified candidates with verified positives.
6. **No current authority:** All 181 existing candidate rows remain `PENDING_OWNER_REVIEW`. This file contains *recommendations only*. No scanner or scoring code was modified.

## Owner sign-off register

- [ ] **B01** Accept/revise 92 routine negatives
- [ ] **B02** Accept/revise 45 medium/high credential positives
- [ ] **B03** Decide weak-but-assigned credentials (10)
- [ ] **B04** Decide password-hash policy (13)
- [ ] **B05** Verify two SSH/PPK private keys
- [ ] **B06** Verify PEM block identity / scanner matching (1)
- [ ] **B07** Retype Rails master.key as symmetric key (1)
- [ ] **B08** Decide AWS identifier vs secret component scoring (2)
- [ ] **B09** Accept identical-blob rename lineage (1)
- [ ] **B10** Decide encrypted Firefox credential policy (4)
- [ ] **B11** Decide five default/test password assignments
- [ ] **B12** Accept anonymous/example FileZilla as negative (2)
- [ ] **B13** Accept Salesforce placeholder as negative (1)
- [ ] **B14** Decide untyped high-entropy strings (2)
- [ ] Verify the completeness of included and excluded historical paths
- [ ] Approve the occurrence policy and resolve `LH-0126` before certifying precision/recall/F1

**Next action after owner approval:** Apply the 14 batch dispositions (with any individual overrides) to the existing 181-row CSV, independently verify updated unique/occurrence denominators, and only then create a versioned authoritative historical oracle. Keep all existing CP3A evidence unchanged.
