> **ARCHIVED CP3A PROPOSAL — SUPERSEDED.** Final approved history truth: [owner approval](leaky-history-approved.md) and [canonical oracle](../../datasets/leaky-repo.history-oracle.json). Owner counts: **65 positive occurrences / 53 unique credentials, 86 negatives, 30 informative, 0 lineage-only (LH-0170 informative)**. The original PENDING statuses and 61/73 candidate denominators below are historical, not current.

# Leaky Repo historical oracle — proposed methodology

- **Status:** proposal for owner verification, not authoritative benchmark truth
- **Dataset:** `Plazmaz/leaky-repo` at `2e951359cac53addbee56437da3ffb546e3dfe24`
- **Scope:** all 25 commits reachable from the pinned revision, first-parent and
side-branch history included
- **Candidate inventory:** [`leaky-history-candidates.csv`](leaky-history-candidates.csv)
- **Readable review register:** [`leaky-history-review.md`](leaky-history-review.md)

This document proposes how to derive and score historical truth. It does not
change the scoring engine, adapters, existing truth manifests, or any benchmark
result.

## 1. Reconnaissance method

1. Verify the pinned revision and complete commit graph.
2. Enumerate every path that exists in any reachable commit.
3. Review all 44 paths represented in the existing filesystem truth manifest, plus
   the historical-only/renamed paths that can carry credentials.
4. Compare each secret-bearing file against its parent commits, using source
   content, Git blobs, rename detection, and explicit line ranges.
5. Treat initial content, later value changes, path renames, and deletions as
   separate historical events.
6. Use existing Gitleaks/Betterleaks history output only after the candidate
   inventory is built. Scanner output is not evidence of truth.

The complete source history was small enough to inspect directly: 25 commits,
65 unique paths reachable from the pinned HEAD, 61 current files. The binary
browser databases (`.mozilla/firefox/*.db`) were enumerated but are not
line-scoreable source artifacts. Benchmark/documentation paths were
reviewed for accidental credentials; no additional credential-bearing source
lines were accepted from them.

## 2. Candidate classification policy

### Positive

A line is proposed positive when it contains actual credential material in a
credential-bearing context:

- a non-empty password, passphrase, token, OAuth token, API key, secret key, or
  private-key block;
- an AWS access/secret pair, represented by its secret component with the access
  key ID as supporting context;
- a credential-bearing URL or authentication blob;
- a password hash (bcrypt, SHA-512 crypt, Apache MD5), which is sensitive
  credential material even though it is not plaintext.

Weak or default-looking passwords may be positive with **low** confidence when
the source provides no explicit example/placeholder marker. Strength is not the
same as secret identity.

### Negative

A line is proposed negative when it is an identifier, hostname, email, username,
path, port, database name, timestamp, browser schema field, public key,
certificate, structural private-key metadata, or an empty/null placeholder. These
are not secrets alone even when the existing 175-item filesystem truth counted
them as informative units.

### Ambiguous

A line is proposed ambiguous when the source does not support a defensible binary
decision, for example:

- an encrypted Firefox password record that cannot be decrypted without the
  browser key;
- an explicitly example-style FTP/Salesforce/password value;
- a literal default password such as `password` or `admin`;
- the test-style MongoDB credential;
- an unlabeled high-entropy string with no service or credential context.

Ambiguous candidates are excluded from proposed positive denominators until the
owner adjudicates them. They are not silently treated as false positives.

## 3. Stable identity and repeated credentials

`secret_identity` is `sha256:` plus a SHA-256 digest of the normalized secret
value(s), never the raw value. Candidates sharing the same identity are assigned
one `secret_group` (for example the same AWS secret in `.bash_profile`,
`cloud/.credentials`, and `cloud/.s3cfg`).

- A repeated credential is **one unique secret**.
- Each distinct path/line placement introduced at a commit is a separate
  **occurrence**.
- An unchanged credential persisting through later commits is not a new
  occurrence.
- A pure rename preserves identity and does not create a new occurrence.
- A changed value creates a new occurrence and a new identity; the previous value
  remains historical-only if it no longer exists.
- Multiple placements of the same value in the initial commit count separately in
  the occurrence model but once in the unique-secret model.

Current proposal: **61 unique positive groups**, **73 positive occurrence rows**,
plus one rename-only row that is excluded from occurrence scoring. Five repeated
placement groups account for twelve duplicate-placement rows; a sixth two-row
group is the config rename lineage.

## 4. Two measurement models

### A. Unique-secret recall

Let `U` be the set of owner-approved positive `secret_group` identities in the
declared scope. A scanner gets credit for a group if it reports the corresponding
secret in at least one snapshot where it exists.

```text
Unique recall = |detected unique groups| / |U|
```

This model tolerates duplicate scanner reports and repeated placements. It is the
appropriate model for scanners that report unique credentials rather than every
occurrence.

### B. Historical occurrence recall

Let `O` be the set of owner-approved positive occurrence rows: a path/line
placement at the commit where that placement first appears. A scanner occurrence
match requires the secret identity and the relevant path/line; a finding at a
later snapshot is mapped back to the introduction occurrence rather than counted
again.

```text
Occurrence recall = |matched occurrence rows| / |O|
```

This model requires commit or unambiguous path/line attribution. If a scanner
reports only unique values with no commit/path placement, occurrence recall is
`NOT_APPLICABLE` or `PARTIAL`, not zero. A scanner that reports the same value at
multiple snapshots must have those findings deduplicated before scoring.

The current provisional denominators are:

- `|U| = 61`
- `|O| = 73` (the one rename-only positive row is excluded)

### Repeated, renamed, modified, and deleted credentials

| Case | Unique model | Occurrence model |
| --- | --- | --- |
| Same value in multiple files at introduction | One group | One occurrence per path/line placement |
| Same value repeated across commits | One group | Still one occurrence per placement |
| Rename with identical blob | One group | No new occurrence |
| Later value change | Old and new values are separate groups | New value is a new occurrence; old value remains historical-only |
| Deletion | Group remains in unique inventory if it ever existed in scope | No new occurrence; historical-only presence |
| Multiple secrets in one line | Split only when the source gives separate credential identity; otherwise one candidate with a documented range |

## 5. Precision, duplicates, and F1

A historical finding can be classified only after owner adjudication:

- **Verified true positive:** value identity or a path/private-key match agrees
  with an approved positive candidate.
- **Verified false positive:** finding maps to an approved negative value, or no
  credential candidate exists and the source context is adjudicated benign.
- **Duplicate:** a second finding for the same approved occurrence, including a
  scanner reporting persistence snapshots.
- **Supporting component:** an access-key ID or other identifier that is part of
  a credential pair but is not the secret component. Proposed as neither TP nor FP
  until the owner decides.
- **Unverified / ambiguous:** identity cannot be established, or the candidate is
  explicitly ambiguous.

```text
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 × Precision × Recall / (Precision + Recall)
```

Denominators must be fixed from the owner-approved positive inventory. Duplicates
are removed. Supporting components are not silently counted as TP, and ambiguous
values are not silently counted as FP. No true-negative count is available for Git
history, so no classification-accuracy claim is made.

**Precision and F1 are not currently certified.** The inventory is unapproved,
14 candidates remain ambiguous, and two private-key findings have path/type
matches but value-hash mismatches.

## 6. Scanner cross-check

The cross-check in
[`leaky-history-scanner-crosscheck.csv`](leaky-history-scanner-crosscheck.csv)
matches CP3 scanner findings by value identity first, then by commit/path/line.
It is a reconciliation exercise, not a truth source, and no candidate was changed
to agree with scanner output.

| Scanner | Findings | Verified TP | Duplicate | Supporting | Ambiguous | Unverified | Provisional unique recall | Provisional occurrence recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Gitleaks | 26 | 20 | 3 | 2 | 0 | 1 | 15/61 (24.59%) | 21/73 (28.77%) |
| Betterleaks | 41 | 34 | 3 | 2 | 1 | 1 | 27/61 (44.26%) | 35/73 (47.95%) |

These percentages are **provisional cross-check observations**, not certified
recall. The supporting findings are AWS access-key components in `.s3cfg`; the
unverified findings are private-key values whose scanner hash is not the same
extraction as the file hash. Both need owner adjudication.

Exactly 26 finding signatures are shared by both scanners; 15 are unique to
Betterleaks and none are unique to Gitleaks, based on commit/path/line/rule/
fingerprint signatures.

## 7. Readiness assessment

| Metric | Status | Unresolved issue |
| --- | --- | --- |
| Unique-secret historical recall | **PARTIAL** | 61 proposed groups require owner approval; 14 ambiguous candidates are excluded; private-key hash matching needs adjudication |
| Historical occurrence recall | **PARTIAL** | 73 placement occurrences require approval; multiple placements, rename handling, merge-snapshot deduplication, and commit attribution must be confirmed |
| Verified false-positive counts | **BLOCKED** | No owner-approved negative oracle; supporting access-key findings and unverified private keys are unresolved |
| Precision | **BLOCKED** | Positive inventory is unapproved; material findings remain ambiguous/unverified; supporting components are neither TP nor FP |
| F1 | **BLOCKED** | Depends on certified precision and recall |
| Per-commit detection reporting | **PARTIAL** | Both scanners carry commit identity, but they report persistence snapshots; occurrence attribution requires deduplication and merge handling |

No metric is ready for certification from this proposal alone. The owner should
first review the candidate inventory and dispositions.

## 8. Owner decisions required

1. Approve/reject/revise the 74 positive, 14 ambiguous, and 93 negative candidate
   rows. Replace `PENDING_OWNER_REVIEW` with the approved disposition.
2. Decide whether the old FileZilla password is a historical-only positive or
   ambiguous; it is currently ambiguous.
3. Decide whether password hashes count as positive credential material.
4. Decide whether encrypted Firefox password records count as positive,
   ambiguous, or negative.
5. Decide whether literal default passwords and unlabeled high-entropy strings
   belong in positive denominators.
6. Decide the occurrence policy for multiple placements in one commit, path
   renames, merge-only snapshots, and modified values.
7. Decide whether AWS access-key components are supporting findings or FPs.
8. Decide whether the two private-key hash mismatches are accepted by path/type or
   require further evidence.
9. Only after those decisions: ratify unique/occurrence denominators and certify
   precision/F1 eligibility.

Until then, Leaky Repo history remains **UNSCORED** and the existing 175-item
filesystem denominator remains inapplicable to history.
