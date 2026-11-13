# CP5D — Historical lineage integrity and negative reference design

**Branch:** `test/scan-harness`  
**Baseline:** `c7ce28a35fb490a7325d2806a43603e26728a389`  
**Scope:** lineage-rooted historical matching, exact-value negative references, metadata-negative consolidation, false-positive accounting, retained-evidence rescoring, tests, and migration proposals.  
**Status:** Implemented and ready for review. No scanner was rebuilt or rerun.

> **CP5D.1 supersedes the proposal details below:** rename continuity is now
> lineage-rooted, the three proposed negatives carry exact value digests, and the
> 184/89 proposal passes the official `validate_proposed` profile. See
> [CP5D.1](CP5D1-final-source-identity-report.md).

## Result

CP5D closes the local parent/child fallback loophole that could have attributed a
reintroduced value at D to the original A occurrence. The retained evidence has no
such D observation, so the current RNC score is unchanged:

- **21 / 65** occurrence recall — **32.31%**
- **19 / 53** unique credential recall — **35.85%**
- **21 TP occurrences**, 21 duplicates, 7 informative matches,
  1 verified false positive, 11 unmatched pending review, 0 unverified
- **61 / 61** observed findings accounted

The new unique-exposure accounting currently reports **1 unique verified nonsecret
exposure** and **1 verified false-positive alert observation**. The 11 pending
observations are not counted as false positives.

## 1. Reintroduction loophole and correction

### Defect

CP5C's `exact_line_retained()` checked only the immediate parent and child. For:

```text
A: PASSWORD=alpha    approved occurrence
B: PASSWORD=beta     rotation
C: PASSWORD=alpha    reintroduction
D: PASSWORD=alpha    persistence of the reintroduction
```

C was not credited (B did not contain alpha), but D was accepted because C and D
both contained alpha. D therefore inherited A's occurrence identity as a duplicate.
That is a local, history-blind fallback, not provenance.

### Correction

`HistorySource.lineage_for()` now carries a rooted state set and permits a changed
line only when **both** of the following are true:

1. the parent state is already in the approved occurrence's lineage;
2. the child is an equal-size, value-preserving edit with the same non-comment code
   prefix and the approved value still evidenced in both parent and child.

The local `exact_line_retained()` helper has been removed. Reintroduction C has no
parent state (B never entered A's lineage), so neither C nor D can enter it. File
deletion followed by recreation behaves the same way.

Valid behavior remains supported:

- unchanged lines shifted by insertions/deletions above them;
- trailing-comment append or label edits such as `# Sensitive` → `# Risk`;
- unchanged content in merge histories;
- the existing reviewed-rename exact-line fallback, which is not a distance rule.

A key-changing line such as `KEY=alpha` → `OTHER=alpha` is rejected because the
non-comment code prefix changes. A line-distance rule is never used, and the value
hash alone never establishes placement identity.

## 2. Exact-value negative references

### Design

A negative reference may now carry the existing optional
`identity.secret_sha256`. For a digest-bearing negative, matching is **exact-value
identity only**, not every token or quoted field on the source line. This permits:

```javascript
conn.login('username@example.com', 'salesforcepassword', function(err, res) {
```

- `salesforcepassword` → informative reference `LH-0138`;
- `function(err` → exact negative candidate `PNJ-001`.

The negative is scoped to the extracted value hash and source location, not to the
whole line. A correct `salesforcepassword` finding cannot match the negative, and a
`function(err` finding cannot match the informative reference.

No new schema field is required: `identity.secret_sha256` is already optional for
negative items, and source validation already proves the digest occurs in the
reviewed line. A future owner-approved oracle migration would need to update the
validator's fixed total/ID/negative counts; that migration is not applied.

### Proposed record

`PNJ-001` is proposed only, with:

- source: `web/js/salesforce.js:6` at `903a9ca`;
- exact value: `function(err`;
- SHA-256: `7a6d503ccb60241ad7a7f8381c4442792fb8143ea4625942bc9d7578750a1a0d`;
- provenance: `903:6`, `9f:7`, `4ad:7`;
- expected alerts: 3.

## 3. Metadata-negative consolidation

The four CP5C proposals at `9f` and `4ad` overlapped at merge `2e951359`.
`9f1468c` is an ancestor of `4ad3f90`, `226fcb4`, and `2e951359`; the `4ad`
records were repeated branch/merge observations, not independent source
placements.

The consolidated proposal contains **two** metadata records:

| Proposed ID | Source | Exact comment value | Covered alerts |
|---|---|---|---:|
| `PNM-001` | `.leaky-meta/secrets.csv:46` at `9f1468c` | `sshPassphrase` | 4 |
| `PNM-002` | `.leaky-meta/secrets.csv:67` at `9f1468c` | `passphrase` | 4 |

Both cover the later `4ad`, `226fcb4`, and `2e951359` observations through the
lineage. There is no branch overlap and no ambiguous negative attribution.

Combined with `PNJ-001`, the migration proposal has **3 records**:

- owner-approved reviewed negatives: **86 → 89**;
- oracle total: **181 → 184**;
- positive occurrences: **65** (unchanged);
- unique groups: **53** (unchanged);
- informative references: **30** (unchanged).

This is a proposed oracle revision, not an accepted one. The owner-approved oracle
file was not changed.

## 4. False-positive accounting

The history metrics now distinguish:

| Metric | Meaning | Current |
|---|---|---:|
| `verified_false_positive_count` | Total observed alerts matched to an approved negative reference | **1** |
| `unique_verified_nonsecret_exposure_count` | Distinct approved negative source identities matched by at least one alert | **1** |

Repeated alerts from one negative identity count once in the unique-exposure
metric. They still count individually in the total alert metric.

If the three proposed records are approved, the simulated accounting is:

| Proposed identity | Unique exposures | Alert observations |
|---|---:|---:|
| `LH-0124` | 1 | 1 |
| `PNM-001` | 1 | 4 |
| `PNM-002` | 1 | 4 |
| `PNJ-001` | 1 | 3 |
| **Total** | **4** | **12** |

The 11 currently pending alerts are not counted as verified false positives. The
proposals remain `PROPOSED_NOT_APPLIED`.

## 5. Current finding accountability

The 19 CP5C observations plus the adjacent Salesforce line-6 observation are
reconciled as:

| Classification | Current CP5D | If proposals approved |
|---|---:|---:|
| `DUPLICATE` | 8 | 8 |
| `FALSE_POSITIVE` | 1 | 12 |
| `UNMATCHED_PENDING_REVIEW` | 11 | 0 |
| total observations in subset | 20 | 20 |

The 8 duplicates are the line-shifted `LH-0137`, `LH-0147`, `LH-0152`, and
`LH-0157` observations. The current false positive is the approved `LH-0124`
placeholder. The 11 pending are 8 metadata comments and 3 `function(err`
extractions.

The full 19-row CP5C reconciliation remains in
[`reports/cp5c/rnc-19-reconciliation.json`](../../reports/cp5c/rnc-19-reconciliation.json).
The CP5D 20-observation report is
[`reports/cp5d/finding-accountability.json`](../../reports/cp5d/finding-accountability.json).

## 6. Rescoring and parity

Retained RNC, Gitleaks, and Betterleaks evidence was rescored offline with the
final matcher. No scanner was rerun.

| Scanner | Observed | TP | Unique TP | FN | FP alerts | Unique FP exposures | Duplicates | Informative | Unmatched | Unverified |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| RNC `93b4dda` | 61 | 21 | 19 | 44 | 1 | 1 | 21 | 7 | 11 | 0 |
| Gitleaks `5f6ec56` | 26 | 21 | 15 | 44 | 0 | 0 | 3 | 2 | 0 | 0 |
| Betterleaks `5eab483` | 41 | 36 | 28 | 29 | 0 | 0 | 3 | 2 | 0 | 0 |

Current classifications are unchanged from CP5C after the lineage correction.
The native/Docker evaluation-multiset parity remains PASS for all three:
RNC 105 evaluations per product, Gitleaks 70, Betterleaks 70.

Precision/F1 remain `null` with `BLOCKED_INCOMPLETE_NEGATIVE_ORACLE`. The
proposed migration would add reviewed negatives but would not make the inventory
exhaustive, so precision/F1 would remain uncertified.

## 7. Regression testing

New tests cover:

- rotation then reintroduction, including persistence of the reintroduced value;
- deletion and recreation of a source file;
- key-changing, value-preserving edits;
- trailing-comment label change on an existing lineage;
- exact negative on an informative/positive line;
- repeated negative alerts counted once as a unique exposure;
- the existing line shift, merge, rename, copy, and negative-removal cases.

**Full suite:** `python -m unittest discover -s tests -v`  
**Result:** **269 tests passed**, 0 failures/errors, 153.103 s.

## 8. Proposed migration and owner decisions

The complete proposal is
[`reports/cp5d/proposed-oracle-migration.json`](../../reports/cp5d/proposed-oracle-migration.json):

- 3 records: `PNM-001`, `PNM-002`, `PNJ-001`;
- source validation of the augmented oracle: **PASS**, 184/184 items/blobs;
- simulated RNC result if approved: 21 TP, 21 duplicates, 7 informative,
  12 FP alerts, 4 unique FP exposures, 0 unmatched, 0 ambiguous, 61/61 accounted;
- no positive or unique-group change.

Owner decisions remaining:

1. Approve or reject exact-value negative identity for a nonsecret extraction on a
   line that also contains an informative value. Without approval, `PNJ-001`
   remains proposed and the 3 Salesforce alerts remain pending.
2. Approve or reject the two consolidated metadata negatives. Without approval,
   the 8 metadata alerts remain pending.
3. If approved, update the owner-approved oracle counts/IDs from 181/86 to
   184/89 and update the hardcoded validator constants; do not change the 65
   positive occurrences or 53 unique groups.
4. Keep precision/F1 uncertified regardless of these additions; reviewed
   negatives remain non-exhaustive.
5. `LH-0179` remains a genuine RNC miss. The `hub:4` placeholder remains a verified
   negative and no positive credit is transferred.

No oracle modification, scanner source change, default-rule change, synthetic-lab
registration, merge, rebase, or force-push was performed.

## Evidence

- [`reports/cp5d/cross-scanner-rescore.json`](../../reports/cp5d/cross-scanner-rescore.json)
- [`reports/cp5d/finding-accountability.json`](../../reports/cp5d/finding-accountability.json)
- [`reports/cp5d/proposed-oracle-migration.json`](../../reports/cp5d/proposed-oracle-migration.json)
- [`reports/cp5d/rnc-native-history.json`](../../reports/cp5d/rnc-native-history.json)
- [`reports/cp5d/rnc-docker-amd64-history.json`](../../reports/cp5d/rnc-docker-amd64-history.json)
- [`reports/cp5d/gitleaks-native-history.json`](../../reports/cp5d/gitleaks-native-history.json)
- [`reports/cp5d/gitleaks-docker-amd64-history.json`](../../reports/cp5d/gitleaks-docker-amd64-history.json)
- [`reports/cp5d/betterleaks-native-history.json`](../../reports/cp5d/betterleaks-native-history.json)
- [`reports/cp5d/betterleaks-docker-amd64-history.json`](../../reports/cp5d/betterleaks-docker-amd64-history.json)
