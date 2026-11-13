# CP5C — Historical finding attribution and scoring integrity

**Branch:** `test/scan-harness`  
**Starting HEAD:** `8599dc1ce7aa68e47ba6eba50ec8eef8311815e1`  
**Scope:** historical matcher, finding accountability, retained-evidence rescoring, tests, and evidence only.  
**Status:** Implemented and ready for review. No scanner was rebuilt or rerun.

## Result

The eight CP5B line-shifted RNC observations are now legitimate repeated detections of
already-approved occurrences. They are retained as `DUPLICATE` and earn no extra
TP. The `hub:4` placeholder now matches the approved `LH-0124` negative and is a
verified false positive. The invalid Salesforce informative match is removed.

The RNC primary score is unchanged:

- **21 / 65** occurrence recall — **32.31%**
- **19 / 53** unique credential recall — **35.85%**

The 19 original unmatched observations now reconcile as **8 duplicates, 1 verified
false positive, and 10 still pending owner review**. One adjacent Salesforce
finding that was previously an invalid `INFORMATIVE_MATCH` is now correctly
pending; total RNC `UNMATCHED_PENDING_REVIEW` is **11**.

## 1. Root causes

### 1.1 Line movement was not represented

`history_matching.py` required the finding line to be inside the oracle's original
`line_start:line_end`, then read the source block at that unchanged line range.
It had no mapping for an occurrence whose line moved because comments were
inserted above it.

The eight affected findings all have the same value as an approved positive:

| Finding | Approved occurrence | Shift |
|---|---|---|
| `web/django/settings.py:24` at `9f/4ad` | `LH-0137` at `903:23` | +1 line |
| `web/var/www/.env:14` at `9f/4ad` | `LH-0147` at `903:9` | +5 lines |
| `web/var/www/.env:33` at `9f/4ad` | `LH-0152` at `903:23` | +10 lines |
| `web/var/www/public_html/config.php:11` at `9f/4ad` | `LH-0157` at `903:7` | +4 lines |

The values and byte digests were already exact; only the line/offset changed.

### 1.2 Removed negatives were anchored to the removal event

`LH-0124` is a `NEGATIVE / NON_SECRET_PLACEHOLDER` observed at
`903a9ca:4` and removed at `9f1468c`. Its `introduced_at` field is the removal
revision, while `observed_commit` is `903a9ca`. The matcher tested
`is_ancestor(introduced_at, finding_commit)`, so the 903 observation was rejected.

The placeholder line is:

```text
  oauth_token: oauth_token
```

The later `9f1468c:4` line is the real approved positive `LH-0179`:

```text
  oauth_token: "7f9cc25de23d1a255720b0ae4551f4044d600f46"
```

RNC's failure to detect `LH-0179` remains a legitimate miss and was not changed.

### 1.3 Informative matching accepted any token from the source line

For `LH-0138`, the approved informative value is `salesforcepassword`. RNC
extracted `function(err` from the same line. The old matcher built a broad token
set from the approved source line and credited the wrong token as
`INFORMATIVE_MATCH`.

This was a scoring-integrity defect, not a scanner TP. Typed positive matching
already intersected the finding digest with the approved representation aliases;
reference matching did not, so an unrelated token on an informative line could
earn credit.

### 1.4 Line preservation needed to distinguish movement from new exposure

A simple line-distance tolerance would incorrectly credit copies, rotations, and
reintroductions. A simple value hash would incorrectly conflate identical values
in different files or placements. The correction therefore uses an
**unchanged-line lineage** through real parent/child diffs and still requires the
approved typed value.

## 2. Source files and scoring logic changed

| File | Change |
|---|---|
| `harness/history_matching.py` | Added `HistorySource.map_line()` / `lineage_for()`, exact retained-line fallback, corrected positive candidate mapping, removed-negative event handling, and exact expected-value matching for references |
| `tests/test_history_matching.py` | Added line-shift, different-placement, trailing-comment, rotation/reintroduction, branch/merge, removed-negative, and informative-value regression tests |
| `tests/test_rnc_history_execution.py` | Updated the pinned RNC expectations to the corrected classifications |
| `reports/cp5c/*` | Rescored retained evidence, 19-finding reconciliation, proposed negatives |
| `docs/history-accountability.md`, `reports/README.md` | Documented the corrected matching and results |

No changes were made to:

- `harness/scoring_engine.py`
- `harness/history_oracle.py`
- `datasets/leaky-repo.history-oracle.json`
- RNC Scanner, Gitleaks, or Betterleaks source
- default scanner rules
- scanner adapters or historical coverage logic

The matcher changes are scanner-independent; no scanner-specific exception exists.

### 2.1 Lineage rules

`HistorySource.lineage_for()` starts at the approved occurrence and follows only
unchanged lines through each real parent/child revision:

- insertions/deletions above a line are allowed and shift it;
- a modified, deleted, or added line stops the lineage;
- copies, rotations, reintroductions, and other placements do not enter it;
- branch and merge parents are traversed through the actual commit graph;
- approved renames keep their exact line fallback, never a distance tolerance.

A value retained on the same exact line with a trailing comment is accepted only
when **both parent and child** contain the approved value at that exact line. This
keeps `.s3cfg` / `.tugboat` trailing-comment persistence as duplicates without
crediting a rotation or reintroduction.

### 2.2 Reference rules

- Positive matching: ancestry + lineage location + typed value identity.
- Negative/informative references: expected value representation, not an arbitrary
  token from the line.
- `Removed` negative references: eligible only at `observed_commit` or its
  ancestors; a later replacement is not covered.
- `LEGACY`/typed unhashed negative references without a digest may use the reviewed
  source line's candidates, but only at the eligible observed location.

## 3. Before/after classification of all 19 RNC observations

| # | Finding | Before | After | Reference | Action |
|---:|---|---|---|---|---|
| 1 | `.leaky-meta/secrets.csv:46` @ `4ad3f90463c8` | `UNMATCHED_PENDING_REVIEW` | `UNMATCHED_PENDING_REVIEW` | none | `PENDING_OWNER_NEGATIVE_APPROVAL` |
| 2 | `.leaky-meta/secrets.csv:46` @ `9f1468c79df2` | `UNMATCHED_PENDING_REVIEW` | `UNMATCHED_PENDING_REVIEW` | none | `PENDING_OWNER_NEGATIVE_APPROVAL` |
| 3 | `.leaky-meta/secrets.csv:48` @ `226fcb481daf` | `UNMATCHED_PENDING_REVIEW` | `UNMATCHED_PENDING_REVIEW` | none | `PENDING_OWNER_NEGATIVE_APPROVAL` |
| 4 | `.leaky-meta/secrets.csv:48` @ `2e951359cac5` | `UNMATCHED_PENDING_REVIEW` | `UNMATCHED_PENDING_REVIEW` | none | `PENDING_OWNER_NEGATIVE_APPROVAL` |
| 5 | `.leaky-meta/secrets.csv:67` @ `4ad3f90463c8` | `UNMATCHED_PENDING_REVIEW` | `UNMATCHED_PENDING_REVIEW` | none | `PENDING_OWNER_NEGATIVE_APPROVAL` |
| 6 | `.leaky-meta/secrets.csv:67` @ `9f1468c79df2` | `UNMATCHED_PENDING_REVIEW` | `UNMATCHED_PENDING_REVIEW` | none | `PENDING_OWNER_NEGATIVE_APPROVAL` |
| 7 | `.leaky-meta/secrets.csv:69` @ `226fcb481daf` | `UNMATCHED_PENDING_REVIEW` | `UNMATCHED_PENDING_REVIEW` | none | `PENDING_OWNER_NEGATIVE_APPROVAL` |
| 8 | `.leaky-meta/secrets.csv:69` @ `2e951359cac5` | `UNMATCHED_PENDING_REVIEW` | `UNMATCHED_PENDING_REVIEW` | none | `PENDING_OWNER_NEGATIVE_APPROVAL` |
| 9 | `hub:4` @ `903a9caba59d` | `UNMATCHED_PENDING_REVIEW` | `FALSE_POSITIVE` | `LH-0124` | `VERIFIED_FALSE_POSITIVE` |
| 10 | `web/django/settings.py:24` @ `4ad3f90463c8` | `UNMATCHED_PENDING_REVIEW` | `DUPLICATE` | `LH-0137` | `RETAIN_AS_DUPLICATE` |
| 11 | `web/django/settings.py:24` @ `9f1468c79df2` | `UNMATCHED_PENDING_REVIEW` | `DUPLICATE` | `LH-0137` | `RETAIN_AS_DUPLICATE` |
| 12 | `web/js/salesforce.js:7` @ `4ad3f90463c8` | `UNMATCHED_PENDING_REVIEW` | `UNMATCHED_PENDING_REVIEW` | none | `PENDING_OWNER_REVIEW` |
| 13 | `web/js/salesforce.js:7` @ `9f1468c79df2` | `UNMATCHED_PENDING_REVIEW` | `UNMATCHED_PENDING_REVIEW` | none | `PENDING_OWNER_REVIEW` |
| 14 | `web/var/www/.env:14` @ `4ad3f90463c8` | `UNMATCHED_PENDING_REVIEW` | `DUPLICATE` | `LH-0147` | `RETAIN_AS_DUPLICATE` |
| 15 | `web/var/www/.env:14` @ `9f1468c79df2` | `UNMATCHED_PENDING_REVIEW` | `DUPLICATE` | `LH-0147` | `RETAIN_AS_DUPLICATE` |
| 16 | `web/var/www/.env:33` @ `4ad3f90463c8` | `UNMATCHED_PENDING_REVIEW` | `DUPLICATE` | `LH-0152` | `RETAIN_AS_DUPLICATE` |
| 17 | `web/var/www/.env:33` @ `9f1468c79df2` | `UNMATCHED_PENDING_REVIEW` | `DUPLICATE` | `LH-0152` | `RETAIN_AS_DUPLICATE` |
| 18 | `web/var/www/public_html/config.php:11` @ `4ad3f90463c8` | `UNMATCHED_PENDING_REVIEW` | `DUPLICATE` | `LH-0157` | `RETAIN_AS_DUPLICATE` |
| 19 | `web/var/www/public_html/config.php:11` @ `9f1468c79df2` | `UNMATCHED_PENDING_REVIEW` | `DUPLICATE` | `LH-0157` | `RETAIN_AS_DUPLICATE` |

Totals for the original 19: **8 duplicates, 1 verified false positive, 10 pending**.

An adjacent finding was not in the original 19 but is part of the same Salesforce
defect:

| Finding | Before | After | Reference | Action |
|---|---|---|---|---|
| `web/js/salesforce.js:6` @ `903a9caba59d` | `INFORMATIVE_MATCH` | `UNMATCHED_PENDING_REVIEW` | `LH-0138` | `INVALID_INFORMATIVE_REMOVED` |

RNC total unmatched pending review is therefore **11** = 8 metadata comments +
2 shifted-line `function(err` findings + 1 original-commit `function(err`
finding.

## 4. Salesforce invalid informative match

The approved informative value is:

```text
salesforcepassword
```

RNC's finding is:

```text
function(err
```

At `903a9ca:6`, both strings occur on the same source line:

```text
conn.login('username@example.com', 'salesforcepassword', function(err, res) {
```

The old matcher took the broad source-token set, found `function(err` as a token,
and awarded `INFORMATIVE_MATCH`. The corrected matcher intersects the finding
digest with the expected informative representation aliases only. `function(err`
does not qualify. The finding is now accountable as
`UNMATCHED_PENDING_REVIEW`.

The actual `salesforcepassword` is already represented by `LH-0138`; no primary
TP is created or lost. The two later `function(err` observations at 9f/4ad also
remain pending. No negative reference is proposed for this line because a
line-level negative would contradict the approved informative credential on the
same line.

## 5. Cross-scanner rescoring

Retained CP3/CP5 evidence was rescored offline with the same matcher. No scanner
was rerun.

| Scanner | Observed | TP | Unique TP | FN | FP | Duplicates | Informative | Unmatched | Unverified | Precision/F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| RNC `93b4dda` | 61 | 21 -> 21 | 19 -> 19 | 44 -> 44 | 0 -> 1 | 13 -> 21 | 8 -> 7 | 19 -> 11 | 0 -> 0 | null / BLOCKED |
| Gitleaks `5f6ec56` | 26 | 21 -> 21 | 15 -> 15 | 44 -> 44 | 0 -> 0 | 3 -> 3 | 2 -> 2 | 0 -> 0 | 0 -> 0 | null / BLOCKED |
| Betterleaks `5eab483` | 41 | 36 -> 36 | 28 -> 28 | 29 -> 29 | 0 -> 0 | 3 -> 3 | 2 -> 2 | 0 -> 0 | 0 -> 0 | null / BLOCKED |

All three scanners retain their TP and unique-identity results. Gitleaks and
Betterleaks are unchanged in every metric. RNC gains no TP and loses none; its
new classification changes are duplicates, one verified false positive, one
removed invalid informative match, and the corresponding pending count.

Native/Docker classification parity:

| Scanner | Evaluations per product | Native/Docker classification parity |
|---|---:|---|
| RNC | 105 | PASS |
| Gitleaks | 70 | PASS |
| Betterleaks | 70 | PASS |

The parity comparison includes classification, expected ID, path, line, commit,
and safe digest. Finding IDs differ between scanner products and are not used as
the parity key.

## 6. Denominators and precision status

The owner-approved oracle is unchanged:

| Denominator | Value |
|---|---:|
| Positive source occurrences | 65 |
| Unique credential groups | 53 |
| Reviewed negatives | 86 |
| Informative references | 30 |
| LINEAGE_ONLY | 0 |
| Oracle SHA-256 | `3f9a71542884224d44ce046d41280d3875c831bc2965ffb115a847955f036055` |
| Reviewed negatives exhaustive | false |

RNC remains **21/65 (32.31%)** and **19/53 (35.85%)**. The new `FALSE_POSITIVE`
count is 1, but precision/F1 remain `null` with
`BLOCKED_INCOMPLETE_NEGATIVE_ORACLE`; one verified negative does not make the
reviewed-negative inventory exhaustive.

## 7. Regression testing

New focused tests in `tests/test_history_matching.py` cover:

- same credential, same placement, different line;
- same credential in later historical revisions;
- same value in a genuinely different file and a different line in the same file;
- source movement versus new exposure;
- credential rotation and reintroduction;
- branch and merge line movement;
- value retained on the same line with a trailing comment;
- historical negative before removal;
- incorrect token versus correct credential on an informative line;
- one approved positive receiving at most one TP.

The pinned RNC test now asserts the corrected 21/19 score, 21 duplicates, 7
informative matches, 1 verified false positive, 11 unmatched, 0 unverified, and
61/61 accounted observations. It also asserts the four line-shift duplicate
groups, the `LH-0124` negative match, and the absence of a Salesforce informative
match.

**Full suite:** `python -m unittest discover -s tests -v`  
**Result:** **264 tests passed**, 0 failures/errors, 126.207 s.

## 8. Remaining owner-adjudication decisions

1. **Eight metadata comment findings remain pending.** They are non-secret risk
   vocabulary, not credentials. Four proposed source references
   (`PN-001`–`PN-004`) are recorded in
   [`reports/cp5c/proposed-negative-additions.json`](../../reports/cp5c/proposed-negative-additions.json)
   but were **not applied** to the oracle. They are marked
   `PROPOSED_NOT_APPLIED`.
   - The proposals overlap on the `2e951359` merge because both the `9f` and
     `4ad` branch lineages reach the same comment. Owner approval must decide
     whether overlapping branch negatives collapse to one candidate; without
     that decision, a finding can be `AMBIGUOUS`, not `FALSE_POSITIVE`.
   - If approved as four additions, the reviewed-negative count would change
     from 86 to 90. That is a separately approved oracle revision, not part of
     CP5C.
   - No positive or informative oracle item is proposed for these comments.

2. **Three Salesforce incorrect-extraction findings remain pending.** The
   `function(err` bytes are not credentials. No line-level negative is proposed
   because the same line contains the approved informative
   `salesforcepassword`; a negative would contradict the informative truth. The
   correct remedy is a scanner extraction correction and, separately, exact
   expected-value informative matching, which CP5C already enforces. These
   findings must not be recast as true positives or false positives merely to
   clear the queue.

3. **`hub:4` is now a verified false positive** under `LH-0124`. The placeholder
   classification is unchanged. RNC's failure to detect the later positive
   `LH-0179` remains a scanner miss; no truth or score correction is proposed.

4. **Precision/F1 remain uncertified.** The reviewed-negative inventory is still
   not exhaustive; the single verified false positive does not change the
   certification status.

No additional truth changes, scanner-specific exceptions, or denominator changes
were made.

## Evidence

- [`reports/cp5c/cross-scanner-rescore.json`](../../reports/cp5c/cross-scanner-rescore.json)
- [`reports/cp5c/rnc-19-reconciliation.json`](../../reports/cp5c/rnc-19-reconciliation.json)
- [`reports/cp5c/proposed-negative-additions.json`](../../reports/cp5c/proposed-negative-additions.json)
- [`reports/cp5c/rnc-native-history.json`](../../reports/cp5c/rnc-native-history.json)
- [`reports/cp5c/rnc-docker-amd64-history.json`](../../reports/cp5c/rnc-docker-amd64-history.json)
- [`reports/cp5c/gitleaks-native-history.json`](../../reports/cp5c/gitleaks-native-history.json)
- [`reports/cp5c/betterleaks-native-history.json`](../../reports/cp5c/betterleaks-native-history.json)

The original CP5 report and CP5B needs-review manifest are preserved unchanged.
