# CP5D.1 — Final source-identity hardening

**Branch:** `test/scan-harness`  
**Baseline:** `e574c218117bf9a25535b4f6388f7bb96c2ceb27`  
**Status:** Implemented and ready for review. No oracle migration applied.

## Result

CP5D.1 corrects the two remaining identity gaps without changing retained scanner
classifications:

| Metric | Value |
|---|---:|
| RNC TP occurrences | **21 / 65** |
| RNC unique TP groups | **19 / 53** |
| Duplicates | **21** |
| Informative matches | **7** |
| Verified FP alerts | **1** |
| Unique verified nonsecret exposures | **1** |
| Unmatched pending | **11** |
| Unverified | **0** |
| Accounted observations | **61/61** |
| Precision/F1 | `null` / `BLOCKED_INCOMPLETE_NEGATIVE_ORACLE` |

Proposed migration accounting remains:

- **21 TP**
- **21 duplicates**
- **7 informative**
- **12 FP alerts**
- **4 unique nonsecret exposures**
- **0 pending**
- **184 total / 89 negatives / 65 positives / 53 unique groups**

## 1. Rename-lineage continuity

### Correction

The independent renamed-path exact-line fallback in `mapped_ranges()` has been
removed. Rename identity is now carried through the rooted lineage graph itself:

- an approved rename transition changes the lineage state path from `from` to `to`;
- the old and new paths are line-mapped through the real parent/child diff;
- if Git's rename heuristic cannot anchor a moved/annotated line, a **unique exact
  content or non-comment code-prefix anchor** is used only inside the explicitly
  approved rename transition;
- multiple possible destinations are ambiguous and are rejected;
- no line-distance or value-hash-only attribution is used;
- deletion/recreation and rotation break the lineage; descendant values do not
  re-enter it.

### Regression coverage

Added tests for:

- valid rename preserving the original credential;
- rename followed by rotation, reintroduction, and persistence;
- rename followed by deletion and recreation;
- rename plus line movement and trailing-comment edits;
- branch/merge paths where an unrelated same-value path must not inherit the
  renamed occurrence.

The existing rename test remains green.

## 2. Exact negative-reference identity

The three proposed negatives now carry verified exact-value digests:

| Proposed ID | Exact extracted value | `identity.secret_sha256` |
|---|---|---|
| `PNM-001` | `sshPassphrase` | `168f39bc81005d2aae6aa2a5ed563bc29b9afb92be9bd33ae58e5676866afa73` |
| `PNM-002` | `passphrase` | `1e089e3c5323ad80a90767bdd5907297b4138163f027097fd3bdbeab528d2d68` |
| `PNJ-001` | `function(err` | `7a6d503ccb60241ad7a7f8381c4442792fb8143ea4625942bc9d7578750a1a0d` |

A digest-bearing negative is matched by **exact extracted-value identity**, not by
every token on its source line. Regression tests prove that `userPassword` on the
same metadata comment and `examplepassword` on the same JavaScript line do not
match `PNM-001` or `PNJ-001`.

The three proposed source identities and their historical observation accounting
are unchanged.

## 3. Official proposed-oracle validation

`harness/history_oracle.py` now exposes an explicit proposed-migration profile used
by `validate_proposed()`. The approved 181/86 loader profile remains unchanged and
strict.

The proposed 184/89 document was validated through the official validator:

```text
validator: harness.history_oracle.validate_proposed
status: PASS
counts: total=184, NEGATIVE=89, POSITIVE=65, INFORMATIVE=30
source_validation: PASS
checked_items: 184
checked_blobs: 184
errors: []
```

The proposed item status is `PROPOSED_NOT_APPLIED`, not owner-approved. The
approved oracle file was **not** changed.

## 4. Retained rescoring

CP5D retained evidence was rescored with the CP5D.1 matcher:

| Scanner | Observed | TP | Unique TP | FN | FP alerts | Unique FP exposures | Duplicates | Informative | Unmatched |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| RNC | 61 | 21 | 19 | 44 | 1 | 1 | 21 | 7 | 11 |
| Gitleaks | 26 | 21 | 15 | 44 | 0 | 0 | 3 | 2 | 0 |
| Betterleaks | 41 | 36 | 28 | 29 | 0 | 0 | 3 | 2 | 0 |

Native/Docker classification parity remains PASS for all three. No retained
classification changed.

## 5. Tests

**276 tests passed**, 0 failures/errors, 180.370 s.

## 6. Remaining decision

The owner-approved oracle migration remains pending final review. If approved,
apply the three proposed negative records and update the validator constants to
184/89 while preserving 65 positive occurrences and 53 unique groups. Until then:

- the current oracle remains 181/86;
- the current RNC run remains 21/21/7/1/1/11;
- precision/F1 remain uncertified;
- no scanner source, default rules, synthetic lab, or scoring formula changed.

## Evidence

- [`reports/cp5d1/proposal-validation.json`](../../reports/cp5d1/proposal-validation.json)
- [`reports/cp5d1/cross-scanner-rescore.json`](../../reports/cp5d1/cross-scanner-rescore.json)
- [`reports/cp5d/proposed-oracle-migration.json`](../../reports/cp5d/proposed-oracle-migration.json)
- [`harness/history_matching.py`](../../harness/history_matching.py)
- [`harness/history_oracle.py`](../../harness/history_oracle.py)
- [`tests/test_history_matching.py`](../../tests/test_history_matching.py)
- [`tests/test_leaky_history_oracle.py`](../../tests/test_leaky_history_oracle.py)
