# Git-history benchmark and truth accountability

**Checkpoint:** CP3 + owner-approved history integration

## Scope

The filesystem Leaky Repo manifest describes **only the pinned working tree**
(`2e951359cac53addbee56437da3ffb546e3dfe24`). Its 175-item denominator and stable
finding IDs are not reused for Git history.

Leaky Repo history discovery is pinned in
[`datasets/leaky-repo.history-scope.json`](../datasets/leaky-repo.history-scope.json):

| Scope fact | Value |
| --- | ---: |
| Commits | 25 |
| Current files | 61 |
| Changed paths | 65 |
| Historical-only paths | 4 |
| Additions / modifications / deletions | 62 / 52 / 1 |
| Renames | 3 |
| Duplicate current-blob groups | 0 |
| Git objects | 207 |

Historical-only paths: `.docker/config`, `benchmarking/DETECT-SECRETS.md`,
`benchmarking/TRUFFLEHOG.md`, `misc-keys/cert-example.pem`. Two of these were
renamed (`.docker/config` → `config`, and the two benchmark documents moved into
`.leaky-meta/`), so "historical-only path" does not mean the content was deleted.

## Owner-approved historical source truth (integrated November 12, 2026)

The owner-approved Leaky Repo Git-history source oracle is
[`datasets/leaky-repo.history-oracle.json`](../datasets/leaky-repo.history-oracle.json)
with **184 records: 65 positive occurrences / 53 unique groups, 89 negative,
30 informative, zero lineage-only (LH-0170 is informative rename lineage)**. The
CP10 owner decision approved the three exact-value negatives (`PNM-001`,
`PNM-002`, `PNJ-001`); their strict identity digests are part of the canonical
oracle. The [approval record](oracle-review/leaky-history-approved.md) controls
disposition, source identity and matching policy.

The harness now integrates this oracle. `harness/history_oracle.py` validates the
owner counts and decisions and checks every reviewed blob/line against the pinned
25-commit source. `harness/history_matching.py` performs ancestry-aware, typed
matching and retains every finding. The separate 175-item filesystem oracle remains
unchanged and is never used as a history denominator.

### Historical matching

A finding earns occurrence credit only when all of the following hold:

- the path is the approved placement or a reviewed rename of it;
- the finding commit is the introduction commit or a descendant;
- the source at that commit still contains the approved credential representation
  at the expected line/span, or at the same placement after unchanged-line source
  movement;
- the finding's safe digest matches a canonical or validated typed representation
  of the credential.

Line movement is followed only through unchanged lines in real parent/child
diffs (`HistorySource.lineage_for`). Insertions or deletions above an occurrence
shift its line; a modified, copied, deleted, or reintroduced value does not enter
the lineage. A value-preserving edit is accepted only inside the existing lineage,
when the non-comment code prefix is unchanged and the approved value remains
evidenced in both parent and child. This avoids unrestricted line-distance
tolerance, filename-only matching, and hash-only matching. The same value in a
different file or a genuinely different placement is not conflated, and a value
reintroduced after a rotation starts no lineage from the original occurrence.

Later observations map to the introduction occurrence. The first observation
earns the occurrence; additional snapshots and duplicate detections are
`DUPLICATE`. A modified or rotated value does not inherit the previous value's
credit. Full PEM blocks permit only terminal-newline variation. Docker and
FileZilla Base64 values, database URI password components, and the JetBrains
encoded attribute are validated from source; a decoded equivalence is not claimed
when the scanner hashes a representation the harness cannot independently derive.

Reviewed `Removed` negative references are anchored at their `observed_commit`,
not their later removal commit. They match observations at or before that
snapshot, not replacements made afterward. Informative and typed negative
references require the expected source value (or an explicitly approved
representation); an arbitrary token from the same source line does not qualify.
An exact-value negative (`identity.secret_sha256`) is scoped to that extraction
and can share a line with an informative/positive credential.

Every finding is retained in `evaluations` and the exception ledger. Unknown
locations are `UNMATCHED_PENDING_REVIEW`; approved locations with missing or
conflicting value identity are `UNVERIFIED_EVIDENCE`. Neither is automatically a
true positive or false positive. Verified false-positive **alert observations**
and **unique verified nonsecret exposures** are reported separately; repeated
alerts at one negative source count once as a unique exposure but individually as
alerts. Reviewed negatives are not exhaustive, so history precision/F1 are **NOT
CERTIFIED** and the certification status is
`BLOCKED_INCOMPLETE_NEGATIVE_ORACLE`.

### Retained-report rescoring

`python -m harness rescore-history --report <report.json> --platform <product>`
rescoring applies the same matcher to already-captured normalized findings without
invoking a scanner. It refuses a compact/truncated finding list rather than
silently scoring a subset.

The current retained Gitleaks native evidence scores **21/65 occurrences** and
**15/53 unique groups** (32.31% occurrence recall, 28.30% unique recall), with
3 duplicates, 2 informative AWS-identifier matches and 0 verified false positives.
The retained Betterleaks native evidence scores **36/65 occurrences** and
**28/53 unique groups** (55.38% occurrence recall, 52.83% unique recall), with
3 duplicates and 2 informative matches. These are **unverified scanner
observations scored against owner-approved source truth**, not a certified
precision/F1 claim.

CP5C rescored the retained RNC evidence with the corrected lineage and reference
rules: **21/65 occurrences**, **19/53 unique groups**, 21 duplicates, 7
informative matches, 1 verified false positive, 11 unmatched pending review, and
0 unverified. Of the original 19 unmatched RNC observations, 8 are now duplicates,
1 is the approved `LH-0124` negative, and 10 remain pending. Gitleaks and
Betterleaks results are unchanged. The reviewed-negative inventory remains
non-exhaustive; precision/F1 remain `null` and `BLOCKED_INCOMPLETE_NEGATIVE_ORACLE`.
See the [CP5C report](checkpoints/CP5C-scoring-integrity-report.md).

CP5D extends the same rule set: the fallback that could attribute a reintroduced
value to the original occurrence was removed; exact-value negative references may
target a nonsecret extraction on an informative/positive line; and verified
false-positive alerts are reported separately from unique nonsecret exposures. In
the retained evidence the current RNC result remains 21/65 occurrences, 19/53
unique groups, 1 verified FP alert, 1 unique verified nonsecret exposure, and 11
pending alerts. Three proposed oracle records (two metadata comments and one exact
Salesforce extraction) would bring reviewed negatives from 86 to 89 and total
records from 181 to 184 without changing the 65/53 positive denominators; they
are not applied. See the [CP5D report](checkpoints/CP5D-lineage-integrity-report.md).

CP5D.1 replaced the renamed-path exact-line fallback with explicit rename
transitions inside the rooted lineage graph. Ambiguous line anchors are rejected;
rotation, reintroduction, deletion/recreation, and unrelated same-value paths do
not inherit the earlier identity. CP10 applied the approved migration: the
official loader is now strict at 184/89, all 184 records are source-validated,
and the retained RNC evidence rescores to 21 TP, 21 duplicates, 7 informative,
12 FP alerts, 4 unique verified nonsecret exposures, and 0 pending. The positive
denominators remain 65 occurrences / 53 groups. Precision/F1 remain **NOT
CERTIFIED**. See the
[CP5D.1 report](checkpoints/CP5D1-final-source-identity-report.md) and
[CP10 report](checkpoints/CP10-final-integration-report.md).

### Original CP3 runtime limitation (retained as pre-integration provenance)

The upstream repository publishes `.leaky-meta/secrets.csv`, which counts secrets
in the working tree. It does **not** publish a per-commit secret manifest. Before
the owner-approved oracle was integrated, the history therefore could not
authoritatively answer:

- which unique credential was introduced in which commit;
- whether two identical values in different commits are one credential or a
  rotation/reuse;
- which removed credential should count as a historical expectation;
- whether a historical path rename carries the same secret identity.

The historical CP3 observations (Gitleaks 26 findings / 16 unique secret fingerprints,
Betterleaks 41 / 29) were recorded as unverified observations. They are now
rescored offline against the owner-approved oracle without rerunning either
scanner; the current results are the 21/65 and 36/65 occurrence scores above. The
175-item filesystem denominator is still not applied to history.

CP3 retained the complete normalized history finding list (path, commit, line,
rule, safe hashes, fingerprint) in the experiment JSON so the independent oracle
could be applied without rerunning the scanner. The
[`rescore-history`](../README.md) command uses that retained evidence.

Report: [`reports/cp1e/history-accountability.json`](../reports/cp1e/history-accountability.json).

## Controlled synthetic history: COMPLETE

A deterministic five-commit synthetic corpus independently validates the
methodology. It is a controlled fixture, not a substitute for the external oracle.
It contains:

| Commit | Content |
| --- | --- |
| c1 | Alpha secret in `config/app.env` |
| c2 | Same alpha secret repeated in `config/duplicate.env` |
| c3 | Alpha replaced by beta in `config/app.env`; beta repeated in `deploy/prod.env` |
| c4 | Gamma added in `removed/legacy.env` |
| c5 | Gamma file removed |

Truth separates:

- **Unique expected secrets:** 3 (alpha, beta, gamma).
- **Expected historical occurrences:** 5.

A secret appearing in multiple commits is not automatically a new unique
credential. Scanner history findings are occurrences; unique credentials are
grouped by the controlled truth's stable `unique_secret_id` and safe value
fingerprint.

| Result | Value |
| --- | ---: |
| History status | **COMPLETE** |
| Unique expected / matched | 3 / 3 |
| Unique recall | 100% |
| Occurrence expected / matched | 5 / 5 |
| Missed / unexpected / duplicates | 0 / 0 / 0 |
| Value-verified occurrences | 5 |
| Products | Windows AMD64, Docker Linux AMD64, Docker Linux ARM64 (emulated) |
| Cross-product history parity | PASS for all three pairs |

## Scanner-convention mapping

The normalized history contract records:

- `commit` on each finding;
- safe `secret_sha256` and scanner `fingerprint` metadata;
- path and line;
- a stable truth `finding_id` per occurrence;
- `metadata.unique_secret_id` and `occurrence_kind` in the truth model.

Gitleaks reports one entry per commit/path/line (with its own fingerprint). The
harness does not assume another scanner uses the same fingerprint format; adapters
must populate commit, path, line, and safe value hashes, and the scoring engine
matches occurrence identity and value separately. A scanner that cannot report
commit identity is `NOT_APPLICABLE` for history scoring, not zero recall.

## Operations

- Leaky Repo always executes filesystem capability; it executes Git history
  automatically when the adapter supports Git mode. There is no operator
  filesystem/history-only switch and no history-only comparison mode.
- History uses the pinned repository revision and `.git`; it does not scan a
  copied tree without history.
- The synthetic history suite is selected independently (`git-history`) and uses
  a controlled fixture rule; its truth has no dependency on Gitleaks report shape.
- Unsupported Git mode is reported as `NOT_APPLICABLE`, not as zero detection.
- Detection and performance remain separate; history runs do not feed the
  filesystem score.
- Registered scanner artifacts execute history against the pinned repository
  revision; the harness requires no scanner source checkout or build.
- RNC CP4/CP4A runs `--history --ref HEAD` so its history scope is the pinned
  HEAD's reachable 25 commits, not every local ref. Its units are changed
  commit/path revisions, not full snapshots; all 166 revisions must be
  `INSPECTED` before the suite scores. The registered Docker image must provide
  Git; history execution mounts the repository including `.git` read-only and
  disables network access.
