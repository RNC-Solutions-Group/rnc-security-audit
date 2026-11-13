# Historical oracle integration, scoring integrity and benchmark infrastructure

**Checkpoint:** CP4 history/accountability assignment
**Branch:** `test/scan-harness`
**Starting HEAD:** `38dc6f8976fdda5ad95c090f5b01698178a5bbe6`
**Ending code HEAD:** `317a1957f8b9d274a826c39a96608a15c3b4151d`
**Status:** Implemented, tested, committed, and pushed; awaiting owner review.
No merge, rebase, force-push, worktree, or application-source change was
performed.

## 1. Implementation changes and architectural decisions

### CP1 baseline findings

The starting tree was clean at `38dc6f8` on `test/scan-harness`. A full baseline
run of 223 tests found five failures, and review found additional correctness
risks:

- baseline comparison treated review-pending findings as invisible, so a new
  unmatched finding did not fail a regression comparison;
- the synthetic-validation fixture still expected historical `UNEXPECTED_FINDING`
  classifications for value mismatches that the newer accountability model
  correctly reports as `UNVERIFIED_EVIDENCE`/`UNMATCHED_PENDING_REVIEW`;
- the approved-oracle test compared a `Counter` with a zero-count
  `LINEAGE_ONLY` key incorrectly;
- the experiment tests depended on Docker daemon availability during cleanup even
  for native-only runs;
- the normalized finding projection filtered only top-level unsafe metadata keys,
  leaving nested `secret`/`raw` keys potentially serializable;
- line-only location matches could become true positives without an explicit
  policy.

These were repaired rather than waived. The final suite is green.

### Historical source oracle and matcher

New modules:

- `harness/history_oracle.py` loads the canonical owner document and validates:
  181 rows, 65/53/86/30/0 counts, owner exceptions LH-0124 and LH-0170, exact
  owner policy strings, unique/repeat group structure, source commits, Git blob
  identities, line bounds, and digest-to-source evidence. It also checks the
  pinned HEAD, 25 reachable commits, clean source, and the history-scope renames.
- `harness/history_matching.py` is a scanner-independent matcher. A finding earns
  an occurrence only when path, commit ancestry, source-line representation,
  and safe value identity all agree. Later snapshots map to the introduction
  occurrence; the first observation earns it and later observations are
  duplicates. A changed/rotated value cannot inherit the previous value's
  occurrence. Reviewed rename lineage adds no occurrence.
- `harness/rescore.py` applies the same matcher to retained normalized findings
  without invoking a scanner and refuses truncated/compact finding lists.

Typed source representation support includes:

- direct credential components (environment assignments, quoted values, URL
  userinfo, `.netrc`, `.pgpass`, XML password attributes);
- complete PEM/PPK blocks with terminal-newline/line-ending normalization;
- Docker Base64 authentication values and decoded password components;
- FileZilla Base64 `Pass` values and decoded components;
- database URI/embedded password components, including percent-decoded variants;
- JetBrains encoded password attribute (decoded equivalence is not claimed
  because the reviewed source identity is the encoded attribute).

The matcher uses a source-side candidate set intersected with the approved
occurrence's representation aliases. A username, hostname, or unrelated token
therefore cannot become primary credit merely because it appears on the line.

### Complete finding accountability

`harness/scoring_engine.py` now:

- requires explicit `ScoringPolicy.allow_line_only` for location-only credit;
- keeps missing/conflicting value evidence as `UNVERIFIED_EVIDENCE`;
- keeps unknown locations as `UNMATCHED_PENDING_REVIEW`;
- treats a finding matching multiple expected locations as `AMBIGUOUS_MATCH`;
- reports `observed_count`, `accounted_observed_count`, and
  `finding_accounting_reconciled`;
- never certifies precision/F1 while pending, informative, partial, ambiguous, or
  unmapped findings remain unresolved;
- only produces `FALSE_POSITIVE` for validated reviewed-negative evidence.

`NormalizedFinding.safe_dict()` now recursively removes unsafe metadata keys and
transient text. Every observed history finding also has an evaluation and, where
applicable, an exception-ledger entry with scanner/path/line/rule, safe hashes,
matching status and explanation.

### Leaky Repo suite

`harness/suites/leaky_repo.py` now loads and source-validates the oracle once per
run (cached across products), scores each Git-capable product automatically, and
reports occurrence recall, unique-group recall, category metrics, duplicates,
informative matches, verified negatives, unmatched/unverified counts, and the
accounting reconciliation. Unsupported Git mode remains `NOT_APPLICABLE`; an
oracle/source failure is `BLOCKED`, never zero recall.

### Benchmark environment architecture

`harness/performance.py` now has explicit `DEV`, `CONTROLLED`, and `RELEASE`
profiles with separate contention, documented-condition, publishability and
stability-threshold settings. `RELEASE` requires the default stress profile.
Reports record host CPU/RAM/disk capacity/load, scanner order, cache state,
eligible/inspected files, inspected throughput, archive fields, timeouts,
resource-limit events, warm-up/measured sequence and performance drift.
`harness/performance.performance_drift()` compares retained documents without
modifying them. Optional `cpu`, `memory`, `io`, and `network` stress profiles are
reserved and clearly separate from detection configuration.

`harness/workspace.py` now skips Docker cleanup when no Docker product was built,
so native-only runs do not depend on the Docker daemon.

### Suite separation

`all` still resolves to Levain + Leaky Repo only. `gitleaks`,
`synthetic-filesystem`, and `git-history` remain explicit opt-ins.
`rnclab` is not registered and a test ensures it is rejected as unknown until its
dataset/oracle/integration are ready.

## 2. Tests executed and results

Command:

```sh
python -m unittest discover -s tests -t . -v
```

Result: **246 tests passed**, 0 failures, 0 errors (91.578 s, Windows AMD64,
Python 3.13.5). The run included the new history matcher, suite integration,
oracle integrity, rescore, scoring-accountability, performance and suite
separation tests.

Additional validation:

- `python -m compileall -q harness tests` — passed.
- `python -m harness verify --json` — exit 0; pinned Levain cache verified
  offline.
- `python -m harness rescore-history` — four retained reports scored; all status
  `PASS`.
- Oracle source validation — 181 checked items, 181 matching blobs, 25 commits.
- CLI help — `experiment`, `rescore-history`, benchmark environment and stress
  profile options parsed successfully.

Focused regression coverage includes known positives, reviewed negatives,
informative references, duplicates, ambiguous source occurrences, missing
hashes, mismatched values, unknown paths, bad commits, later snapshots,
historical renames, truncated rescore input, and complete accounting.

## 3. Oracle expected/matched/missed results

Owner-approved denominator: **65 source occurrences / 53 unique credential
groups**, plus 86 reviewed negatives and 30 informative references. The 175
filesystem items are not used for history.

| Scanner | Product | Findings | Occurrences | Unique groups | Occurrence recall | Unique recall | Duplicates | Informative | Verified FP | Unmatched | Unverified |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Gitleaks `5f6ec56` | Windows AMD64 native | 26 | 21 / 65 | 15 / 53 | 32.31% | 28.30% | 3 | 2 | 0 | 0 | 0 |
| Gitleaks `5f6ec56` | Docker Linux AMD64 | 26 | 21 / 65 | 15 / 53 | 32.31% | 28.30% | 3 | 2 | 0 | 0 | 0 |
| Betterleaks `5eab483` | Windows AMD64 native | 41 | 36 / 65 | 28 / 53 | 55.38% | 52.83% | 3 | 2 | 0 | 0 | 0 |
| Betterleaks `5eab483` | Docker Linux AMD64 | 41 | 36 / 65 | 28 / 53 | 55.38% | 52.83% | 3 | 2 | 0 | 0 | 0 |

Missed occurrences: 44 (Gitleaks) and 29 (Betterleaks). Native/Docker evaluation
multisets are identical for each scanner (70 evaluations each, zero differences).
The two informative matches per scanner are AWS access-key identifiers; they earn
no primary recall.

**Precision and F1 are `null`** and
`precision_certification_status=BLOCKED_INCOMPLETE_NEGATIVE_ORACLE` because the
86 reviewed negatives are explicitly not exhaustive. No certified precision/F1
claim is made.

Evidence:

- [history summary](../../reports/history/README.md)
- `reports/history/gitleaks-5f6ec56-native-history.json`
- `reports/history/gitleaks-5f6ec56-docker-amd64-history.json`
- `reports/history/betterleaks-5eab483-native-history.json`
- `reports/history/betterleaks-5eab483-docker-amd64-history.json`

## 4. Unknown and unverified findings requiring investigation

Current retained reports have **0 unmatched and 0 unverified findings**. The
ledger is nevertheless active and tested for both states; every finding is
accounted for (26/26 and 41/41). Any future unmatched or unverified observation
is retained with safe path/line/hash evidence and a review reason, and blocks
precision/F1 certification.

The current four missing-category clusters are documented as misses rather than
hidden: WordPress application secrets (8), FileZilla encoded passwords (2),
SMTP password (1), SSH passphrase (1), JetBrains obfuscated password (1), and
various application/database placements. They remain source-oracle misses, not
false negatives invented by a path-only matcher.

## 5. Outstanding scoring limitations

1. **No certified history precision/F1.** The reviewed negative inventory is
   intentionally non-exhaustive. This is a source-truth limitation, not a
   temporary implementation gap.
2. **Retained-report rescoring, not a new scanner execution.** The evidence uses
   normalized findings captured by CP3. No scanner was rebuilt or rerun for this
   checkpoint.
3. **JetBrains decoded equivalence.** Only the validated encoded source attribute
   is credited. A scanner that hashes an independently decoded JetBrains value is
   not credited unless a validated derivation is added.
4. **Strict line/span locality.** A later observation is credited only when the
   approved source range at that commit still contains the representation. Large
   line drift without a source review is not silently mapped.
5. **Benchmark environment execution.** The environment architecture is
   implemented and tested, but no new `CONTROLLED`/`RELEASE` measurement or
   stress run was performed in this contended DEV session. Existing CP3
   performance evidence remains version-1 evidence.
6. **No ARM64 rerun.** Native Windows and Docker AMD64 history evidence is
   covered; emulated/native ARM64 is not claimed.
7. **No source-built scanner rerun.** The retained CP3 reports are used only for
   offline rescoring; current source-build conformance is covered by earlier
   evidence and unit/integration tests.

## 6. Known scanner weaknesses observed

- **Gitleaks `5f6ec56`**: 21/65 occurrences and 15/53 unique groups. It misses the
  MongoDB URI, several `.env` credentials, WordPress salts, FileZilla Base64,
  SMTP, SSH, JetBrains, and multiple application/database placements. Its
  `.s3cfg` access-key identifier is informative, not a credential TP.
- **Betterleaks `5eab483`**: 36/65 occurrences and 28/53 unique groups. It covers
  more environment/API/application placements, including the MongoDB URI and one
  PEM block with terminal-newline normalization, but still misses all eight
  WordPress salts, FileZilla, SMTP, SSH, JetBrains, and several database values.
- Neither scanner produced a verified false positive in the retained history
  findings.
- Both scanners report AWS access-key identifiers as separate informative
  observations; those are not counted as primary detections.

These are scanner observations, not benchmark-tuned truth changes. No scanner
source or rule was modified.

## 7. Remaining work and proposed next checkpoint

1. Owner review of the source matcher, representation policy, retained evidence,
   and the investigation ledger before accepting history scores.
2. Re-run a source-built Gitleaks and Betterleaks experiment with the integrated
   suite so history execution and scoring are exercised end-to-end in a fresh
   report, rather than only by rescoring retained findings.
3. Execute a documented `CONTROLLED` performance run on a reduced-contention host
   and record the host conditions; reserve `RELEASE` for pinned artifacts,
   default configuration, controlled hardware and publishable evidence.
4. Add optional stress-driver support only after the controlled host and
   methodology are assigned.
5. Keep `rnclab` unregistered until its finalized manifest, oracle validation,
   execution integration and tests exist.
6. Consider reviewed line-drift handling and a validated JetBrains decoded
   representation as separate, explicitly tested changes.

## 8. Deliverables

- New history oracle loader, matcher and offline rescore command.
- Integrated Leaky Repo history scoring with complete accounting.
- Explicit line-only policy and sanitized metadata projection.
- Benchmark environment profiles, coverage fields and drift comparison.
- Four committed redacted history evidence documents.
- Updated architecture, scoring, history, performance, roadmap and README
  documentation.
- 246 passing tests.
