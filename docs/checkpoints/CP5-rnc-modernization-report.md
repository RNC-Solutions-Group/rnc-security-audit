# CP5 — RNC Scanner adapter modernization and integration

**Branch:** `test/scan-harness`
**Starting harness HEAD:** `ae36fa178a57c8144d3ad3b854ed81161a4feee0`
**Ending code HEAD:** `5e76e3a5ad022748372ee8f3309919838a23191b`
**Pinned scanner source:** `RNC-Solutions-Group/rnc-security-audit` at
`93b4dda909cb3b41606a4d0f36c8ef9d06b77fde` (`feat(cp4a): harden evidence,
private reports and delivery`)
**Status:** Implemented, tested, and documented; awaiting owner review. No merge,
rebase, force-push, worktree, branch change, or unrelated-repository change was
performed.

## 1. Baseline and scope

The working tree was clean on `test/scan-harness` at the required starting
`ae36fa1`. I reviewed the CP4 scoring/oracle implementation and checkpoint
documentation and ran the relevant pre-change regressions:

- `tests.test_adapters`;
- `tests.test_history_suite_integration`;
- `tests.test_suites`;
- `tests.test_scoring_engine`;
- `tests.test_performance`.

All 59 pre-change tests passed. I did not modify the scoring implementation,
historical matcher, oracle, truth loaders, contracts, approved truth, or scoring
policies.

## 2. Pinned source, build, and default configuration

The scanner was fetched at the exact required commit and built from a disposable
checkout. The experiment's source checkout verified HEAD and the official GitHub
repository URL.

| Fact | Value |
| --- | --- |
| Engine version | `0.1.0` |
| Rule bundle | `rules/rnc-providers-v1.json` |
| Ruleset | `rnc-providers-v1` `2026.11.4` |
| Rules / families | 37 / 22 |
| Component extractor | `database-uri-password` |
| Rule file SHA-256 | `87d7f9051ae41df34df29a0d5447ee8c9d71854ada46b789c9b7a00e4320a73a` |
| Canonical ruleset digest | `sha256:dc1ab16f64a5dfb91262b46f321a9f5b219a13ed3bfb49e0f79c067de40bbc0f` |
| Native executable SHA-256 | `e6ee7be57e156ca8272677d75e511d7bf9d536d2aaf779df41daa0d089b61ecc` |
| Docker image ID | `sha256:27aea2a7304230730c2859ba493cb3b99f60e886a9d25b22e86cbf2db47e4bf8` |
| Dockerfile SHA-256 | `edbe1662616484adade693e2916bd765d198216f39c2cf4d008e57176ce62903` |
| Native build duration | 75.436 s |
| Docker build duration | 87.018 s |

Native and Docker products both reported `history_capability: true`. The native
build duration is not included in scanner runtime.

The adapter reads the ruleset from the pinned checkout rather than hardcoding a
count or digest. It records rule count, family count, optional component
extractors, file SHA-256, ruleset ID/version, and the digest independently
recomputed with `rnc rules validate --strategy auto`.

## 3. Capability and execution changes

`RNCAdapter` now supports:

- `supports_mode("dir")` unchanged;
- `supports_mode("git")` verified from the pinned CLI source after build;
- native `rnc scan --history --ref HEAD ...`;
- Docker `rnc scan --history --ref HEAD ...`;
- `--ref HEAD` rather than RNC's broader default all-local-refs scope, preserving
  the independently established 25-commit Leaky Repo history scope. A default
  all-refs test produced 26 commits / 183 units; the required pinned scope is
  25 commits / 166 changed-path revisions.
- report destinations outside the scanned root;
- read-only Git acquisition;
- native/Docker environment isolation and preserved exit/result semantics.

Ordinary filesystem scans never add `--history`. `--history` is emitted only for
`mode="git"`.

### Docker history runtime

The runtime image installs `git` and configures system-level
`safe.directory`; the source repository is bind-mounted read-only including
`.git`, the output directory is separate, `--network none` is used, the root
filesystem is read-only with a writable `/tmp`, and the scanner is run under
native RNC entrypoint semantics. The full Docker historical scan succeeded; a
version-only smoke test was not accepted as proof.

## 4. Private report and source identity

The adapter consumes the private `rnc-cp2-output-v1` envelope, not the public
sanitized report. It joins findings to `execution.units` through `unit_id` and now
validates:

- execution state, evidence validity, result classification, CI exit agreement;
- unit-id format and uniqueness;
- canonical relative locators and source kinds;
- `working_tree_file` filesystem units;
- `git_commit_blob` history units with
  `commit/<40-character-lowercase-oid>/<repository-relative-path>`;
- repository-relative nested paths, with traversal, absolute paths, drives,
  backslashes, empty segments, short OIDs, and malformed locators rejected;
- mixed source kinds rejected;
- finding `line`, `line_end`, `start_byte`, `end_byte`, and evidence digests.

Historical attribution is never inferred from HEAD, a filename, or another
scanner. The exact OID and repository-relative path come from the validated unit
locator. The retained private report has 166 `git_commit_blob` units and 61
findings, all joined to source units.

## 5. Structured database-password evidence

The adapter validates `structured_evidence.version = "1"` and joins each
`database-password` component to its exact parent finding and unit. It checks:

- supported component kind/version;
- exact `finding_id` and `unit_id` ownership;
- component byte range inside the parent contextual span;
- line/line_end inside the parent line span;
- SHA-256 syntax for source and normalized digests;
- supported `ansi` values and the bounded `ansi-sgr-v1` normalization contract;
- consistent no-ANSI evidence;
- one component per finding; duplicate/multiple components are explicit errors;
- no second primary finding is created.

For a valid component, the normalized password digest becomes
`NormalizedFinding.secret_sha256`; the original contextual URI digest remains in
`match_sha256` and `metadata.contextual_secret_sha256`. Component source digests
and component byte offsets are not written to the sanitized finding projection.
The current scanner supplied exactly one database-password component for the
Leaky Repo database URI, and it correctly normalized to the owner-approved
`DATABASE_URI_CREDENTIAL` password identity.

Malformed structured evidence is an explicit report error, not a guessed
normalization. Percent decoding is not performed. ANSI support is limited to the
scanner's bounded SGR contract. A finding with no component retains its contextual
digest faithfully and receives no fabricated password credit.

## 6. Coverage and execution integrity

History coverage is checked separately from filesystem expected-file coverage:

- execution state `COMPLETED`;
- result code 1/2/3 and coverage `COMPLETE`;
- evidence valid, no failure/fatal codes, no timeout/limit/Git-failure markers;
- source adapter `local-git-history`;
- history scope `selected-refs`, refs exactly `["HEAD"]`;
- `history.units_seen` equals execution units;
- 25 commits, matching the approved history-scope manifest;
- all changed commit/path revisions `INSPECTED`;
- required discovered = inspected = every unit;
- no uninspected, blocked, or required-uninspected units;
- ruleset ID and independent digest agreement;
- CI exit/result agreement.

The suite also independently checks `git rev-list --count HEAD` against the
scope's 25 commits. A mismatch or incomplete coverage blocks scoring instead of
creating a misleading clean result. Filesystem `execution_coverage` behavior was
preserved and its tests remain green.

## 7. Actual Leaky Repo results

Command: `python -m harness experiment --scanner rnc --commit
93b4dda909cb3b41606a4d0f36c8ef9d06b77fde --platforms
windows-amd64,docker-linux-amd64 --suites leaky-repo --offline --warmups 1
--runs 3 --copies 1`.

Both products built and the suite completed with status `PASS`
(`COMPLETED_AND_SCORED`).

### Historical denominator

**65 expected occurrences / 53 unique credential groups**, plus 86 reviewed
negatives and 30 informative references. The filesystem 175-item denominator is
not used.

| Metric | Native Windows AMD64 | Docker Linux AMD64 |
| --- | ---: | ---: |
| Observed findings | 61 | 61 |
| Historical commits | 25 | 25 |
| Inspected revisions | 166 | 166 |
| Coverage verified | yes | yes |
| Scope matches approved 25 commits | yes | yes |
| Matched occurrences | 21 / 65 | 21 / 65 |
| Occurrence recall | 32.31% | 32.31% |
| Matched unique groups | 19 / 53 | 19 / 53 |
| Unique recall | 35.85% | 35.85% |
| Duplicates | 13 | 13 |
| Informative matches | 8 | 8 |
| Verified false positives | 0 | 0 |
| Unmatched pending review | 19 | 19 |
| Unverified evidence | 0 | 0 |
| Accounted observations | 61 / 61 | 61 / 61 |

Native and Docker evaluation multisets are identical (105 evaluations each,
zero differences). Precision and F1 are `null` with
`precision_certification_status=BLOCKED_INCOMPLETE_NEGATIVE_ORACLE`; no certified
precision/F1 is claimed.

### Matched historical groups

`SG-002`, `SG-005`, `SG-007`, `SG-008`, `SG-013`, `SG-015`, `SG-020`, `SG-022`,
`SG-037`, `SG-038`, `SG-045`, `SG-048`, `SG-049`, `SG-050`, `SG-057`, `SG-058`,
`SG-071`, `SG-074`, `SG-075`.

### Unmatched investigation ledger

Nineteen findings (ten unique locations) remain pending review and are not counted
as false positives:

- `.leaky-meta/secrets.csv` benchmark metadata lines 46, 48, 67, 69 across
  several changed revisions (8 findings);
- `hub:4` — RNC generic-assignment digest differs from the owner-approved OAuth
  token representation;
- `web/django/settings.py:24` and `web/js/salesforce.js:7`;
- `web/var/www/.env` lines 14 and 33;
- `web/var/www/public_html/config.php:11`.

The `.leaky-meta` path is benchmark metadata, not an approved source occurrence.
The `hub:4` mismatch is retained rather than reclassified as a true or false
positive.

Informative matches: `cloud/.s3cfg:1` AWS access-key identifier across three
snapshot observations, `web/js/salesforce.js:6`, and four Firefox login metadata
entries. Informative references earn no primary recall.

### Filesystem result

The same run also exercised the filesystem benchmark: 29 observed findings,
25/175 rich line-truth matches (23 value-verified, 2 line-only), 2 unexpected
findings retained in the ledger, 27/175 legacy count coverage, and 18/44 files
(15.43%). The filesystem truth is not an exhaustive negative oracle; no
precision/F1 is certified.

### Preliminary performance

DEV profile, one warm-up and three measured filesystem runs on the 61-file
workload:

| Product | Median | Min / max | CV | Stability |
| --- | ---: | ---: | ---: | --- |
| Windows AMD64 native | 0.441 s | 0.403 / 0.467 s | 0.0601 | STABLE |
| Docker Linux AMD64 | 1.354 s | 1.265 / 1.373 s | 0.0354 | STABLE |

These are contended-DEV measurements, not release evidence.

## 8. Tests and validation

Final full suite:

```sh
python -m unittest discover -s tests -t . -v
```

Result: **257 tests passed**, 0 failures, 0 errors (158.574 s, Windows AMD64,
Python 3.13.5).

Coverage includes:

- existing filesystem parsing and empty valid reports;
- native and Docker history argument construction;
- Dockerfile Git-runtime requirement;
- commit/nested path parsing and malformed/traversal locator rejection;
- unknown unit references and mixed/invalid source kinds;
- contextual digest preservation;
- valid database-password component linking and ANSI normalization;
- missing, duplicate, mis-owned, and unsupported components;
- no second finding from a component;
- component digests/offsets absent from sanitized projections;
- coverage rejection for incomplete execution and wrong history scope;
- native/Docker normalized-result parity;
- pinned native historical execution against the real Leaky Repo source, 166
  inspected revisions, 61 findings, 21/65 occurrences, 19/53 groups, 19 unmatched,
  0 unverified, and complete accounting;
- all prior Gitleaks, Betterleaks, scoring, oracle, suite, performance, and
  workspace regressions.

Additional manual validation:

- `rnc --version` → `rnc 0.1.0`;
- `rnc rules validate` → 37 rules, 22-family bundle, digest
  `sha256:dc1ab16f64a5dfb91262b46f321a9f5b219a13ed3bfb49e0f79c067de40bbc0f`;
- native historical scan → 25 commits / 166 units / 61 findings;
- Docker historical scan → same normalized results;
- source `.git` status and HEAD remained unchanged after scans;
- official GitHub source checkout HEAD verified at `93b4dda...`.

## 9. Limitations and scanner observations

1. RNC reports 61 historical findings but only 21 owner-approved occurrences; 19
   findings are unmatched investigation items. This is not suppressed or
   relabeled.
2. RNC misses the AWS secret-key `.s3cfg` component, Docker auth credentials,
   FileZilla Base64 passwords, NPM token, OAuth token (representation mismatch),
   SMTP password, SSH passphrase, WordPress salts, and several other approved
   placements. Category recall is reported in the experiment JSON.
3. `.leaky-meta/secrets.csv` is benchmark metadata; detections there are not
   oracle occurrences.
4. RNC's `hub:4` generic assignment digest does not match the owner-approved
   OAuth token digest; this remains an unmatched observation.
5. History coverage is changed-revision coverage (166 units), not full-snapshot
   coverage. Unchanged snapshots are not invented.
6. Docker history requires Git in the runtime image; the adapter installs it and
   validates a full historical scan, not just `--version`.
7. Structured evidence currently covers database passwords only. ANSI support is
   limited to `ansi-sgr-v1`; percent-decoded passwords are not claimed.
8. History precision/F1 remain uncertified because the reviewed negative set is
   not exhaustive. No expected recall threshold was imposed.
9. Performance remains preliminary/DEV-only with three measured runs. No
   release/controlled performance claim is made.
10. RNC's Git-history locator is private evidence; the adapter preserves the
    source identity but does not expose the complete locator as a public path.

## 10. Compliance statement

- **Scoring implementation unchanged:** no changes to
  `harness/scoring_engine.py`, `harness/history_matching.py`,
  `harness/history_oracle.py`, `harness/truth.py`, `harness/leaky_truth.py`, or
  `harness/contracts.py`.
- **Owner oracle unchanged:** no changes to
  `datasets/leaky-repo.history-oracle.json`, `datasets/leaky-repo.rnc-truth.json`,
  or their classifications/counts.
- **RNC Scanner source unchanged:** the pinned repository was fetched/read and
  built only; its working tree and commit remain unchanged.
- **Default scanner rules unchanged:** the pinned 37-rule / 22-family
  `2026.11.4` bundle was used. No benchmark-specific rule was substituted.
- **No benchmark-specific tuning:** no oracle, scoring, timeout, or rule changes
  were made to improve results.
- **No silent finding suppression:** all 61 parsed findings were passed to the
  existing scorer; 19 unmatched findings are explicitly retained.
- **No fabricated evidence:** missing/malformed structured components are errors
  or remain unverified; the adapter does not infer password evidence from a URI
  alone.
- **No merge, rebase, force-push, or worktree creation.**
- **RNC Lab untouched:** no files under `datasets/cache/rnc-synth-lab/` were
  modified.

## 11. Evidence and remaining work

Evidence:

- [CP5 evidence summary](../../reports/rnc-cp5/README.md)
- [19-finding needs-review manifest](../../reports/rnc-cp5/needs-review.json)
- [Needs-review review table](../../reports/rnc-cp5/needs-review.md)
- `reports/rnc-cp5/rnc-93b4dda-official-93b4dda909cb-default.json`
- `reports/rnc-cp5/rnc-93b4dda-official-93b4dda909cb-default.md`
- `tests/test_adapters.py`
- `tests/test_rnc_history_execution.py`

Remaining work:

1. Owner review of RNC's 19 unmatched historical findings and the
   `.leaky-meta/secrets.csv` metadata detections.
2. Determine whether `hub:4` is a scanner representation defect or a benign
   non-credential assignment; do not change scoring to resolve it.
3. Review the Git/runtime image tradeoff and `safe.directory` policy before
   production use.
4. Consider adding RNC structured-evidence support for additional component kinds
   only when the scanner publishes a versioned contract for them.
5. Run controlled/release performance measurement separately; the current
   evidence is DEV-only.
