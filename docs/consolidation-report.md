# Consolidation report — Docker harness and executable harness

**Branch:** `test/scan-harness`
**Authorized work:** consolidate the legacy Docker acceptance harness with the
CP1A executable harness. CP2 was not started.
**Legacy reference:** `work/docker-legacy/` (temporary, not committed) and
`review/_rnc-build/`.

## Outcome

The Docker acceptance harness was migrated into the harness package and placed
behind one target-acquisition and orchestration flow:

```text
python -m harness consolidate \
  --repo https://github.com/RNC-Solutions-Group/gitleaks \
  --branch master --targets both
```

One disposable checkout of the resolved commit is used for:

1. the native executable build;
2. the Docker image build;
3. branch-specific Go tests.

The three test lanes then run sequentially: Go tests, pinned Docker fixtures,
and Levain. Each lane reports independently and a consolidated summary is
written.

The first consolidated run resolved `master` to
`5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` and produced:

| Lane | Result |
| --- | --- |
| Branch Go tests | `PASS` — 270 tests passed, 0 failed, 2 skipped, 7 packages |
| Pinned Docker fixtures | `FUNCTIONAL_PASS_COVERAGE_INCOMPLETE` — **23 scenarios, 147 assertions, 33 Docker-applicable fixtures**; functional `PASS`, coverage `INCOMPLETE` |
| Levain | `COMPLETED` — negative 3 false positives; positive 47/85 TP, 1 partial, 2 duplicates |
| Consolidated | `COMPLETE_WITH_LIMITATIONS` |

The Docker-only target path was also exercised: Levain executed through the
built image and reproduced 47/85 TP with 3 negative-corpus findings.

The full Python suite is **124 tests, OK** after the CP1B follow-up.

## CP1B follow-up

The matrix was extended after the initial consolidation. CP1B added:

- native-executable execution of the portable pinned scenarios (22/22 applicable
  pass on Windows; the Linux-only symlink scenario is `NOT_APPLICABLE`, with 141
  native assertions);
- independent Levain execution through both adapters when `--targets both` is
  selected;
- separate executable/Docker results and cross-target fixture/Levain comparisons;
- canonical `PASS`, `FAIL`, `BLOCKED`, `NOT_RUN`, and `NOT_APPLICABLE` lane
  statuses, including partial target-build handling;
- a named-test audit of all 75 `INTERNAL_GO` contracts: 71 mapped (55 passing,
  16 skipped on Windows) and 4 unmapped; package-level success is never used as
  fixture evidence.

The Docker parity remains **23/23 scenarios, 147/147 assertions, 33/33
Docker-applicable fixtures**. See the
[CP1B report](checkpoints/CP1B-report.md) for the matrix results and evidence.

## CP1C follow-up

CP1C replaced the monolithic Gitleaks orchestration path with a scanner-adapter
and suite architecture. The legacy `consolidate` command remains as a
compatibility path, while `python -m harness matrix` and the interactive CLI use
the new adapter/suite matrix. The Python suite grew to **161 tests, OK**. Leaky
Repo was pinned and integrated as a count-based filesystem benchmark. See the
[CP1C report](checkpoints/CP1C-report.md) and
[architecture](architecture.md).

CP1D subsequently removed the active Go-test suite and build-only macOS/native
Linux matrix entries, replaced shared scoring with a scanner-independent engine,
added a 175-item Leaky Repo truth manifest with dual legacy/RNC scores, and
validated the engine with 25/25 independent synthetic cases at 100% accuracy.
See the [CP1D report](checkpoints/CP1D-report.md) and
[scoring contract](scoring-contract.md).

CP1E finalized finding-level synthetic validation, added controlled Git-history
scoring and Leaky history observation, and separated a real performance benchmark
from detection scoring. See the [CP1E report](checkpoints/CP1E-report.md),
[history accountability](history-accountability.md), and
[performance methodology](performance-methodology.md).

Evidence:

- [consolidated-5f6ec56.json](../reports/consolidated/consolidated-5f6ec56.json)
- [consolidated-5f6ec56.md](../reports/consolidated/consolidated-5f6ec56.md)
- JSON SHA-256: `dbbaec506dc768e333ea6ac127dee8e6dd46ab1904fd9add5636fd3dcd9a0718`
- Markdown SHA-256: `6d7ab079bde6d0eb0861b9d2a20ed85a4562d80faf51db8b03f51b95939877b1`

CP1B matrix evidence (supersedes the single combined report for execution-matrix
questions):

- [cp1b-both.json](../reports/consolidated/cp1b-both.json)
- [cp1b-both.md](../reports/consolidated/cp1b-both.md)
- [cp1b-executable.json](../reports/consolidated/cp1b-executable.json)
- [cp1b-docker.json](../reports/consolidated/cp1b-docker.json)

## Target acquisition

`harness/targets.py` implements:

- `git ls-remote --heads` resolution of a user-supplied branch to a full
  40-character commit SHA;
- a revision-addressed cache at
  `datasets/cache/targets/<repository-key>/<sha>/source`;
- checkout and immutable-commit verification;
- one checkout reused by both builds and the Go-test lane;
- `go build -mod=readonly -trimpath -buildvcs=true`;
- `docker build` from a source tree with the upstream `Dockerfile`;
- `go test -mod=readonly -json ./...` with test/package accounting.

The Dockerfile derives its version from `git describe`. The disposable target
checkout receives a local semver tag
`v8.0.0-rnc.<12-char-sha>` when no valid tag exists; no source file is changed.
The built image version was `v8.0.0-rnc.5f6ec56cfa6f`.

Build identities for the baseline:

| Target | Identity |
| --- | --- |
| Source | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |
| Executable SHA-256 | `e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2` |
| Docker image | `gitleaks-consolidated:5f6ec56cfa6f` |
| Docker image ID | `sha256:e9e096883b0f956e40625c08cb2040e616551a849763b83c712efa59f2da1044` |
| Image platform | `linux/amd64` |

## Fixture acquisition and cache

`datasets/gitleaks-fixtures.toml` pins the complete external fixture source to
`5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c`, independent of the branch being
evaluated. `harness/fixtures.py`:

- clones that revision into
  `datasets/cache/gitleaks-fixtures/<sha>/source` (Git-ignored);
- requires the checkout HEAD to equal the pin;
- rejects a modified working tree;
- verifies the MIT license hash;
- verifies `cases.json` and `fixture-inventory.lock.json` hashes;
- rebuilds the 228-entry inventory from the pinned checkout and verifies every
  content hash, Git mode/blob ID, symlink target, scenario bundle, and the
  composed inventory digest;
- reuses the verified cache offline.

Verified fixture facts:

| Metric | Value |
| --- | --- |
| Source revision | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |
| Inventory entries | 228 |
| Physical fixture records | 223 |
| Scenario bundles | 5 |
| Docker-applicable fixtures | 33 |
| Git symlinks | 1 (`testdata/repos/symlinks/file_symlink/symlinked_id_ed25519`) |
| Inventory digest | `cd7f05e76b4590ee738d4573f3ddb3c493142ecd1204bc15754a21d0e66f7345` |
| Lock SHA-256 | `1c902f60c3c0aeee43fc32e55e61475362e87467673d20ed460cab236724c507` |

The legacy Docker scenarios still consume `testdata/` from this cache, not from
the target checkout. Symlink reconstruction and Git-fixture staging continue to
read the pinned Git blobs and `dotGit` metadata.

## Reused, replaced, retired

### Reused

- `validate.py` Docker invocation, image inspection, fixture staging, scenario
  execution, assertion generation, and per-run reports.
- `evidence.py` finding comparison, assertion, exclusion, and aggregation logic.
- `inventory_lock.py` lock construction and fail-closed integrity checks.
- `aggregate.py` and `exclusions.py` retained as importable modules.
- `cases.json`, `fixture-inventory.lock.json`, synthetic `fixtures/`, and the
  28 legacy self-tests.
- CP1A executable runner, Gitleaks report parser, strict scorer, control
  validation, redaction, and Levain dataset cache.

### Replaced

- The legacy fixed `REPO_ROOT = BUILD_DIR.parent` assumption is replaced with
  `--fixture-root` / `GITLEAKS_FIXTURE_ROOT`, pointing at the pinned cache.
- The legacy merge-base fixture-revision discovery was replaced for consolidation
  by an explicit `--fixture-revision`; the consolidated runner always passes the
  pin.
- The legacy assumption that an operator supplies an already-built image is
  replaced for consolidation by building the image from the same target source
  as the executable and Go tests.
- The invalid `rnc-consolidated-*` Docker version tag used during bring-up was
  replaced by a valid semver tag; the failure was not suppressed.

### Retired

- The temporary `_rnc-build` path is no longer the runtime location.
- Legacy `_rnc-build/.work*`, raw reports, and copied reference directories are
  not committed.
- `work/docker-legacy/` is migration reference material only and is ignored.
- No legacy asset or branch was deleted.

## Docker parity assessment

The legacy full Docker run and the consolidated run both report:

| Metric | Legacy reference | Consolidated |
| --- | --- | --- |
| Scenarios | 23 | 23 |
| Scenarios passed | 23 | 23 |
| Assertions | 147 | 147 |
| Assertions passed | 147 | 147 |
| Docker-applicable fixtures | 33 | 33 |
| Docker-validated fixtures | 33 | 33 |
| Functional result | PASS | PASS |

The Docker-applicable count is the 38 `ASSERTABLE` records minus the 5 scenario
bundles; physical records remain separately counted.

**Variance:** both the legacy reference and the consolidated run report
`COVERAGE RESULT: INCOMPLETE` and `OVERALL ACCEPTANCE: NOT COMPLETE` because
`INTERNAL_GO` fixture contracts are not fully evidenced. This is expected and was
not changed to obtain a pass. CP1B subsequently mapped 71 of the 75 contracts to
named Go tests or subtests (55 passing, 16 skipped on Windows); 4 remain unmapped.
The branch Go-test lane still passes independently (270 tests), and package-level
success is never used as fixture evidence.

Docker isolation and identity were preserved:

- `--pull=never`, `--network none`, read-only fixture/local mounts;
- image ID, platform, entrypoint, tags, and labels inspected;
- symlink volume reconstruction;
- raw report output parsed in memory and not committed.

## Functional vs internal-Go evidence

The consolidated report keeps these separate:

- **Pinned external fixtures** (Docker lane) — 23 scenarios and 147 assertions
  pass; 33 Docker fixtures validated.
- **Branch-specific Go tests** — 270 passed, 0 failed, 2 skipped; reported only
  as a Go-test lane.
- **Synthetic RNC acceptance** — Docker scenarios and synthetic `fixtures/`.
- **Levain** — independent synthetic corpus, 47/85 TP at the pinned default
  configuration, reproduced through native and Docker adapters.

CP1B additionally audits the 75 `INTERNAL_GO` contracts against named Go tests or
subtests. A package-level pass is not accepted as fixture evidence. The current
mapping is 71 contracts (49 direct, 6 indirect extension-base, 16 parent
`TestFromGit` contracts), with 55 passing and 16 skipped on Windows; 4 contracts
remain unmapped.

## Limitations and unresolved findings

- Docker fixture coverage is incomplete until every `INTERNAL_GO` contract is
  independently evidenced. CP1B mapped 71 of 75; 4 remain unmapped
  (`baseline.json`, one unreferenced invalid config, and two commented-out
  expected Git snapshots), and 16 are skipped on Windows.
- Docker execution was exercised on Windows 11 + Docker Desktop/WSL2
  (`linux/amd64`), not a native Linux Docker Engine.
- The Docker image is locally built and not a release artifact; it is identified
  by image ID and target SHA.
- Fixture acquisition uses the RNC repository at the pinned SHA. The upstream
  project is the same source lineage, but this migration does not claim an
  independent upstream mirror comparison.
- The corpus is synthetic; Levain numbers are not real-world prevalence.
- Functional conformance and performance lanes remain separate.
- `aggregate.py`/`exclusions.py` are retained and importable but are not yet
  exposed as consolidated CLI subcommands.

## CP2 readiness

The consolidated harness is ready for review. CP1B completed the executable/Docker
matrix and the named-test evidence audit; the remaining coverage limitation is the
4 unmapped and 16 Windows-skipped `INTERNAL_GO` contracts, not harness execution.
CP2 must not begin without separate authorization.

**Stop after CP1B. Awaiting review before deleting legacy assets or branches.**
