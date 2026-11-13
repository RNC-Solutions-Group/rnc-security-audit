# RNC Gitleaks Docker Acceptance

> **Vendored Docker lane.** The consolidated entry point is
> `python -m harness consolidate ...`. To run this lane directly, pass
> `--fixture-root <pinned cache source>` and `--fixture-revision
> 5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c`; the fixture cache is prepared by
> `harness.fixtures`. The legacy examples below describe the original standalone
> layout; its image is now built from the target source by the consolidated
> orchestrator.

```text
RRRRR  N   N  CCCCC
R   R  NN  N  C
RRRRR  N N N  C
R  R   N  NN  C
R   R  N   N  CCCCC
RNC Solutions Group, Inc.
Turning Complexity into Clarity.
www.rncsolutionsgroup.com
```

Contributed by: Dave Woods (@davidwoods15)

This standard-library Python harness executes Gitleaks CLI acceptance cases inside an operator-supplied local Docker image. It never builds, pulls, retags, or removes the Gitleaks image, and it does not replace Gitleaks' Go test suite. For symlink staging, Docker may pull the small `alpine:3.24` helper if it is not already local.

## Requirements

- Python 3.11 or newer.
- Docker CLI and a running Docker Engine or Docker Desktop daemon.
- The desired Gitleaks image already present locally.
- A repository checkout containing the upstream `testdata/` fixtures.

The harness uses only Python's standard library. On Windows, Docker Desktop must be able to bind-mount the checkout. WSL2 users should run from a WSL checkout when possible. Native Linux uses the same commands and stable in-container paths.

## Run

```powershell
python _rnc-build/validate.py --image gitleaks:release-latest
```

```sh
python3 _rnc-build/validate.py --image gitleaks:release-latest --scenario-group files
python3 _rnc-build/validate.py --image gitleaks:pr2308mod \
  --compare-to _rnc-build/reports/runs/<release-execution-id>/execution.json
python3 _rnc-build/validate.py --image gitleaks:rnc-base \
  --compare-to _rnc-build/reports/runs/<release-execution-id>/execution.json
python3 _rnc-build/validate.py --image gitleaks:release-latest \
  --scenario-group archives --scenario-group git
python3 _rnc-build/validate.py --image gitleaks:release-latest --scenario-group symlinks
```

Each run gets an immutable `_rnc-build/reports/runs/<execution-id>/` directory containing `execution.json`, `execution.md`, `fixture-assertions.json`, and `fixture-exclusions.json`. Phase 1 reports at the top level remain untouched. Use `--reports-dir` to select another destination. The report records manifest version 2 and harness version 2.4.0.

Generate cumulative reports from saved runs:

```sh
python3 _rnc-build/aggregate.py --reports-dir _rnc-build/reports \
  --image-id sha256:<immutable-image-id>
```

Omit `--image-id` to produce separate aggregates for every compatible image/manifest/revision group. Inspect a run's complete exclusions with:

```sh
python3 _rnc-build/exclusions.py _rnc-build/reports/runs/<execution-id>/execution.json
```

Run the harness's pure logic self-tests with `python _rnc-build/test_evidence.py`. `--scenario-group` may be repeated; unselected scenarios remain `NOT RUN` and their applicable fixtures appear in exclusions.

The harness inspects the image ID, platform, entrypoint, tags, digests, and labels, then executes Gitleaks containers with `--pull=never --network none`. Fixture/config mounts and scan workspaces are read-only inside each Gitleaks container. CLI JSON is parsed in memory; raw report output is not written to disk. Reports contain secret hashes, sanitized finding fields, exit codes, and output hashes, not raw secret values.

Exit codes are `0` for complete pass, `1` for an acceptance failure, and `2` for an incomplete run or a reported build failure. An unavailable local image is `NOT RUN`/`INCOMPLETE`; it is not assumed to be a build failure. The harness does not build images. To record a known external build failure without executing Docker, use `--build-failed`; reports then use `BUILD FAILED` and mark every case unexecuted. Build failures are never presented as Gitleaks functional failures.

## Architecture

- `validate.py` owns Docker invocation, image metadata, fixture staging, scenario execution, assertion generation, and per-run reports.
- `cases.json` defines scenarios, independently sourced expectations, and inventory rules.
- `evidence.py` contains pure finding comparison, assertion, exclusion, and aggregate logic.
- `aggregate.py` writes image-scoped cumulative JSON/Markdown; `exclusions.py` prints an execution or aggregate exclusion register.
- `test_evidence.py` self-tests failure detection, coverage unions, image/manifest isolation, and historical failures.
- `fixtures/` contains synthetic format, encoded, clean, and baseline inputs.
- `reports/runs/` contains immutable per-execution evidence; `reports/aggregates/` contains cumulative image-scoped evidence.

All container paths are stable under `/rnc/testdata`, `/rnc/local`, and `/rnc/work`. Git history/staged cases copy the upstream `dotGit` fixture to `_rnc-build/.work*/`, restore it as `.git`, and mount the staged copy read-only. The small Git fixture has stale remote-tracking metadata; only those remote refs are removed from the disposable copy. Local branch refs and commit objects remain intact.

For symlink scenarios, the runner reads the symlink mode and target from the exact fixture source revision, creates a uniquely named temporary Docker volume, copies `testdata` into it with `alpine:3.24`, recreates the link from that Git blob, verifies `test -L`, target resolution, and the relative target, then mounts the volume read-only at `/rnc/testdata` for the network-isolated Gitleaks scan. Only the volume created by that execution is removed. No host Windows symlink semantics or preexisting named volume are required. The helper image may be pulled if unavailable; the Gitleaks image under test is never pulled.

## Expected Results

Expected findings are explicit in `cases.json`; they are not learned from the image under test. Expected file paths, rule IDs, commits, and locations are based on upstream test assertions. Secret values are represented by SHA-256 hashes. The encoded-value and common-format inputs are synthetic adaptations of existing test patterns, with their expected rule and location defined in the manifest.

The harness compares findings individually. Matching uses rule, normalized file, commit, location, and secret hash; remaining field differences are reported as changed findings. `--compare-to` compares each case's observed findings with another run's observed findings and records removed, added, and changed findings. A baseline comparison is informational and does not override the explicit manifest expectations.

The execution fixture ledger records every matched fixture with a stable ID, origin, source revision, type, purpose, expected behavior, applicable scenarios, required assertion IDs, validation method, classification, and coverage status. `ASSERTABLE` fixtures need passing fixture-specific assertions; `EXERCISED` fixtures were encountered but lack such proof; `SUPPORTING` fixtures provide inputs/metadata; `INTERNAL_GO` records the responsible upstream test and remains pending until verified Go-test evidence is executed or imported; `UNSUPPORTED` and `UNTESTED` remain excluded and visible. Directory scenario bundles are separate from physical file inventory entries.

Scenario counts, assertion counts, Docker-applicable fixture counts, internal Go-test contract counts, and validated fixture counts are separate. A directory scan alone does not validate all members. For example, the clean negative case requires both zero findings and a trace event naming the file. The baseline fixture is synthetic and derives its finding fields from the upstream plain-file test contract, not from release-image output. A functional PASS with incomplete fixture or Go-test coverage is reported as `OVERALL ACCEPTANCE: NOT COMPLETE`.

The official release image is only a behavioral parity comparator. Both images still run against the same explicit manifest expectations. In a comparison, unsupported/unexecuted cases are `N/A`, never zero differences.

## Known Limitations

- `testdata/repos/nogit/api.go` is byte-identical to `main.go`; the fixture `.gitleaksignore` suppresses its exact `api.go:aws-access-key:20` fingerprint. Relative source paths preserve the fingerprint, while `main.go` remains a required positive finding.
- Symlink staging reconstructs the committed mode-`120000` link from Git metadata in a temporary Linux volume. The scan is read-only and network-isolated; the temporary volume is removed after the scenario.
- The four CP4 source fixtures (`api/api.go`, `api/ignoreCommit.go`, `api/ignoreGlobal.go`, and `README.md`) are validated by path-filtered Git CLI scenarios with path/commit-scan or exact suppression-trace assertions. Other Git-history content without a fixture-specific assertion remains `EXERCISED` and visible in exclusions.
- The complete valid/invalid config translation matrix, baseline matching internals, CSV/SARIF/JUnit/custom-template serializers, and archive-bearing Git history remain `INTERNAL_GO` or `SUPPORTING`. Their responsible Go tests are listed in each fixture record; no Go-test results are claimed by these Phase 2 runs.
- Phase 2 execution is on Windows 11 with Docker Desktop/WSL2 Linux containers. A native Linux Docker Engine run is still a follow-up; this is not a native Windows container test.

## Reproducibility and CI

Reports record the exact requested tag, immutable image ID/digests, runtime version, fixture-source revision, manifest digest/version, harness version 2.4.0 and implementation identity, source commit, host/daemon platforms, scenario definitions, assertion outcomes, fixture-level statuses, sanitized findings, exit codes, and stdout/stderr hashes. Aggregates use the union of validated fixture IDs and keep image, manifest, fixture revision, harness version, and implementation identity separate. Any historical failed assertion remains unresolved even if a later execution passes.

## Inventory Lock

`fixture-inventory.lock.json` is the pinned full file inventory derived from `cases.json`, the upstream source revision, and discovered files under `testdata/` and `fixtures/`. Each physical record carries a content hash; upstream Git symlinks also carry their Git mode, blob ID, and link target so Windows checkout representation does not erase their Linux semantics. Scenario bundles are hashed from their physical child records and are not counted as physical files.

Normal execution and aggregation fail closed if the current manifest, source revision, discovered paths, fixture hashes, or lock entries differ. To accept an intentional upstream fixture or manifest change, review the inventory diff, update/justify manifest rules (including any explicit overlapping-glob `override`), then run `python _rnc-build/validate.py --refresh-inventory-lock` and commit the reviewed lock together with the manifest change. Do not refresh solely to clear an integrity error.

The runner records a SHA-256 harness implementation identity over the execution, evidence, lock, aggregation, and exclusions modules. Aggregation requires the exact image ID, manifest digest/version, fixture source revision, inventory digest, harness version, and implementation identity. It recomputes inventory membership independently and reconciles every incoming execution before counting successful fixture assertions.

For future CI, add a small Linux job that builds a disposable test image and runs this curated manifest, then publishes the JSON/Markdown reports as artifacts. Keep the established Ubuntu/Windows Go test matrix unchanged. Do not publish or retag an image as part of this harness.