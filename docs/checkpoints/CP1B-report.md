# CP1B report — unified execution matrix and evidence mapping

**Checkpoint:** CP1B, executed under explicit authorization.

**Branch:** `test/scan-harness` (orphan).

**Starting HEAD:** `fe91644df3589551c77befc54a4f592e121ea5cb`.

**Scope:** complete the executable/Docker execution matrix without regressing the
23/147/33 Docker parity baseline, and audit the 75 `INTERNAL_GO` fixture
contracts. CP2 was not started.

## Outcome

| Requirement | Result |
| --- | --- |
| `--targets executable` runs every executable-applicable lane | **PASS** |
| `--targets docker` runs every Docker-applicable lane | **PASS** |
| `--targets both` runs the matrix against both targets | **PASS** |
| Levain runs independently through both adapters for `both` | **PASS** |
| Native executable fixture testing is implemented | **PASS** — 22/22 applicable scenarios; 1 Linux-only symlink `NOT_APPLICABLE` on Windows |
| Docker-only scenarios/assertions stay Docker-only | **PASS** — all 23/147 preserved; one container-path assertion and Linux symlink staging are not forced onto the native host |
| Statuses distinguish `PASS`, `FAIL`, `BLOCKED`, `NOT_RUN`, `NOT_APPLICABLE` | **PASS** |
| Separate target results and cross-target comparisons | **PASS** — 22 shared scenarios identical, 0 differences, 1 not comparable |
| Docker parity preserved | **PASS** — 23/23 scenarios, 147/147 assertions, 33/33 Docker-applicable fixtures |
| `INTERNAL_GO` contracts reviewed against named Go tests | **71/75 mapped**; 55 passing, 16 skipped on Windows, 4 unmapped; 0 failed |
| Tests cover all three target selections and partial build failures | **PASS** — 3 target-selection tests, 3 partial-build tests |
| External fixture revision unchanged | **PASS** — pinned `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |

The pinned run overall is `COMPLETE_WITH_LIMITATIONS`: all applicable execution
lanes pass, but four `INTERNAL_GO` contracts have no named executing test and
sixteen mapped contracts (the `TestFromGit` archive fixture family) are skipped
on Windows.

## Matrix results at `5f6ec56`

| Lane | Executable-only | Docker-only | Both |
| --- | --- | --- | --- |
| Branch Go tests | `PASS` — 270/0/2, 7 packages | `PASS` — same source lane | `PASS` — same source lane |
| Native fixtures | `PASS` — 22 applicable passed, 1 `NOT_APPLICABLE`, 141 assertions | `NOT_APPLICABLE` | `PASS` — 22 applicable passed, 1 `NOT_APPLICABLE`, 141 assertions |
| Docker fixtures | `NOT_APPLICABLE` | `PASS` — functional; 23/147/33 parity; coverage `INCOMPLETE` | `PASS` — functional; 23/147/33 parity; coverage `INCOMPLETE` |
| Levain (executable) | `PASS` — 47/85 TP, 1 partial, 2 duplicates, 3 negative FPs | `NOT_APPLICABLE` | `PASS` — same |
| Levain (Docker) | `NOT_APPLICABLE` | `PASS` — 47/85 TP, 1 partial, 2 duplicates, 3 negative FPs | `PASS` — same |
| Cross-target comparison | `NOT_APPLICABLE` | `NOT_APPLICABLE` | Fixtures `PASS`; Levain `PASS` |
| Overall | `COMPLETE_WITH_LIMITATIONS` | `COMPLETE_WITH_LIMITATIONS` | `COMPLETE_WITH_LIMITATIONS` |

The native lane executes 22 of 23 scenarios on Windows. The `symlink-file`
scenario is `NOT_APPLICABLE` because the host cannot stage the pinned Linux
symlink; the Docker lane still executes it and validates the symlink fixture.
The native assertion count is 141 rather than 147 because the symlink scenario's
assertions and the Docker-specific `clean-negative` container-path assertion are
excluded. All 141 native assertions passed.

### Cross-target comparison

| Metric | Value |
| --- | --- |
| Shared scenarios | 22 |
| Identical scenarios | 22 |
| Different scenarios | 0 |
| Not comparable | 1 (`symlink-file`, Windows native) |
| Assertions compared | 141 |
| Levain differences | 0 |

## Status model

`harness/status.py` defines the only lane vocabulary:

| Status | Meaning |
| --- | --- |
| `PASS` | Every applicable assertion/lane completed successfully. |
| `FAIL` | An executed lane or deterministic assertion failed. |
| `BLOCKED` | A required target, fixture, or tool was unavailable; no result is claimed. |
| `NOT_RUN` | Applicable work was not executed and is not a pass. |
| `NOT_APPLICABLE` | The target/lane was not selected, or a platform-specific capability is unavailable. |

`NOT_APPLICABLE` is ignored when combining statuses, but a run with no applicable
lane is `INCOMPLETE`, never `PASS`. `BLOCKED`/`NOT_RUN` produce `INCOMPLETE`;
`FAIL` produces `FAIL`; all applicable lanes passing with incomplete evidence
coverage produces `COMPLETE_WITH_LIMITATIONS`.

## Native fixture lane

`harness/native_fixtures.py` reuses the pinned `cases.json`, finding-comparison
helpers, fixture identity functions, and Git-fixture staging. It:

- runs `dir` and `git` scenarios with the executable and the pinned config;
- stages Git fixtures into a disposable work tree;
- mirrors the Docker workdir-relative layout for the ignore-file and baseline
  scenarios, so the pinned `../testdata/...` expectations remain unmodified;
- omits only assertions that reference Docker container paths;
- reports the Linux symlink scenario as `NOT_APPLICABLE` on Windows;
- records only hashed finding values and redacted argv in the report.

No Docker-specific behavior is imposed on the executable. The Docker lane retains
all 23 scenarios and 147 assertions, including container paths, read-only mounts,
`--pull=never`, `--network none`, image identity inspection, and symlink-volume
reconstruction.

## INTERNAL_GO evidence audit

`harness/internal_go.py` maps each fixture to a specific observed Go test or
subtest. Package-level pass events are ignored.

| Metric | Count |
| --- | ---: |
| `INTERNAL_GO` contracts | 75 |
| Mapped | 71 |
| — direct named test/subtest | 49 |
| — indirect extension-base parent | 6 |
| — parent `detect.TestFromGit` | 16 |
| Validated (`PASS`) | 55 |
| Skipped on this Windows host | 16 |
| Failed | 0 |
| Unmapped | 4 |
| Audit status | `NOT_RUN` |

Unmapped contracts:

| Fixture | Reason |
| --- | --- |
| `testdata/baseline/baseline.json` | No executing test loads it; `TestFileLoadBaseline` covers the CSV/SARIF rejection paths, not the JSON baseline. |
| `testdata/config/invalid/extend_invalid_base.toml` | No named test or parent extension exercises this file. |
| `testdata/expected/git/small.txt` | Only reference is a commented-out test in `sources/git_test.go`. |
| `testdata/expected/git/small-branch-foo.txt` | Only reference is a commented-out test in `sources/git_test.go`. |

The 16 skipped contracts are the `testdata/repos/archives/` fixture family, mapped
to `detect.TestFromGit`; that test is explicitly skipped on Windows. The audit
does not claim them as validated. On a Linux host the same mapping would be
available without changing the fixture pin.

The inventory names `detect.TestLoadBaseline`, but the executing test is
`detect.TestFileLoadBaseline`; this alias is recorded explicitly. No inventory
lock or fixture content was changed.

## Reports and identities

| Artifact | Identity |
| --- | --- |
| Target source | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |
| Executable SHA-256 | `e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2` |
| Docker image tag | `gitleaks-consolidated:5f6ec56cfa6f` |
| Docker image ID (final both run) | `sha256:c1cb3f995e8523e5730aa9ebd72226154b66320bc996e36a9373bf3f3b37e6cf` |
| Docker image version | `v8.0.0-rnc.5f6ec56cfa6f` |
| Docker platform | `linux/amd64` |

Reports:

- [`cp1b-both.md`](../reports/consolidated/cp1b-both.md)
- [`cp1b-executable.md`](../reports/consolidated/cp1b-executable.md)
- [`cp1b-docker.md`](../reports/consolidated/cp1b-docker.md)

SHA-256:

| Report | SHA-256 |
| --- | --- |
| `cp1b-both.json` | `4dc836e7ce6075f24f6bf5afab83c81607b3f931c5d580bdf2fe9143d31e937d` |
| `cp1b-both.md` | `b5675998b45b505b89749c71e8c91013806426dfa5d30c2efd960f0ae84bb409` |
| `cp1b-executable.json` | `a6587a03409d2c3dadf36037974b2f85c4fe090338f3b8afc58710e859752a21` |
| `cp1b-executable.md` | `2cbf66b0835e35b6e3e5551c02c13f728ef611476b13471019369d40219f410e` |
| `cp1b-docker.json` | `a1bd9c1aad2eb7c5984a38e57b2f9115bea08e53ebc8bf2681d547754f7fce8b` |
| `cp1b-docker.md` | `39ca5e4918ffb901a0648b8b56176fc1b6dbe07cb9e439263e1fed558cddbf76` |

Raw scanner output remains under ignored work paths.

## Test evidence

```sh
python -m unittest discover -s tests -t . -v
```

Result: **124 tests, OK** (about 61 s on this host). New coverage includes:

- canonical status aggregation;
- all three `--targets` selections;
- partial executable build `FAIL` while Docker still runs;
- partial Docker build `FAIL` while executable still runs;
- partial executable build `BLOCKED` producing `INCOMPLETE`;
- native fixture path normalization, Docker-only trace filtering, relative layout,
  and controlled end-to-end execution;
- direct, indirect, aliased, skipped, failed, unmapped, and package-only
  `INTERNAL_GO` evidence cases;
- fixture and Levain comparison differences.

The previous 23/147/33 Docker parity is unchanged and reproduced in both the
Docker-only and both-target runs.

## Limitations

- Native fixture execution was exercised on Windows 11; the Linux-only symlink
  scenario remains `NOT_APPLICABLE` there. No native Linux Docker Engine was
  available.
- Sixteen archive-fixture contracts map to `detect.TestFromGit`, which is skipped
  on Windows; they are not claimed as validated.
- Four `INTERNAL_GO` contracts remain unmapped; Docker coverage therefore remains
  `INCOMPLETE`.
- Levain is a synthetic corpus; its counts are not real-world prevalence.
- The Docker image is a local build, not a release artifact.
- Functional conformance and performance lanes remain separate.

**Stop after CP1B. Awaiting review; CP2 is not authorized.**
