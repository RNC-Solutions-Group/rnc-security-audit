# CP1C report — modular scanner architecture and initial CLI

**Checkpoint:** CP1C, implemented under explicit authorization.

**Branch:** `test/scan-harness` (orphan).

**Starting HEAD:** `a5df5657ed59ca158777162af3d7ac2b7303706f`.

**Scope:** refactor the Gitleaks-specific harness into a scanner-independent
adapter/suite framework, integrate pinned Leaky Repo, add TOML configuration,
configurable sanitized/raw reporting, and an interactive/noninteractive CLI.
CP2 was not started.

## Outcome

| Deliverable | Result |
| --- | --- |
| Scanner-adapter interface and Gitleaks implementation | Complete |
| Seven build targets (5 executables, 2 Docker images) | All seven built successfully |
| Independent suites: `gitleaks`, `go`, `levain`, `leaky-repo`, `all` | Complete |
| Unsupported suites reported as `NOT_APPLICABLE` | Complete |
| Pinned Leaky Repo acquisition and filesystem benchmark | Complete |
| TOML configuration and example | Complete |
| Sanitized/raw/console report generation | Complete |
| Interactive and noninteractive CLI | Complete |
| CP1B regression behavior | Preserved |
| Automated suite | **161 tests, OK** |

## Architecture

See [architecture](../architecture.md) for the design.

```text
CLI / interactive -> matrix -> adapter(s) + suite(s) -> pinned datasets
                         |
                    reporting (sanitized / raw / console)
```

The adapter owns scanner build commands, version discovery, invocation,
configuration validation, output parsing, fixture mechanics, and internal Go
evidence. Suites own only test selection, assertions, and scoring. No suite
constructs scanner build commands or parses scanner output itself.

### Build targets

All seven catalogued targets were built from pinned `5f6ec56`:

| Platform | Kind | Build | Version discovery |
| --- | --- | --- | --- |
| `windows-amd64` | executable | PASS | PASS — `v8.0.0-rnc.5f6ec56cfa6f` |
| `linux-amd64` | executable | PASS | `NOT_RUN` — cross-compiled, not host-executable |
| `linux-arm64` | executable | PASS | `NOT_RUN` — cross-compiled |
| `darwin-amd64` | executable | PASS | `NOT_RUN` — cross-compiled |
| `darwin-arm64` | executable | PASS | `NOT_RUN` — cross-compiled |
| `docker-linux-amd64` | Docker | PASS | PASS |
| `docker-linux-arm64` | Docker | PASS | PASS |

A built cross-platform artifact is never counted as tested. Build status and
execution availability are separate fields.

Executable SHA-256:
`e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2`.

Docker images are locally built and identified by immutable image ID; the final
both-target run used
`sha256:ccff37adc38c9c7330a74225e3f4481cca4787cfaa84d730466f048cd6bcd9d7`.
The all-platform build report records the separate Linux ARM64 image ID.

## Suite results at `5f6ec56`

Final both-target run: `windows-amd64` + `docker-linux-amd64`.

| Suite | Status | Result |
| --- | --- | --- |
| `gitleaks` | PASS | native 22/22 applicable, 1 Linux-only `NOT_APPLICABLE`, 141/141 assertions; Docker 23/23 scenarios, 147/147 assertions, 33/33 Docker-applicable fixtures; executable-vs-Docker comparison PASS (22 identical, 1 not comparable, 0 differences) |
| `go` | PASS | 270 tests passed, 0 failed, 2 skipped, 7 packages; 71/75 `INTERNAL_GO` mapped, 55 validated, 16 skipped on Windows, 4 unmapped, 0 failed |
| `levain` | PASS | 47/85 true positives, 1 partial, 2 duplicates, 3 negative false positives; independently reproduced through native and Docker adapters; comparison PASS |
| `leaky-repo` | PASS | 175 expected count units; 22 covered (12.57%); 13/44 files (29.55%); 0 excess findings; 0 unlisted findings; native/Docker comparison PASS |

Overall:
**`COMPLETE_WITH_LIMITATIONS`** — all four suites pass, but Gitleaks Docker
coverage remains incomplete for `INTERNAL_GO`, and Leaky Repo is a count
benchmark with 12.57% count coverage rather than a credential-level completeness
claim.

The four unmapped Gitleaks contracts remain exactly as documented in CP1B:
`baseline.json`, one unreferenced invalid config, and two commented-out expected
Git snapshots. No test result was relabeled.

## Leaky Repo integration

**Source:** <https://github.com/Plazmaz/leaky-repo>

**Pinned revision:** `2e951359cac53addbee56437da3ffb546e3dfe24` (2020-02-29)

**License:** MIT (Git-blob SHA-256
`fcba3a10b27145467a3c92560a806e09ede71977584e4627b5a33f2e42cdf66f`)

**Inventory:** 44 file rows; 96 risk + 79 informative = 175 count units.

**Inventory SHA-256:**
`146df5e25fa987a0b5c5610a958941e5416a29c9f72eadaa3677abc620b281ce`

Acquisition is revision-addressed under
`datasets/cache/leaky-repo/<sha>/source`. `prepare` verifies the commit, clean
worktree, MIT text/hash, scoring CSV hash, inventory hash, every row, every file
Git-blob hash and size, and the composed inventory digest before a run.

Methodology:

- copy the worktree without `.git` so Git objects are not scanned;
- scan with the selected adapter;
- count findings per published file row;
- report `count_coverage = Σ min(observed, expected)`, files covered, excess
  findings, and unlisted findings;
- never convert count totals to TP/FP/precision/recall without detailed
  credential annotations.

Git-history benchmarking is **not enabled** in CP1C. The benchmark is
filesystem-only and uses the scanner's default configuration.

## Configuration and reporting

[`harness.toml.example`](../harness.toml.example) documents the TOML schema.
`harness.toml` is Git-ignored. Independently configurable:

- source repository/branch/commit defaults;
- scanner and preferred platforms;
- default suite selection;
- console, sanitized, and raw report toggles;
- Markdown/JSON formats;
- output/raw destinations;
- report naming conventions;
- cache directory and timeout.

Raw reporting is opt-in. Raw destinations inside the repository must be
Git-ignored or outside the repository. Raw secret-shaped values are never printed
in the ordinary console summary; raw reports are not automatically published.
Sanitized reports contain hashes/counts only, plus the dataset revisions and
checksums recorded under the report's `datasets` section.

## CLI

Interactive:

```sh
python -m harness
```

It uses configured scanner/source defaults, shows the four test suites with an
ALL option, accepts multiple selections, offers host/executable/docker/all/custom
platforms, confirms the scope, then prints a concise summary with builds, suite
statuses, pass/fail/blocked/not-run totals, metrics, cross-target comparisons,
and report locations.

Noninteractive:

```sh
python -m harness matrix --suites all --platforms host --offline
python -m harness matrix --suites go,gitleaks --platforms host,docker-linux-amd64 --offline
python -m harness matrix --suites leaky-repo --raw --raw-dir work/raw
```

Existing `prepare`, `verify`, `status`, `run`, and `consolidate` commands remain
available. `consolidate` is the CP1B compatibility path.

## Verification

```sh
python -m unittest discover -s tests -t .
```

**161 tests, OK** (about 100 s on this host). New tests cover:

- platform catalog and all seven keys;
- adapter parsing/configuration/version handling;
- TOML configuration validation and raw-destination safety;
- suite registry, `all`, and unsupported-suite `NOT_APPLICABLE`;
- Leaky Repo pin, counts, cache tamper rejection, and count scoring;
- sanitized/raw/console report independence;
- matrix build failures/crashes and incomplete coverage;
- interactive multi-selection and cancellation.

CP1B regression verified independently:

- native fixture coverage unchanged (22 applicable / 141 assertions);
- Docker 23 scenarios / 147 assertions / 33 applicable fixtures, parity true;
- Levain 47/85 both adapters;
- executable/Docker comparison PASS;
- existing dataset pins unchanged.

## Reports and hashes

- [cp1c-both.json](../reports/cp1c/cp1c-both.json) — all four suites, both targets
- [cp1c-both.md](../reports/cp1c/cp1c-both.md)
- [cp1c-all-builds.json](../reports/cp1c/cp1c-all-builds.json) — seven-platform build proof
- [cp1c-all-builds.md](../reports/cp1c/cp1c-all-builds.md)

| Report | SHA-256 |
| --- | --- |
| `cp1c-both.json` | `e3a1d76fb7063b5957324a2a595059b7cb26065fa6f4908da370bab3ad80b82b` |
| `cp1c-both.md` | `524ad8f627a0f58a0fcf001cd092dbbc4544aba0dd04a5a6af25ab8390f09226` |
| `cp1c-all-builds.json` | `32a6225d72e5ef2ff7c75ab73e7770b53b623f52eca1ed161344dd56e0879084` |
| `cp1c-all-builds.md` | `fcc7921b1acd2db316d9da7c00183ce68072781c6a99750e8cd8a91fab97c37a` |

## Limitations

- Four `INTERNAL_GO` contracts remain unmapped; sixteen mapped contracts are
  skipped on Windows. Docker coverage therefore remains `INCOMPLETE`.
- Native Gitleaks fixtures run on Windows AMD64 only; the Linux symlink scenario
  is `NOT_APPLICABLE` there and remains covered only by Docker.
- Docker builds were produced on Windows 11 + Docker Desktop/WSL2, not a native
  Linux host.
- Leaky Repo is count-based; 12.57% count coverage is a benchmark measurement,
  not credential-level recall/precision.
- Leaky Repo Git-history benchmarking is not enabled.
- The Gitleaks fixture lane retains hashed reports rather than raw scanner report
  bytes; raw reports are available for Levain and Leaky Repo.
- Docker images are local artifacts, not release artifacts.
- CP2 has not started.

**Stop after CP1C. Awaiting owner review.**
