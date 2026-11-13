# CP11 — Local artifact execution refactor

**Repository:** `RNC-Solutions-Group/rnc-security-audit`
**Branch:** `benchmark-harness`
**Status:** Implemented and validated with the full regression suite plus real
locally available artifacts. Operator-supplied CP3/CP4A artifacts remain pending.

## Scope

CP11 changed how the harness receives and executes scanners. It does **not**
change benchmark suites, scoring engines, oracles, performance methodology, or
sequential execution.

Removed from normal experiments:

- repository clone/fetch and exact-commit checkout;
- Go/Rust compilation;
- adapter-owned Dockerfile generation and image builds;
- Docker image pulls and source-checkout rule discovery;
- substituting an unavailable build with another revision.

Added:

- a Git-ignored local `run/` artifact directory;
- `run/manifest.toml` with multiple registered builds per scanner;
- SHA-256 executable verification, local Docker image ID/architecture
  verification, and rules/configuration hash verification;
- explicit `BLOCKED` results with expected/observed identities;
- exact argv evidence for every scanner invocation;
- container-only cleanup that never deletes registered images or `run/`
  artifacts.

## Artifact manifest

`run-manifest.example.toml` is tracked; `run/` is Git-ignored. The manifest
supports several builds for one scanner, optional executables/images, and
optional rules files. Source commits are metadata only.

```toml
[[builds]]
id = "rnc-cp4a"
scanner = "rnc"
version = "0.1.0"
source_commit = "93b4dda909cb3b41606a4d0f36c8ef9d06b77fde"

executable = "rnc-cp4a.exe"
executable_sha256 = "<actual SHA-256>"

docker_image = "rnc-scanner:cp4a"
docker_image_id = "sha256:<actual image ID>"

rules_file = "rules/rnc-providers-v1.json"
rules_sha256 = "<actual SHA-256>"
capabilities = ["filesystem", "git-history"]
```

RNC requires a registered `rules_file`. Gitleaks/Betterleaks capability defaults
are filesystem + Git history; RNC defaults to filesystem unless the operator
declares `git-history`.

## Execution and CLI

```powershell
python -m harness experiment `
  --build rnc-cp4a `
  --platforms windows-amd64 `
  --suites all
```

```powershell
python -m harness experiment `
  --build rnc-cp4a `
  --platforms docker-linux-amd64 `
  --suites all
```

The interactive front-end lists registered builds and selects one. The old
`--repo` and `--commit` flags are gone.

## Docker behavior

- `docker image inspect` verifies the registered image ID and
  `linux/<arch>` architecture.
- Execution uses `docker run --rm --pull=never`.
- No pull, build, retag, or substitute path exists.
- Missing image or ID/architecture mismatch is `BLOCKED`.
- Scanner products run sequentially.
- The adapter removes its exact named container on timeout/interruption; run
  cleanup removes any remaining container carrying the run-specific label.
- Registered images are never deleted. Cleanup no longer lists or removes
  images at all.

## Invocation reporting

`Invocation` now carries invocation type, suite, workload, and exact argv
through the adapter boundary. The adapter records:

- scanner and manifest build ID;
- executable SHA-256 or Docker image ID;
- platform, suite, workload, and type (`detection`, `warmup`, `measured`,
  `verification`);
- the actual executed argv / full `docker run` command and its digest;
- exit code, duration, timeout/error state, and report SHA-256.

JSON reports expose `invocations`; Markdown reports render a readable
command/execution table. Explicit credential-bearing flag values are redacted;
no raw matched secret text is serialized.

## Validation

### Regression suite

```text
python -m unittest discover -s tests -t .
Ran 299 tests in 135.363s
OK
```

New/updated coverage includes manifest parsing and multiple revisions,
executable and Docker selection, missing/wrong hash and image ID, missing/wrong
architecture, missing/mismatched rules, exact detection/performance argv
capture, RNC exit-code semantics, interrupted-container cleanup, and
artifact/source-commit reporting.

### Real local-artifact smoke tests

No scanner was downloaded or built for CP11. Tests used artifacts already
present in the ignored local workspace. Representative reports are retained in
[`reports/cp11/`](../../reports/cp11/README.md).

| Build | Artifact | Suite | Result | Invocations |
| --- | --- | --- | --- | ---: |
| Gitleaks local | executable SHA-256 `e0831964…` | `levain` | PASS; 47/85 TP, 3 FP, 1 partial, 2 duplicates | 4 |
| Gitleaks local | executable SHA-256 `e0831964…` | `gitleaks` fixtures | PASS; 22/23 scenarios, 141/141 assertions | 22 |
| RNC CP5 local | executable SHA-256 `321fbdb3…` | `synthetic-filesystem` | PASS; 4/4 expected | 2 |
| RNC CP5 local | Docker image `sha256:f05f1b34…` | `synthetic-filesystem` | PASS; 4/4 expected | 2 |
| RNC CP5 local | executable SHA-256 `321fbdb3…` | `leaky-repo` | PASS; filesystem + 25-commit history; 21/65 approved occurrences | 7 |
| RNC CP3 local | executable SHA-256 `284c4c98…` | `synthetic-filesystem` + `levain` | PASS; 4/4 synthetic, 32/85 Levain TP, 0 FP | 6 |

The CP3 native smoke was executed after the operator registered the CP3
executable/rules and the `rnc-scanner:cp3-amd64` image in the local manifest. It
used ruleset `rnc-providers-v1` version `2026.11.2` (19 rules), recorded the
ruleset digest from `rnc rules validate`, and matched the historical CP3 Levain
result exactly (32/85 TP, 0 FP). The CP3 Docker AMD64 and ARM64 artifacts verify
by image ID/architecture but were not executed in this native smoke.

Docker smoke evidence recorded the full `docker run` command, including
`--rm`, `--pull=never`, image tag/ID, labels, mounts, and scanner arguments. The
registered image still existed after cleanup and `images_removed` was empty.

Blocked-path smoke: a manifest entry with a zeroed executable SHA-256 produced
`Artifacts: windows-amd64=BLOCKED`, a report containing expected/actual hashes,
zero scanner invocations, and overall `INCOMPLETE`.

### Preserved behavior checked

- `--suites all` remains Levain + Leaky Repo.
- `gitleaks` remains a functional-only fixture lane with no performance
  workload.
- `rnclab` remains standalone and opt-in.
- Leaky Repo history still uses the owner-approved 184-record oracle and the
  same 21/65 result on the local CP5 artifact.
- One active scanner/product benchmark at a time and sequential performance
  execution are unchanged.

## Limitations and pending operator input

- The operator's real `run/manifest.toml` and executables are not committed, by
  design. CP3 native/rules and both CP3 Docker images are now registered locally;
  CP4A uses a CP5-era executable and still references a Docker image that is no
  longer present, so CP4A Docker remains a local operator follow-up.
- The CP3 ARM64 Docker image verifies by ID/architecture but was not executed in
  the native smoke. ARM64 selection remains an explicit operator run.
- The Docker Gitleaks fixture lane's command capture is implemented through the
  fixture validator's recorded `docker_command`; the real smoke test exercised
  the native fixture lane. Docker fixture execution remains available but was
  not re-run for this checkpoint.
- Device/CPU/memory telemetry limitations from CP10 are unchanged.

## Operator follow-up

1. Build CP3/CP4A artifacts outside the harness.
2. Place executables/rules under `run/`; retain Docker images locally.
3. Copy `run-manifest.example.toml` to `run/manifest.toml` and enter real
   SHA-256/image ID values.
4. Run the desired `--build`/`--platforms`/`--suites` combinations.
5. Review the invocation table and report before publishing results.
