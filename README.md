# RNC Scanner Harness

**Independent, operator-artifact scanner benchmarking for RNC Solutions Group.**

> **Status: CP11 implemented.** One invocation selects one registered scanner
> build from `run/manifest.toml`, verifies the operator-supplied executable
> SHA-256 and/or local Docker image ID, runs the applicable pinned benchmarks,
> records the exact scanner command for every invocation, writes one experiment
> report, and removes only run-created temporary resources. The harness never
> clones scanner source, compiles a scanner, builds an image, or pulls an image.
> Cross-scanner execution and comparison remain retired. Leaky Repo history is
> scored against the **owner-approved 184-record / 65-occurrence / 53-group
> source oracle** when the selected artifact declares Git-history capability;
> reviewed negatives are not exhaustive, so history precision/F1 remain
> **NOT CERTIFIED**. The certified **RNC Synthetic Secrets Lab v3** is the
> standalone `rnclab` suite. See the
> [CP10 report](docs/checkpoints/CP10-final-integration-report.md),
> [CP11 report](docs/checkpoints/CP11-local-artifact-execution-report.md),
> [baseline index](reports/baseline-20261112/README.md),
> [history/accountability report](docs/checkpoints/CP4-history-accountability-report.md),
> [architecture](docs/architecture.md), and
> [CP5D.1 evidence](reports/cp5d1/).

## Purpose

The harness answers a narrow question: **for this operator-registered scanner
artifact, on these pinned benchmarks and execution products, what did the
scanner do?**

```text
run/manifest.toml + build id
    -> select exactly one registered build
    -> verify executable SHA-256 and/or local Docker image ID
    -> verify registered rules/configuration files
    -> run benchmarks with the existing suites and scoring engines
    -> record every exact argv, exit status, and timeout
    -> one experiment report
    -> remove run-created containers and temporary data only
```

It is not a general-purpose scanner, a scanner-development test runner, a build
system, a scheduler, a database, a hosted service, or a multi-scanner comparison
engine. External tools (including DSH agents) may run the harness repeatedly and
compare separate reports.

The executed artifact identity is the registered executable SHA-256 or Docker
image ID. The source commit is retained as operator-supplied metadata; it is not
verified by cloning or building the scanner.

## Local artifacts

Create the Git-ignored local directory and copy the tracked example manifest:

```text
run/
├── manifest.toml
├── gitleaks.exe
├── betterleaks.exe
├── rnc-cp3.exe
├── rnc-cp4a.exe
└── rules/
    └── rnc-providers-v1.json
```

```powershell
New-Item -ItemType Directory -Force run
Copy-Item run-manifest.example.toml run/manifest.toml
# place the operator-built executables/rules under run/
# edit run/manifest.toml with the real SHA-256 and Docker image ID values
```

`run/` is entirely Git-ignored. Executables, rules, Docker images, and the
operator's actual `run/manifest.toml` must never be committed. Docker images
remain in Docker's local image store.

Example build entry:

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

Rules and Docker images are optional where the scanner does not require them;
RNC builds require a registered `rules_file`. Multiple builds for one scanner
(CP3, CP4A, future revisions) are supported and selected explicitly by
`--build`. `capabilities` defaults to filesystem + Git history for Gitleaks and
Betterleaks, and filesystem-only for RNC; declare `git-history` on an RNC build
only when the artifact actually supports `--history --ref HEAD`.

Verification behavior:

- A missing executable, missing rules file, missing image, wrong SHA-256, wrong
  image ID, or wrong image architecture is reported as **BLOCKED** with the
  expected and observed values.
- No pull, rebuild, retag, alternative build, or image substitution is attempted.
- Registered executables and images are never deleted or modified.
- Source commits are metadata only. No scanner source checkout is required.

The schema and a four-build example are in
[`run-manifest.example.toml`](run-manifest.example.toml).

## Adapters and profiles

| Adapter | Registered artifact | Capabilities |
| --- | --- | --- |
| `gitleaks` | Operator executable and/or Docker image | filesystem, Git history, Gitleaks fixtures |
| `betterleaks` | Operator executable and/or Docker image | filesystem, Git history |
| `rnc` | Operator executable and/or Docker image plus registered rules | filesystem, Git history when declared, private structured evidence |

Adding a scanner requires one conforming adapter and one registry entry. Generic
orchestration, artifact verification, scoring, performance, and reporting contain
no scanner-specific branches. **DEFAULT** uses the registered rules/runtime
defaults; **CUSTOM** requires an explicit configuration file and records its
path, SHA-256, and applied settings. CUSTOM and controlled-fixture results are
excluded from DEFAULT baseline metrics. For RNC, DEFAULT passes the registered
`rules_file` and a harness-generated empty repository config to suppress target
auto-discovery; CUSTOM accepts an RNC repository config or a JSON rule bundle.

## Benchmark suites and outcomes

**Baseline selection:** `--suites all` means **Levain + Leaky Repo only**. It is intentionally not every test suite. `--suites gitleaks` is the separate Gitleaks-only regression lane with **no performance workload**; `--suites git-history` and `--suites synthetic-filesystem` are explicit diagnostics. `--suites rnclab` is the certified, standalone **local-only** synthetic lab; it is opt-in and never silently runs under `all`.


| Suite | Purpose | DEFAULT baseline? |
| --- | --- | --- |
| `gitleaks` | Legacy Gitleaks-only regression fixture, **explicit opt-in**; excluded from shared `all` | No; not scanner-neutral |
| `synthetic-filesystem` | Controlled 4-item scanner/adapter/scorer control plus negatives | No; controlled fixture |
| `git-history` | Controlled five-commit history: 3 unique credentials / 5 occurrences | No; controlled fixture |
| `levain` | Pinned positive/negative credential corpus with precision/recall/F1 | Yes |
| `leaky-repo` | Filesystem legacy count + RNC line truth; automatic history scored against the approved source oracle | Filesystem yes; history yes when supported |
| `rnclab` | Certified RNC Synthetic Secrets Lab v3: 1,282 filesystem + 320 Git items, exact-value identities, canonical performance, legacy-5x/legacy-10x loads | Standalone opt-in |

RNC supplies `synthetic-filesystem`, `levain`, and `leaky-repo` filesystem and
Git-history assessment. `git-history` controlled-fixture mode remains
`NOT_APPLICABLE` for RNC because that suite supplies a Gitleaks TOML fixture
configuration; the Leaky Repo historical benchmark uses RNC's native
`--history --ref HEAD` path and the owner-approved source oracle. The legacy
`gitleaks` fixture suite is not in shared `all` and remains an explicit
Gitleaks-adapter regression lane only. The synthetic suite uses an
adapter-provided controlled RNC JSON rule bundle; the DEFAULT provider catalogue
is used for Levain and Leaky.

Every requested suite reports `PASS`, `FAIL`, `BLOCKED`, `NOT_RUN`, or
`NOT_APPLICABLE`, plus `COMPLETED_AND_SCORED`, `COMPLETED_UNSCORED`,
`NOT_APPLICABLE`, `FAILED`, or `BLOCKED`. Unsupported capability is not zero
recall. Missing ground truth produces an unscored observation, not invented
accuracy.

**Leaky Repo history is source-scored for Git-capable adapters.** The 184-record
owner-approved oracle defines **65 positive source occurrences in 53 unique
credential groups**, plus 89 reviewed negatives and 30 informative references.
Matching is ancestry-aware, value-identity based, and rename-aware. Persistence
snapshots and duplicates do not create new occurrence credit. The filesystem
175-item denominator is never used for history. Reviewed negatives are not
exhaustive, so history precision/F1 are reported as **NOT CERTIFIED**; unmatched
or unverified findings stay in the investigation ledger. The upstream Leaky count
score remains **LEGACY COUNT COVERAGE**, not verified recall.

## Products

| Product | Execution |
| --- | --- |
| `windows-amd64` | Registered native executable |
| `docker-linux-amd64` | Registered local Docker image |
| `docker-linux-arm64` | Registered local Docker image (emulated on this AMD64 host) |

Products of one registered build are not scanners. Native/container and
AMD64/emulated-ARM64 performance are not directly comparable. A build that
registers only an executable cannot satisfy a Docker platform, and vice versa;
that product is `BLOCKED`, never silently substituted.

## Running the harness

The harness uses only the Python standard library (3.11+; exercised on 3.13).
Docker is required only for Docker products. No Go or Rust toolchain is used.

```sh
python -m unittest discover -s tests -t . -v

# One complete experiment: registered CP4A executable, all applicable suites.
python -m harness experiment `
  --build rnc-cp4a `
  --platforms windows-amd64 `
  --suites all

# The same registered build through its locally retained Docker image.
python -m harness experiment `
  --build rnc-cp4a `
  --platforms docker-linux-amd64 `
  --suites all

# Certified RNC Synthetic Secrets Lab v3, including 5x/10x load profiles.
python -m harness experiment --build rnc-cp4a --platforms windows-amd64 --suites rnclab --warmups 1 --runs 5

# Gitleaks functional fixtures only; no performance workload.
python -m harness experiment --build gitleaks-5f6ec56 --platforms docker-linux-amd64 --suites gitleaks

# Explicit non-default manifest location and output directory.
python -m harness experiment --build rnc-cp4a --artifact-manifest C:\bench\run\manifest.toml --platforms windows-amd64 --suites all --out-dir reports/cp11

# Declare the benchmark environment explicitly (DEV is the contended default).
python -m harness experiment --build rnc-cp4a --benchmark-environment CONTROLLED --suites all

# Explicit CUSTOM configuration experiment.
python -m harness experiment --build rnc-cp4a --profile custom --scanner-config path\to\scanner.toml

# Debugging: retain the run-owned workspace and run-created containers.
python -m harness experiment --build rnc-cp4a --retain-work
```

Other active commands:

```sh
python -m harness prepare    # fetch/verify the pinned Levain corpus
python -m harness verify     # verify cache offline
python -m harness status     # dataset readiness
python -m harness synthetic  # independent scoring-engine validation
python -m harness interactive
```

`harness.toml.example` is the committed configuration template. `harness.toml`
is Git-ignored. `run/manifest.toml`, executable artifacts, rules, dataset caches,
and temporary scan artifacts remain ignored.

## Invocation evidence

Every scanner invocation is recorded with:

- scanner and registered manifest build ID;
- executable SHA-256 or Docker image ID;
- suite, workload, platform, and invocation type (`detection`, `warmup`,
  `measured`, or `verification`);
- the exact executed argv or full `docker run` command, in execution order;
- exit code, duration, timeout/error status, and report SHA-256.

The JSON report includes the invocation records as `invocations`. The Markdown
report includes a readable command/execution table. Credential-bearing argument
values are redacted only when an explicit sensitive flag such as `--password` or
`--token` is present; the original argv digest is retained. No raw matched
secret values are serialized.

## Cleanup and safety

By default the run removes its temporary benchmark workspace, generated
datasets, and any run-created container identified by the run-specific Docker
label. `docker run` uses `--rm --pull=never`; the adapter also removes its exact
named container if a run times out or is interrupted. Cleanup executes on
success, failure, and exceptions.

**Registered Docker images are never deleted.** The harness never runs
`docker image rm`, `docker system prune`, `docker rmi`, or volume removal, and
it never traverses unrelated developer files. `--retain-work` is explicit and
reported.

The operator is responsible for the provenance and trustworthiness of local
scanner artifacts. Run this harness only on dedicated development/benchmark
infrastructure, never on the RNC production website VPS. Do not provide
production credentials, volumes, or deployment secrets.

## Evidence and reproducibility

Each experiment report records the local manifest path/SHA-256, registered build
ID, source-commit metadata, adapter identity, profile and config provenance,
artifact verification result, executable SHA-256 or Docker image ID,
platform/architecture, dataset/oracle revisions, every applicable benchmark
outcome, normalized history findings, defensible detection metrics, unscored
observations, performance iterations, every exact scanner invocation, errors,
and cleanup status.

Reports are written as one Markdown and one JSON file with a predictable,
collision-resistant name containing scanner, source-commit metadata, and
profile. Previous reports are never silently overwritten. Full artifacts remain
compact enough to review; temporary full evidence stays under ignored `work/`.

## Datasets

- **Levain FP Corpus**, MIT, pinned at `c130c321…`; fetch/verify into ignored cache.
- **Gitleaks fixtures**, pinned at `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c`;
  Gitleaks-specific functional scenarios only.
- **Leaky Repo**, MIT, pinned at `2e951359…`; 44 files / 175 upstream count units,
  RNC line-level truth, six upstream category conflicts preserved, no exhaustive
  negative oracle. Git-history source oracle: 184 owner-approved rows
  (65 positive occurrences / 53 groups, 89 negative, 30 informative). History
  precision/F1 remain **NOT CERTIFIED** because reviewed negatives are not
  exhaustive.
- **RNC Synthetic Secrets Lab v3**, `rnc-synthetic-secrets-lab/1.2.0` build `v3`,
  local-only under `datasets/cache/rnc-synth-lab/`. Certified manifest
  `691548588679f4a1e5e41ecd5d253d7137693337c1ddef2c6e8943bbb7cd7d0b` and oracle
  `83dea16b343ff7a9340ff463513f4bdb454cea6faaf3234696a78fe8e6b85214`;
  1,602 items / 496 unique positive identities. The frozen corpus is verified
  before and after each run and is never rebuilt during benchmarking.
- **ProwlBench is not approved** (PolyForm Noncommercial 1.0.0). Do not download,
  run, vendor, or auto-enable it.

See [`datasets/manifest.toml`](datasets/manifest.toml) and
[`datasets/THIRD_PARTY_NOTICES.md`](datasets/THIRD_PARTY_NOTICES.md).

## Layout

| Path | Purpose |
| --- | --- |
| `run-manifest.example.toml` | Tracked example of the Git-ignored `run/manifest.toml` |
| `harness/artifacts.py` | Local artifact manifest parsing, executable/image/rules verification |
| `harness/experiment.py` | One-registered-build orchestration, performance, and report assembly |
| `harness/workspace.py` | Run-owned temporary workspace and container-only cleanup |
| `harness/adapters/` | Adapter contract, Gitleaks/Betterleaks/RNC adapters |
| `harness/profile.py` | DEFAULT/CUSTOM profiles and provenance |
| `harness/suites/` | Benchmark suite implementations |
| `harness/execution.py` | Deterministic invocation, exact argv capture, report parsing |
| `harness/scoring_engine.py` | Scanner-independent scoring |
| `harness/rnclab.py` | Certified RNC Lab v3 validation, exact-value attribution, and run-owned load generation |
| `harness/history_oracle.py` | Owner-approved historical oracle loading and source validation |
| `harness/history_matching.py` | Ancestry-aware, typed history matcher and accountability ledger |
| `harness/rescore.py` | Offline rescoring of retained normalized history findings |
| `harness/performance.py`, `harness/telemetry.py` | Repeated measurements, environment profiles, and OS/container telemetry |
| `harness/reporting.py` | Markdown/JSON reports including exact invocation evidence |
| `docs/checkpoints/` | CP1A–CP11 reports |
| `reports/baseline-20261112/` | Authoritative retained baseline evidence |

Historical CP1A–CP10 reports remain intact. No application source is modified, no
application branch is touched, and this orphan branch is never merged into
application history.

## Licensing

RNC-authored harness code has no separate public reuse license. Third-party notices
and licenses are preserved in [`datasets/THIRD_PARTY_NOTICES.md`](datasets/THIRD_PARTY_NOTICES.md).
Gitleaks and Betterleaks are independent upstream projects; this harness is not
affiliated with or endorsed by their maintainers.
