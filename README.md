# RNC Scanner Harness

**Independent source-commit scanner benchmarking for RNC Solutions Group.**

> **Status: CP10 implemented and executed; authoritative baseline refreshed.**
> One invocation evaluates **one scanner source commit**, builds the requested
> native/Docker products from a disposable checkout, runs the applicable pinned
> benchmarks, writes one experiment report, and removes run-owned resources.
> Gitleaks, Betterleaks, and RNC Scanner are built from the operator-supplied
> commit; no scanner release is substituted. Cross-scanner execution and
> comparison were retired. Leaky Repo history is scored against the
> **owner-approved 184-record / 65-occurrence / 53-group source oracle** when the
> scanner supports Git mode; reviewed negatives are not exhaustive, so history
> precision/F1 remain **NOT CERTIFIED**. The certified **RNC Synthetic Secrets
> Lab v3** is the standalone `rnclab` suite. See the
> [CP10 report](docs/checkpoints/CP10-final-integration-report.md),
> [baseline index](reports/baseline-20261112/README.md),
> [history/accountability report](docs/checkpoints/CP4-history-accountability-report.md),
> [CP5D.1 source-identity report](docs/checkpoints/CP5D1-final-source-identity-report.md),
> [architecture](docs/architecture.md), and
> [CP5D.1 evidence](reports/cp5d1/).

## Purpose

The harness answers a narrow question: **for this scanner source commit, on these
pinned benchmarks and execution products, what did the scanner do?**

```text
repository + exact commit
    -> disposable checkout (HEAD verified)
    -> adapter-owned native and Docker builds
    -> automatic benchmark capabilities
    -> normalized findings -> independent scoring
    -> one experiment report
    -> scoped cleanup
```

It is not a general-purpose scanner, a scanner-development test runner, a scheduler,
a database, a hosted service, or a multi-scanner comparison engine. External tools
(including DSH agents) may run the harness repeatedly and compare separate reports.

The source commit is the canonical scanner identity. The harness never substitutes
a release executable, a moving branch, a tag alone, or a published scanner image.

## Adapters and profiles

| Adapter | Default repository | Source build | Capabilities |
| --- | --- | --- | --- |
| `gitleaks` | RNC Gitleaks fork | Go native; upstream source Dockerfile | filesystem, Git history, Gitleaks fixtures |
| `betterleaks` | upstream Betterleaks | Go native; adapter source-build Dockerfile | filesystem, Git history |
| `rnc` | RNC Security Audit (`rnc-security-audit`) | Rust/Cargo native; adapter source-build Dockerfile with Git runtime | filesystem, Git history (pinned CP4/CP4A source), private structured evidence |

Adding a scanner requires one conforming adapter and one registry entry. Generic
orchestration, scoring, performance, and reporting contain no scanner-specific
branches. **DEFAULT** uses the scanner's bundled rules and refuses a target-local
configuration; **CUSTOM** requires an explicit config and records its path,
SHA-256, and applied settings. CUSTOM and controlled-fixture results are excluded
from DEFAULT baseline metrics. For RNC, DEFAULT passes the bundled
`rules/rnc-providers-v1.json` rule bundle and a harness-generated empty repository
config to suppress target auto-discovery; CUSTOM accepts an RNC repository config
or a JSON rule bundle.

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
| `windows-amd64` | Native executable |
| `docker-linux-amd64` | Docker container |
| `docker-linux-arm64` | Docker container (emulated on this AMD64 host) |

Products of one source commit are not scanners. Native/container and
AMD64/emulated-ARM64 performance are not directly comparable.

## Running the harness

The harness uses only the Python standard library (3.11+; exercised on 3.13) plus
Go, Cargo/Rust, and Docker for source builds and execution.

```sh
python -m unittest discover -s tests -t . -v

# One complete experiment: exact commit, all applicable suites, performance.
python -m harness experiment \
  --scanner gitleaks \
  --repo https://github.com/RNC-Solutions-Group/gitleaks \
  --commit 5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c \
  --platforms windows-amd64 \
  --suites all \
  --warmups 1 --runs 5 --copies 10 \
  --offline \
  --out-dir reports/cp3 --name gitleaks-5f6ec56-native

# Native plus Docker products of the same commit in one report.
python -m harness experiment --scanner gitleaks \
  --commit 5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c \
  --platforms windows-amd64,docker-linux-amd64,docker-linux-arm64 \
  --suites synthetic-filesystem,git-history,levain,leaky-repo,gitleaks \
  --out-dir reports/experiments

# Betterleaks source build.
python -m harness experiment --scanner betterleaks \
  --repo https://github.com/betterleaks/betterleaks \
  --commit 5eab48332cc48565864514e3bc6de89df091a7c4 \
  --platforms windows-amd64 --suites all --offline

# RNC Scanner source build; filesystem and Git-history benchmark.
python -m harness experiment --scanner rnc \
  --repo https://github.com/RNC-Solutions-Group/rnc-security-audit \
  --commit 93b4dda909cb3b41606a4d0f36c8ef9d06b77fde \
  --platforms windows-amd64,docker-linux-amd64 \
  --suites all --offline --out-dir reports/rnc-cp5

# Certified RNC Synthetic Secrets Lab v3: standalone accuracy, performance,
# and run-owned legacy-5x/legacy-10x load profiles. Never included in `all`.
python -m harness experiment --scanner gitleaks \
  --repo C:\Dev\gitleaks\gitleaks \
  --commit 5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c \
  --platforms windows-amd64 --suites rnclab \
  --warmups 1 --runs 5 --offline \
  --out-dir reports/baseline-20261112

# Scanner-specific functional fixtures: no performance workload.
python -m harness experiment --scanner gitleaks \
  --commit 5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c \
  --platforms docker-linux-amd64 --suites gitleaks --offline

# Offline rescoring of retained normalized history findings.
python -m harness rescore-history \
  --report reports/cp3/gitleaks-5f6ec56-native-5f6ec56cfa6f-default.json \
  --platform windows-amd64 --out work/rescore-history.json

# Declare the benchmark environment explicitly (DEV is the contended default).
python -m harness experiment --scanner gitleaks --commit <40-char-sha> \
  --benchmark-environment CONTROLLED --suites all

# Explicit CUSTOM configuration experiment.
python -m harness experiment --scanner gitleaks \
  --commit <40-char-sha> --profile custom --scanner-config /path/to/scanner.toml

# Debugging: retain the run-owned checkout, builds, and Docker resources.
python -m harness experiment --scanner gitleaks --commit <40-char-sha> --retain-work
```

Other active commands:

```sh
python -m harness prepare    # fetch/verify the pinned Levain corpus
python -m harness verify     # verify cache offline
python -m harness status     # dataset readiness
python -m harness synthetic  # independent scoring-engine validation
python -m harness interactive
```

`harness.toml.example` is the committed configuration template. `harness.toml` is
Git-ignored. Dataset caches and temporary scan artifacts remain ignored.

## Cleanup and safety

By default the run removes its source checkout, native executable, generated
Dockerfile, scan copies, and run-owned images/containers. Docker cleanup is scoped
by a run-specific label and exact image tag; the harness never runs `docker system
prune`, removes volumes, or traverses unrelated developer files. Cleanup executes
on success, failure, and exceptions. `--retain-work` is explicit and reported.

Historical source commits execute build-time code. Run this harness only on
dedicated development/benchmark infrastructure, never on the RNC production website
VPS. Do not provide production credentials, volumes, or deployment secrets.

## Evidence and reproducibility

Each experiment report records source repository/commit and HEAD verification,
adapter identity, profile and config provenance, build status/toolchain, executable
SHA-256 or Docker image ID, platform/architecture, dataset/oracle revisions, every
applicable benchmark outcome, normalized history findings, defensible detection
metrics, unscored observations, performance iterations, errors, and cleanup status.

Reports are written as one Markdown and one JSON file with a predictable,
collision-resistant name containing scanner, commit, and profile. Previous reports
are never silently overwritten. Full artifacts remain compact enough to review;
temporary full evidence stays under ignored `work/`.

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
| `harness/experiment.py` | One-scanner source-commit orchestration, performance, and report assembly |
| `harness/source.py` | Exact-commit disposable checkout and HEAD verification |
| `harness/workspace.py` | Run-owned temporary workspace and scoped cleanup |
| `harness/builds.py` | Scanner-independent native/Docker build primitives |
| `harness/adapters/` | Adapter contract, Gitleaks adapter, Betterleaks adapter |
| `harness/profile.py` | DEFAULT/CUSTOM profiles and provenance |
| `harness/suites/` | Benchmark suite implementations |
| `harness/scoring_engine.py` | Scanner-independent scoring |
| `harness/rnclab.py` | Certified RNC Lab v3 validation, exact-value attribution, and run-owned load generation |
| `harness/history_oracle.py` | Owner-approved historical oracle loading and source validation |
| `harness/history_matching.py` | Ancestry-aware, typed history matcher and accountability ledger |
| `harness/rescore.py` | Offline rescoring of retained normalized history findings |
| `harness/performance.py`, `harness/telemetry.py` | Repeated performance measurements, environment profiles, and OS/container telemetry |
| `harness/reporting.py` | Compact Markdown and machine-readable JSON reports |
| `docs/checkpoints/` | CP1A–CP1E, CP2, and CP3 reports |
| `reports/cp3/` | Representative CP3 experiment evidence |

Historical CP1A–CP2 reports remain intact. No application source is modified, no
application branch is touched, and this orphan branch is never merged into Gitleaks
application history.

## Licensing

RNC-authored harness code has no separate public reuse license. Third-party notices
and licenses are preserved in [`datasets/THIRD_PARTY_NOTICES.md`](datasets/THIRD_PARTY_NOTICES.md).
Gitleaks and Betterleaks are independent upstream projects; this harness is not
affiliated with or endorsed by their maintainers.
