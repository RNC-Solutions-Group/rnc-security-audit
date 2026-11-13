# Harness architecture

**Branch:** `test/scan-harness`
**Checkpoint:** CP10 final integration + certified RNC Lab v3 + 184/89 approved history oracle

The harness is an independent, purpose-built scanner benchmark application. It
evaluates **one scanner source commit per invocation** against pinned benchmark
datasets, writes one experiment report, and removes its temporary build and scan
resources. It is not a general-purpose scanner, a scanner-development test
runner, a hosted service, or a multi-scanner comparison engine.

## Canonical workflow

```text
repository + exact commit
        |
disposable checkout (HEAD verified)
        |
adapter-owned native and Docker source builds
        |
automatic benchmark capabilities
        |
normalized findings -> independent scoring engine
        |
one experiment report (JSON + Markdown)
        |
run-owned cleanup
```

The source commit is the primary experiment identity. A release executable, a
moving branch, a tag alone, or a published scanner image is never substituted for
the requested commit.

## Layers

```text
CLI (`experiment`)
        |
experiment runner
   |         |          |
 source   adapters    suites
   |         |          |
 exact    build/CLI   scoring
 commit   /parse      datasets
        |
 reporting + performance + cleanup
```

### Source acquisition and workspace

`harness/source.py` validates a full 40-character commit, creates a run-owned
partial clone in a system temporary directory, fetches the exact commit when
needed, checks it out detached, verifies `HEAD`, and requires a clean working
tree. A failed acquisition is reported, never retried against another revision.

`harness/workspace.py` owns the disposable run directory and cleanup. Temporary
source, native executables, Docker build files, scan evidence, and benchmark
copies stay outside the tracked harness tree. The only retained output is the
reported experiment evidence.

### Scanner adapter contract

`harness/adapters/base.py` defines the single extension point. An adapter owns:

- scanner key, display name, default repository, and capabilities;
- native source-build strategy and linker/version handling;
- Docker source-build strategy and image topic;
- scanner invocation, configuration behavior, and output parsing;
- normalization into the shared `NormalizedFinding` contract;
- scanner-specific optional fixture hooks.

The harness owns workspace lifecycle, source acquisition, platform selection,
benchmark suite selection, datasets, scoring, performance, reporting, and
cleanup. The scoring engine imports neither adapter. Generic orchestration and
reporting contain no scanner names.

Adding a supported scanner requires one conforming adapter plus one registry
entry. It must not require branches in the scoring engine, reporting layer, or
experiment runner.

The registry is explicit:

| Adapter | Default repository | Source build | Capabilities |
| --- | --- | --- | --- |
| `gitleaks` | RNC Gitleaks fork | Go native; adapter local-base source Dockerfile with offline vendor tree | filesystem, Git history, Gitleaks fixtures, `rnclab` |
| `betterleaks` | upstream Betterleaks | Go native; adapter source-build Dockerfile | filesystem, Git history, `rnclab` |
| `rnc` | RNC Security Audit | Rust/Cargo native; adapter source-build Dockerfile with Git runtime | filesystem, Git history, private structured evidence, `rnclab` |

Betterleaks v1.8.1's upstream Dockerfile pins a Go 1.24 builder while its
`go.mod` requires Go 1.25. The adapter therefore builds a matching-toolchain
source Dockerfile from the same checkout. It does not pull the published
Betterleaks image or download a release binary. This compatibility decision is
reported as adapter provenance.

RNC Scanner is a Rust workspace built with Cargo at the pinned source commit.
Its CLI consumes an explicit versioned rule bundle; DEFAULT therefore passes the
bundled `rules/rnc-providers-v1.json` and records its ruleset ID, version,
37-rule / 22-family count, component-extractor declarations, and independently
validated digest. A harness-generated empty repository configuration is passed as
`--config` so a target-local config cannot silently change DEFAULT.

The private `rnc-cp2-output-v1` JSON is joined through `execution.units` to map
byte-addressed findings back to relative paths. Filesystem units use
`working_tree_file`; historical units use `git_commit_blob` with locator
`commit/<40-character-oid>/<repository-relative-path>`. The adapter validates and
parses that locator into `NormalizedFinding.commit` and repository-relative
`file`; it never treats the complete history locator as a path or assigns the
current HEAD. Findings expose evidence digests rather than raw matched bytes.
Process exits 0/10 with result codes 1/2/3 are completed scans; result code 3
(`ACTIONABLE`, exit 10) is accepted for scoring. Result codes 4/5 and exits 20/30
are incomplete/failed execution and are never scored as zero findings.

Git-history invocation adds `--history --ref HEAD`, preserving the independently
established 25-commit benchmark scope rather than scanning every local ref. The
runtime image installs Git and system-level `safe.directory` configuration; the
repository bind mount is read-only and includes `.git`, network is disabled, and
the report destination is separate. History coverage verifies all changed
commit/path revisions are `INSPECTED`, counts reconcile, refs are exactly `HEAD`,
and execution is `COMPLETED`/`COMPLETE`; otherwise the suite blocks instead of
scoring.

CP4A's private `structured_evidence.version = "1"` supplies validated
`database-password` components. The adapter joins each component to its exact
parent finding and unit, validates byte/line bounds and ANSI metadata, and uses
the normalized password digest as the normalized credential identity. The
contextual URI digest remains safe metadata. Components never create a second
finding; malformed or multiply-linked components are explicit report errors.
The Docker runtime installs Git because a successful `rnc --version` is not proof
of historical acquisition capability.

The adapter also verifies the scanner's own execution and coverage ledger: every
expected generated source unit must be present, required, `INSPECTED`, and
content-addressed; required/uninspected/blocked counts must reconcile; the
execution must be `COMPLETED` with no failure or limit codes; and the ruleset ID
and canonical digest must match the bundle independently validated with
`rnc rules validate`. This is an additive `execution_coverage` adapter channel.
When it succeeds but the synthetic control credential was not extracted, the
shared scorer records `COMPLETED_COVERAGE_VERIFIED` rather than pretending a
control detection occurred. The negative oracle still determines whether
observed findings are false positives. Adapters without the channel retain the
existing control behavior.

### Platforms and products

| Product | Kind | OS / architecture |
| --- | --- | --- |
| `windows-amd64` | executable | Windows AMD64 |
| `docker-linux-amd64` | Docker | Linux AMD64 |
| `docker-linux-arm64` | Docker | Linux ARM64 (emulated on the AMD64 host) |

Multiple products for the **same source commit** may appear in one report with
separate build results, detection results, and performance. Products are not
scanners: a Windows executable and a Linux container built from the same commit
are one scanner identity and two execution products.

Native/container and native/emulated-architecture measurements are not directly
comparable. ARM64 Docker is labeled emulated; it is not native ARM64 evidence.

### Configuration profiles

`harness/profile.py` defines two mutually exclusive profiles:

- **DEFAULT** uses the scanner's bundled detection rules. The harness passes no
  scanner config argument, clears known scanner-config environment variables,
  and runs from an empty run-owned working directory. The scanner does not expose
  a machine-readable digest of its embedded rule set, so isolation is verified at
  the invocation boundary rather than by hashing an embedded file.
- **CUSTOM** requires an explicit configuration file. The report records the
  source path, SHA-256, applied settings, scanner commit, and results. CUSTOM
  results are excluded from DEFAULT baseline metrics.

Synthetic integration controls generate their own controlled fixture rules and
are labeled `CONTROLLED_FIXTURE` and `baseline_metric: false`. They validate the
scanner/adapter/scorer path; they are not default-baseline detection results.

### Benchmark suites and outcomes

| Suite | Method | Baseline metric |
| --- | --- | --- |
| `gitleaks` | Pinned Gitleaks functional scenarios, including the applicable symlink case | No; scanner-specific functional fixture |
| `synthetic-filesystem` | Controlled 4-item corpus plus negative files; real scanner execution | No; controlled fixture |
| `git-history` | Controlled five-commit history; unique credentials and occurrences | No; controlled fixture |
| `levain` | Pinned positive/negative credential corpus | Yes for DEFAULT |
| `leaky-repo` | Filesystem legacy count + RNC line-level truth; automatic history scoring against the approved source oracle | Filesystem yes for DEFAULT; history yes when Git mode is supported |
| `rnclab` | Certified RNC Synthetic Secrets Lab v3; filesystem 1,282 / Git 320 exact-value lanes; canonical performance plus `legacy-5x`/`legacy-10x` loads | Standalone opt-in, never under `all` |

Each suite reports a canonical status (`PASS`, `FAIL`, `BLOCKED`, `NOT_RUN`,
`NOT_APPLICABLE`) and an outcome:

- `COMPLETED_AND_SCORED`
- `COMPLETED_UNSCORED`
- `NOT_APPLICABLE`
- `FAILED`
- `BLOCKED`

`COMPLETED_COVERAGE_VERIFIED` is a run status, not a new outcome or metric. It
means complete inspection was proven by scanner-native coverage evidence while
the synthetic control credential was not extracted. It is accepted only when the
independent corpus oracle remains in force.

Unsupported capability is `NOT_APPLICABLE` with a reason, never zero recall.
Execution failure remains `FAILED`/`BLOCKED`, not capability absence.

The Gitleaks functional fixtures are not applied to Betterleaks or RNC. No
scanner-development Go unit tests are active benchmark obligations; the archived
CP1C Go mapping modules were removed in CP3. RNC participates in the Leaky Repo
Git-history benchmark through its native `--history --ref HEAD` capability; the
controlled `git-history` fixture remains Gitleaks-specific because it supplies a
TOML fixture configuration. RNC's synthetic control uses an adapter-provided RNC
JSON rule bundle, while Levain and Leaky use the bundled provider catalogue.

### Strict output validation

A valid empty report (`[]`, Betterleaks `null`, or RNC `findings: []`) is zero
findings. Missing, empty, malformed, truncated, or schema-incompatible reports are
execution failures. A parser failure can never become a zero-finding result. All
adapters normalize only code, commit, rule, path, line, and safe hashes; raw
secret values are transient and are never serialized. RNC's private evidence
format contains only digests and locators, so Levain's legacy text matcher uses a
digest-to-expected-value bridge in memory rather than requiring raw output. The
bridge includes the corpus and the synthetic control values, so a structured RNC
control detection is not lost during normalization.

### Scoring and detection metrics

`harness/scoring_engine.py` is scanner-independent. Where an independent,
defensible truth oracle exists it reports true positives, false positives, false
negatives, precision, recall, F1, duplicates, partial matches, and identity
evidence.

Leaky Repo has no negative oracle: precision and F1 remain `null`. Its upstream
175-item count score is explicitly labeled **LEGACY COUNT COVERAGE** and is never
described as verified recall or detection accuracy. The RNC line-level truth
score reports detection only.

Leaky Repo Git history is scored against the **owner-approved source oracle**
when the adapter supports Git mode. The oracle contains 184 reviewed rows:
65 positive occurrences in 53 unique credential groups, 89 reviewed negatives,
30 informative references, and no lineage-only rows (`LH-0170` is informative
rename lineage). It is distinct from the 175 filesystem items. The three
exact-value negatives (`PNM-001`, `PNM-002`, `PNJ-001`) match only their approved
extraction digest, never every token on the source line.

`harness/history_oracle.py` validates the oracle's counts, owner decisions,
policy, source blob identities, line ranges, and the digest-to-source evidence
relationship before scoring. `harness/history_matching.py` then requires:

1. a path in the approved occurrence, including reviewed rename lineage;
2. a finding commit that is the introduction commit or a descendant;
3. the credential representation still present in the source at that commit, at
   the approved location or after unchanged-line source movement;
4. a validator-approved canonical or typed value representation (full PEM blocks,
   terminal-newline normalization, Docker/FileZilla Base64, database URL userinfo,
   JetBrains encoded attribute, and direct credential components).

Later snapshots map to the introduction occurrence through unchanged-line
lineage; approved rename transitions change the lineage path in the same graph.
There is no independent renamed-path exact-line fallback. A moved/annotated line
inside a rename is accepted only through a unique exact-content or unchanged
non-comment code-prefix anchor; ambiguous destinations are rejected. Copies,
rotations, reintroductions, deletion/recreation, and different placements do not
inherit the occurrence's credit. A value-preserving edit is accepted only inside
the existing lineage and only when the non-comment code prefix is unchanged and
the approved value remains evidenced in both parent and child.

Reviewed `Removed` negatives are anchored at `observed_commit`; they match only
the snapshot where the negative value existed, not a later replacement.
Informative and typed negative references require the expected value
representation, not an arbitrary token from the source line. An exact-value
negative uses `identity.secret_sha256` and is scoped to that single extraction,
which may share a line with an informative/positive credential. Unknown or
value-mismatched findings become `UNMATCHED_PENDING_REVIEW` or
`UNVERIFIED_EVIDENCE`, never automatic TPs or FPs.

The official approved-oracle loader is strict at 184/89 and source-checks all
184 records. There is no permissive fallback for the superseded 181/86 profile.

The history metrics separately report **verified false-positive alert
observations** and **unique verified nonsecret exposures**. Repeated alerts at one
approved negative source count once as an exposure but individually as alerts.
This accounting does not make the negative inventory exhaustive.

Reviewed negatives are not exhaustive, so history precision and F1 are **NOT
CERTIFIED** (`BLOCKED_INCOMPLETE_NEGATIVE_ORACLE`). Informative matches are
reported separately and excluded from primary recall. Every observed finding stays
in the evaluation/exception ledger and the metrics reconcile observed and
accounted counts.

Retained normalized history findings can be rescored without a scanner through
`python -m harness rescore-history`; this applies the same matcher to captured
evidence and refuses truncated/compact finding lists.

### RNC Synthetic Secrets Lab v3

`harness/rnclab.py` independently verifies the lab manifest self-hash, oracle
hash, all 360 corpus files, the 51-commit local Git lane, and the exact source
span of every one of the 1,602 oracle items before scoring. The two lanes remain
separate: filesystem 1,282 items (640 positive) and Git 320 (160 positive), with
496 unique positive identities overall. Findings earn credit only when path,
commit ancestry (Git), exact value identity, and private-key material policy all
hold. Public-only/SPKI-only/private-container-only evidence is unverified, never a
private-key TP. Duplicate alerts, informative references, verified nonsecret
exposures, unmatched pending review, and unverified evidence are reported
separately. The frozen manifest/oracle/corpus hashes are rechecked after scanning.
Canonical performance uses 1 warm-up/5 measured runs; `legacy-5x` and
`legacy-10x` are generated in a disposable copy and measured 1 warm-up/3 runs,
sequentially, and are never scored against the canonical oracle.

### Performance

The experiment includes a separate performance section. Selected suites register
identifiable workloads: Levain, replicated Leaky Repo filesystem, Leaky Repo Git,
and RNC Lab filesystem/Git. The scanner-specific fixture lane registers no
performance workload. Each executable product runs one warm-up and a configurable
number of measured scans per workload. The report records each measured iteration
and derived statistics (median, min, max, standard deviation, coefficient of
variation), files and bytes, CPU and peak memory where available, host toolchain,
native vs container, and emulated-architecture status.

Measurement conditions are declared separately from scanner detection settings:
`DEV`, `CONTROLLED`, or `RELEASE`. `RELEASE` requires pinned artifacts, default
configuration, controlled hardware, and the default stress profile. Host capacity,
load average, disk, memory, throughput, eligible/inspected files, archive
extraction fields, timeouts, resource-limit events, scanner order, cache state,
warm-ups, and measurement variability are recorded. `performance_drift` compares
already-published documents without modifying either one. Optional CPU, memory,
I/O, and network stress profiles are reserved and reported separately from the
default baseline.

Build time is recorded separately from scanner execution. Docker CPU-seconds and
peak memory are unavailable for short runs and are `null`, never zero. Detection
accuracy and performance are never combined into a weighted score.

### Cleanup

`harness/workspace.py` removes the run-owned source checkout, executables, build
files, scan copies, and run-owned images/containers by exact tag or run-specific
Docker label. It never runs a broad Docker prune, removes volumes, or traverses
unrelated developer paths. Cleanup runs on success, failure, cancellation, and
exceptions. `--retain-work` is the explicit debugging exception and is recorded in
the report.

### Status and reporting

The experiment report contains scanner identity, source repository and exact
commit, adapter identity, profile, configuration provenance, build status and
toolchain, executable SHA-256 and Docker image IDs, platform metadata, dataset and
oracle revisions, every applicable benchmark outcome, normalized history
findings, defensible detection metrics, unscored observations, performance,
errors, and cleanup status.

One invocation writes one Markdown and one JSON report with a collision-resistant
name containing the source commit and profile. Previous experiment reports are
never overwritten.

## Retired in CP3

The following obsolete paths were removed rather than left as competing entry
points:

- multi-scanner `comparative` execution and cross-scanner difference reporting;
- `product_comparison` cross-run comparison;
- standalone `benchmark` orchestration (performance is part of the experiment);
- the old `matrix` CLI/orchestrator;
- the legacy direct-executable `run` CLI;
- cached target acquisition (`targets.py`);
- archived consolidation, internal Go-test mapping, and go-test suite modules.

Historical CP1A–CP1E and CP2 reports and datasets remain intact. Git history is
not rewritten and no application branch is touched.
