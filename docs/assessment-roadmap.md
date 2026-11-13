# Scan harness implementation roadmap

**Repository:** `RNC-Solutions-Group/rnc-security-audit`
**Branch:** `benchmark-harness` (orphan; never merge into an application branch)
**Status:** CP0, CP1, CP1A, and consolidation are accepted. CP1B–CP1E are implemented. CP2, CP3, and the RNC CP5 line are implemented and preserved as development evidence. CP3A's historical Leaky Repo oracle is owner-approved; CP10 applied the approved 184-record/89-negative migration and the official loader is strict at 184/89. The certified RNC Synthetic Secrets Lab v3 is integrated as the standalone `rnclab` suite. CP11 replaces source acquisition/builds with operator-provided local executables and retained Docker images referenced by `run/manifest.toml`; the CP10 benchmark methodology, scoring, oracles, performance plan, and sequential execution are preserved. Precision/F1 remain uncertified where the negative reference set is not exhaustive. No merge, rebase, scanner-source edit, or oracle relaxation is authorized.

## Mission

Build an independently reproducible harness that can execute and evaluate **one operator-registered scanner build** against approved, pinned benchmark corpora. Test whether the program functions correctly, whether secrets are detected accurately, and how results change between artifact revisions. Keep Go race testing separate.

The harness is a test tool, not a Gitleaks fork or a replacement for the original application tests. It must remain usable from a normal terminal without requiring an AI agent, database, hosted service, or special toolkit. Scanner artifacts are built and supplied by the operator; the harness verifies and executes them.

## Evaluation lanes

| Lane | Question | Oracle / evidence | Initial state |
| --- | --- | --- | --- |
| Functional conformance | Do supported commands and flags behave as specified? | Explicit scenario assertions, artifact validation, documented exit codes | Planned |
| Detection accuracy | Are known positive and negative cases classified correctly? | External corpus answer keys, normalized matching, TP/FP/FN/TN | Implemented (CP1A baseline) |
| Performance | What are runtime, throughput, and memory costs? | Fixed inputs, repeatable environment, measurements separated from data retrieval | Planned |
| Go race / stability | Are internal concurrent operations free of observed races? | Separate Go race/stress commands in the source checkout | Separate; not part of the functional score |

## Checkpoints

### CP0 — Isolated foundation

**State:** Accepted 2026-11-09.

Deliver:
- Orphan-branch README and AGENTS.md explicitly preventing source-branch changes.
- .gitignore covering downloaded datasets, compiled artifacts, diagnostics, and raw findings.
- Roadmap and first implementation assignment.
- Dataset manifest with unresolved revisions explicitly disabled.
- Verification that the branch contains no Gitleaks application source.

**Stop:** Do not fetch datasets or execute tests as part of CP0.

### CP1 — Levain dataset acquisition and scoring

See [CP1 assignment](checkpoints/CP1-levain.md) and [CP1 report](checkpoints/CP1-report.md).

**State:** Accepted. CP1A separately corrected the scoring oracle, pinned-clone
behavior, and control validation, and produced the first real Gitleaks baseline.
The original CP1 stub reports are historical because their permissive matcher was
superseded.

Deliver:
- Resolve and record a **full immutable upstream commit SHA**, license/notice, and expected corpus artifact hashes.
- Implement an opt-in dataset fetch/verify/cache step; refuse ambiguous or changing revisions.
- Load the published negative and positive case manifests and report case accounting clearly.
- Integrate a deterministic runner against a user-specified Gitleaks binary; distinguish successful no-findings from invocation failure.
- Produce a first repeatable, clearly scoped detection report. Do not claim functional option coverage yet.

**Stop:** Report mismatches and pending decisions before CP2.

### CP1A — Scoring integrity and live baseline

See [CP1A report](checkpoints/CP1A-report.md).

**State:** Complete. Strict evidence matching replaces substring/line attribution;
fresh clones explicitly detach at the pinned commit; control validation requires a
structured expected credential. Real Gitleaks `5f6ec56` was built outside the
worktrees and run on both corpora with the default config: 47/85 TP, 1 partial,
2 duplicates, 0 unexpected, 3 negative FPs.

**Stop:** Do not begin CP2 without separate authorization.

### Consolidation — executable and Docker lanes

See [consolidation report](consolidation-report.md).

**State:** Complete. One resolved target checkout drives executable and Docker
builds plus branch Go tests. Pinned external Gitleaks fixtures are acquired into a
separate SHA-addressed cache and verified against the 228-entry legacy inventory
lock. Docker parity is 23 scenarios / 147 assertions / 33 Docker-applicable
fixtures; functional `PASS`, coverage `INCOMPLETE` pending 75 INTERNAL_GO
contracts. Levain remains 47/85.

**Stop:** Await review before deleting legacy assets or branches.

### CP1B — Unified execution matrix and evidence mapping

See [CP1B report](checkpoints/CP1B-report.md).

**State:** Complete. `--targets executable`, `docker`, and `both` now run every
applicable lane. The native fixture lane runs the portable pinned scenarios (22
of 23 on Windows; the Linux-only symlink scenario is `NOT_APPLICABLE`), while the
Docker lane retains all 23 scenarios and 147 assertions. Levain runs independently
through both adapters when `both` is selected. Executable and Docker results are
reported separately, followed by fixture and Levain comparisons. The 75
`INTERNAL_GO` contracts are mapped only to named Go tests: 71 map (55 passing, 16
skipped on Windows) and 4 remain unmapped. No package-level pass is treated as
fixture coverage.

**Stop:** Await review. CP2 must not begin without a separate authorization.

### CP1C — Modular scanner architecture and initial CLI

See [CP1C report](checkpoints/CP1C-report.md) and [architecture](architecture.md).

**State:** Complete and awaiting review. The Gitleaks-specific harness is now
behind a scanner-adapter interface with seven build targets. Independent suites
cover Gitleaks fixtures, branch Go tests/evidence, Levain, and the newly pinned
Leaky Repo count benchmark. TOML configuration controls source defaults,
platforms, suites, console/sanitized/raw reporting, destinations, formats, and
naming. `python -m harness` is interactive; `python -m harness matrix` is the
noninteractive equivalent. Legacy `run` and `consolidate` commands remain
compatibility paths.

**Stop:** Await review. Do not begin CP2 without a separate authorization.

### CP1D — Scoring-engine stabilization and dataset accountability

See [CP1D report](checkpoints/CP1D-report.md) and
[scoring contract](scoring-contract.md).

**State:** Complete and awaiting review. Shared scoring consumes the normalized
finding contract and versioned truth manifests with no scanner parser dependency.
Every Leaky Repo count unit is line-located in the RNC truth manifest; six
upstream category rows remain explicitly conflicted rather than arbitrarily
reassigned. Leaky Repo reports legacy upstream and RNC rich scores side by side.
The active matrix executes Windows AMD64, Docker Linux AMD64, and Docker Linux
ARM64 (emulated) against Gitleaks fixtures, Levain, and Leaky Repo. macOS and
native Linux build-only products and the redundant Go-test suite were removed
from the active pipeline. The synthetic adapter validates 25/25 controlled cases
at 100% scoring accuracy.

**Stop:** Await review. Do not begin CP2 without a separate authorization.

### CP1E — Scoring finalization, Git history, performance

See [CP1E report](checkpoints/CP1E-report.md),
[correction register](cp1d-corrections.md),
[history accountability](history-accountability.md), and
[performance methodology](performance-methodology.md).

**State:** Implemented and awaiting review. Rich-scoring readiness propagates;
synthetic validation checks 31 individual cases at 100%; Leaky value fingerprints
and per-file reconciliation are explicit; active Go-contract obligations are
removed; controlled Git-history scoring is COMPLETE while Leaky Repo history truth
is BLOCKED; three products executed filesystem and history suites; a separate
performance benchmark collected real native/Docker measurements.

**Stop:** Await review. Do not begin CP2 without a separate authorization.

### CP2 — Multi-scanner integration and comparative validation

See [CP2 report](checkpoints/CP2-report.md).

**State:** Implemented and awaiting review. Betterleaks v1.8.1 is integrated as
the second production scanner with its own adapter. Leaky Repo capability
selection is automatic (filesystem plus Git history when supported). Controlled
filesystem and Git-history end-to-end suites validate scanner/adapter/scorer
integration. Multi-scanner comparison reports capability differences, expected
item differences, and negative-oracle precision/recall/F1. Performance remains a
separate benchmark. All three execution products were exercised for both
scanners; all applicable parity comparisons passed.

**Deferred:** historical Leaky truth remains BLOCKED; Betterleaks v2 is a
release-candidate line; no macOS/native Linux products in this environment; no
live targets or credential validation.

**Stop:** Await review. Do not begin CP3 without separate authorization.

### CP3 — Source-driven simplification and reproducible experiments

See [CP3 report](checkpoints/CP3-report.md) and [architecture](architecture.md).

**State:** Implemented and awaiting review. The harness evaluates exactly one
scanner source commit per invocation, builds native and Docker products from a
disposable checkout, verifies the checkout HEAD, and writes one experiment report
with a separate performance section. DEFAULT uses bundled scanner rules; CUSTOM
is explicit and provenance-tracked. Cross-scanner execution/comparison was
retired. At CP3, Leaky Repo history executed and was reported as
`COMPLETED_UNSCORED`; the filesystem 175-item denominator was never applied to
history. That limitation is superseded by the owner-approved source-oracle
integration below. Run-owned source, builds, images, and containers are removed by
default.
Legacy direct-executable and cached-target entry points were removed.

**Deferred:** historical Leaky truth remains BLOCKED; Leaky precision/F1 remain
unavailable without a negative oracle; Betterleaks v1.8.1's upstream Dockerfile
was incompatible with its own Go version requirement and the adapter supplies a
matching-toolchain source-build Dockerfile; no macOS/native Linux product in this
environment; ARM64 Docker is emulated.

**Stop:** Await review. Do not begin CP4 without separate authorization.

### CP3A — Leaky Repo historical oracle discovery

See [CP3A report](checkpoints/CP3A-report.md) and the
[proposed review files](oracle-review/).

**State:** Owner-approved and integrated. The final oracle has 181 rows:
65 positive occurrences / 53 unique groups, 86 negative, 30 informative, and zero
lineage-only (LH-0170 informative). Runtime scoring is source-validated and
retains every unmatched/unverified finding. Precision/F1 remain **NOT
CERTIFIED** because reviewed negatives are not exhaustive.

**Decision required:** Review the integrated matcher, retained evidence and
investigation ledger before accepting historical scores. The original CP3A
proposal counts (74 positive / 14 ambiguous / 93 negative) are superseded.

### RNC Scanner integration

See the [RNC integration report](checkpoints/RNC-integration-report.md) and
[experiment evidence](../reports/rnc/).

**State:** Corrective pass complete and awaiting review. Native and Docker AMD64
source builds passed. RNC reports 32/85 Levain positive credentials with **0
negative-corpus findings**, precision **100.0%**, recall **37.65%**, and F1
**54.70%**; RNC's own coverage ledger verified **117/117** required negative-corpus
units and the canonical ruleset digest. Leaky reports 33/175 legacy count units
and 32/175 rich line-truth matches. Three additional Levain positive-corpus
observations are classified as broader database-URI capture, not false positives.
At the prior `5391d845` source commit, Git history was `NOT_APPLICABLE`; the CP5
subsection below covers the newer pinned CP4/CP4A source.

**Decision required:** Review the corrective adapter, coverage channel, evidence,
and the neutral database-URI report-span finding before accepting the results.

### RNC Scanner CP5 modernization

See [CP5 RNC modernization report](checkpoints/CP5-rnc-modernization-report.md).

**State:** Implemented and awaiting review for pinned source
`93b4dda909cb3b41606a4d0f36c8ef9d06b77fde`. The adapter now recognizes
`supports_mode("git")`, invokes `--history --ref HEAD` natively and in Docker,
parses `git_commit_blob` locators into normalized commit/path identity, joins
CP4A `database-password` structured components to their exact parent findings,
and verifies historical coverage/scope before scoring. The Docker runtime includes
Git and the repository is mounted read-only with network disabled. Default rules
are the checked-out 37-rule / 22-family bundle (`2026.11.4`), independently
digested. Retained/scanner evidence is reported without benchmark-specific tuning.
No scoring code, owner oracle, scanner source, or default rules were changed.

**Decision required:** Review the adapter, native/Docker evidence, structured
component normalization, and the corrected historical finding attribution in
CP5C before accepting the integration.

### CP5C — Historical attribution and scoring integrity

See [CP5C report](checkpoints/CP5C-scoring-integrity-report.md).

**State:** Implemented and awaiting review. The matcher now follows unchanged-line
source movement through real parent/child diffs, anchors removed negative
references at `observed_commit`, and requires expected-value identity for
informative and typed negative references. The eight CP5B line-shifted RNC
findings are duplicates of `LH-0137`, `LH-0147`, `LH-0152`, and `LH-0157`; the
`hub:4` placeholder matches the approved `LH-0124` negative; the invalid Salesforce
informative match is removed. RNC remains **21/65 occurrences (32.31%)** and
**19/53 unique groups (35.85%)**; Gitleaks and Betterleaks retained results are
unchanged. Of the original 19 unmatched observations, 8 are duplicates, 1 is a
verified false positive, and 10 remain pending. No oracle or denominator change
was made.

**Decision required:** Review the lineage/reference matching rules, the 19-row
reconciliation, and the proposed metadata-negative additions. The latter are
`PROPOSED_NOT_APPLIED`; the `2e951359` merge overlap and the Salesforce
incorrect-extraction disposition require owner adjudication.

### CP5D — Historical lineage integrity and negative-reference design

See [CP5D report](checkpoints/CP5D-lineage-integrity-report.md).

**State:** Implemented and awaiting review. The local parent/child fallback is
removed; value-preserving edits must remain inside the existing occurrence
lineage, so reintroduced values do not inherit the original identity. Exact-value
negative references can target a nonsecret extraction on a line that also contains
an informative/positive credential. The CP5C metadata proposals are consolidated
from four to two records at `9f1468c`, and one exact Salesforce record is proposed;
the proposal is 86→89 reviewed negatives and 181→184 total records, with 65
positive occurrences and 53 unique groups unchanged. Current retained scores are
unchanged (RNC 21/65 and 19/53); the new unique-exposure accounting reports 1
unique verified nonsecret exposure and 1 FP alert. No oracle record was applied.

**Decision required:** Approve or reject the exact-value negative semantics and
the three proposed records; if approved, update the owner-approved oracle counts
and validator constants while preserving the 65/53 positive denominators. Keep
precision/F1 uncertified.

### CP5D.1 — Final source-identity hardening

See [CP5D.1 report](checkpoints/CP5D1-final-source-identity-report.md).

**State:** Implemented and awaiting review. The renamed-path exact-line fallback
was removed; approved rename transitions are carried through the rooted lineage
graph, with ambiguity rejected. Rename plus rotation/reintroduction/deletion,
line movement/trailing comments, and branch/merge inheritance are covered by
regressions. `PNM-001`, `PNM-002`, and `PNJ-001` now carry exact value digests and
match only those extractions. The proposed 184/89 document passes the official
`validate_proposed` profile and source validation of 184/184 records. Retained
classifications remain unchanged: RNC 21/65 and 19/53, 21 duplicates, 7
informative, 1 FP alert, 1 unique exposure, 11 pending. Proposed RNC accounting is
21 TP, 21 duplicates, 7 informative, 12 FP alerts, 4 unique exposures, 0 pending.
The migration is not applied.

**Decision required:** Accept the source-identity hardening, then approve or reject
the oracle migration. Until approved, keep the 181/86 oracle and the 11 pending
RNC observations; do not certify precision/F1.

### Leaky Repo Git-history integration

See [history/accountability report](checkpoints/CP4-history-accountability-report.md).

**State:** Implemented and awaiting review. The owner-approved 181-row oracle is
loaded with strict count/owner/source validation. The scanner-independent matcher
credits only ancestry-valid, source-evidenced, value-identified occurrences;
later snapshots are duplicates, renames add no occurrence, and typed PEM, Base64,
database-URI and encoded representations are validated from source. Every observed
finding is retained; unmatched and unverified findings are investigation items.
History precision/F1 are **NOT CERTIFIED** because reviewed negatives are not
exhaustive. Retained CP3 reports were rescored without rerunning scanners.

**Decision required:** Review the source matcher, representation policy, retained
evidence and the reported unmatched/unverified ledger before accepting historical
scores.

### Benchmark environment extension

**State:** Implemented and awaiting review. DEV, CONTROLLED and RELEASE profiles
are explicit and separate from detection configuration; host CPU/RAM/disk,
scanner order, cache state, inspected/eligible files, archive fields, timeouts,
resource-limit events and performance drift are recorded. DEV remains the
contended default. No controlled/release host or stress driver has been claimed.

### CP4 — Optional expansion (requires separate assignment)

- Consider MIT Leaky Repo for realistic repository and Git-history coverage; verify exact ground-truth claims independently.
- Consider more extensive profiling and synthetic scale cases.
- **ProwlBench remains disabled/not integrated** until licensing authorization and intended-use limits are documented. Adapter capability alone must not imply permission.
- Consider CI integrations only after stable local execution.

### CP10 — Final harness integration and authoritative baseline

See the [CP10 report](checkpoints/CP10-final-integration-report.md) and
[baseline index](../reports/baseline-20261112/README.md).

**State:** Implemented and executed. The approved oracle migration is applied
(184 total / 89 negatives / 65 positives / 53 unique groups / 30 informative).
The certified `rnclab` suite verifies the lab manifest/oracle/corpus, scores
filesystem and Git lanes independently, enforces exact-value and private-key
identity, and runs canonical performance plus `legacy-5x`/`legacy-10x` loads.
`--suites all` remains Levain + Leaky Repo; `rnclab` is opt-in. The Gitleaks
fixture lane is functional-only and has no performance workload. Scanner builds
are source-only and sequential; Docker bases and dependencies are local-only.
The baseline records every completed matrix cell and explicitly blocks cells
that could not be executed without network acquisition or a missing local source
revision.

### CP11 — Local artifact execution refactor

See the [CP11 report](checkpoints/CP11-local-artifact-execution-report.md).

**State:** Implemented. Normal experiments no longer clone/fetch scanner source,
check out commits, compile Go/Rust executables, build or pull Docker images, or
require a scanner checkout. `run/manifest.toml` registers one or more builds per
scanner and the operator supplies the executable and/or retains the Docker image
locally. The harness verifies executable SHA-256, Docker image ID and
architecture, and optional rules/configuration hashes before execution. Missing
or mismatched artifacts are explicit `BLOCKED` products with no substitution.
`docker run --rm --pull=never` executes local images; cleanup removes only
run-created containers and never deletes registered images or `run/` artifacts.
Every scanner invocation is recorded with its exact argv, build ID, artifact
identity, suite, workload, platform, type, exit code, duration, and timeout
status in JSON and Markdown reports. Source commits are metadata only. Existing
benchmark suites, scoring engines, oracles, performance methodology, and
sequential execution are unchanged.

## Shared definition of done

A checkpoint is complete only when its deliverables are committed to this branch, their reproducibility claims are backed by executed evidence, and unknowns are clearly labeled. Missing executables, unavailable datasets, or failed checks are blockers/limitations, never silent passes. Agent analysis may interpret results; it must not replace the deterministic oracle.

## Explicit non-goals

- Merging this branch into application source history.
- Fixing scanner source code during a benchmark.
- Copying third-party datasets into the public branch.
- Treating the Gitleaks race detector as part of the CLI functional score.
- Performing network-based validation of credential-shaped test values.
