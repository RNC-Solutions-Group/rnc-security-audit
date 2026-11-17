# CP-HI1 - Harness integrity, execution provenance, and reporting hardening

## Outcome

CP-HI1 is implemented on `feat/harness-integrity-hardening`, based on the merged
`benchmark-harness` commit `094394e`. PR #16 and PR #17 were verified merged before
the branch was created. Implementation commit: `b14bd52`; evidence-lock revision
commit: `ebc9132`.

The change preserves the certified scoring engine, frozen oracles, scanner rules,
scanner artifacts, and historical reports. Betterleaks v2 remains deferred; no v2
adapter, parser, artifact substitution, manifest rewrite, or benchmark was made.

## What changed

### Exact execution provenance

- Every adapter records the actual sanitized argv, experiment/invocation IDs,
  phase, suite/workload/lane, platform, artifact identity, manifest metadata,
  cwd, cleared environment, configuration identity, exit interpretation, timeout,
  process-start status, duration, report/stdout/stderr digests, and timestamps.
- A normalized command template is stored separately and labelled as a display
  template, never as the literal command.
- Harness commands, direct scanner invocations, nested fixture-validator
  invocations, and auxiliary operations are kept distinct.
- Warmups, measured repetitions, verification, reference, and diagnostic phases
  all share the same record contract.
- The standard Markdown report gained a complete "Scanner invocations: execution
  commands and effective configuration" section, including per-run argv and
  metric-to-invocation links for performance runs.
- Matrix reports now carry equivalent per-run provenance and effective-settings
  sections for new runs.

### Argument acceptance and comparability

- `--scanner-args` uses a Windows-safe splitter that preserves unquoted paths and
  quotes.
- Arguments are classified as PERFORMANCE, DETECTION, SCOPE, OUTPUT, SECURITY, or
  UNKNOWN, with origin and requested/effective distinction.
- Reserved harness-controlled flags and duplicate single-valued flags fail before
  execution.
- Performance-only overrides such as `--workers auto` remain DEFAULT detection
  with explicit execution tuning. Scope, detection, security, or unknown
  arguments cannot inherit baseline comparability.
- Effective values are not invented. `--workers auto` records an unknown effective
  worker count unless a profile artifact exposes it.

### Correct source attribution

- Container misses are no longer classified `SOURCE_UNSUPPORTED/CONFIRMED` merely
  because no target in that class was credited.
- New inspection states are separate from source capability and detection result:
  `INSPECTED_VERIFIED`, `NOT_INSPECTED_VERIFIED`, `INSPECTION_UNVERIFIED`,
  `UNSUPPORTED_VERIFIED`, `NOT_APPLICABLE`.
- Unverified container misses use `SOURCE_INSPECTION_UNVERIFIED` / `UNRESOLVED`.
- Unverified ordinary-file detection hypotheses are downgraded to `PROBABLE` and
  labelled evidence-limited.
- Existing target IDs, credits, misses, scores, unique groups, and oracle
  identities are unchanged.

### Deterministic evidence and publication

- `reports/detection-gaps/analysis-inputs.json` pins report path, SHA-256, build
  ID, source-commit metadata, run ID and dataset/oracle digests.
- Modification-time selection is removed. Hash/build/source mismatches fail
  closed; missing locks fail with an actionable error.
- Explicit report overrides remain available and are recorded as unpinned.
- Detection-gap output is staged, validated, and published through a
  `publication.json` `IN_PROGRESS` -> `COMPLETE` manifest with file hashes.
- Non-empty output directories without a valid completion marker require
  `--replace`.
- Volatile timestamps and run selection are isolated in `analysis-run.json`;
  substantive files reproduce from the same lock.

### Privacy and report safety

- Nested `--scanner-args` credentials in the harness command, URL userinfo,
  authorization headers, sensitive assignments, and report paths are redacted.
- CSV cells beginning with formula characters are neutralised after leading
  whitespace/control characters; numeric values are preserved.
- Markdown table cells escape pipes and newlines; code spans choose a safe
  backtick fence.
- The malformed sample-target backtick construction in the detection-gap report
  was fixed.

### Documentation and lifecycle

- Added execution-provenance, detection-gap-evidence, and report-lifecycle
  documents.
- Updated README and report index with verified commands, pinning, publication,
  comparability, privacy, and retention semantics.
- Documented current report volume (204 tracked report files, 63.2 MiB) and a
  future bulk-artifact proposal. No historical report was migrated or deleted.

## Before/after attribution

| Scanner | Before confirmed / probable / unresolved | After confirmed / probable / unresolved | Before source-unsupported confirmed | After source-unsupported confirmed | After inspection-unverified |
| --- | --- | --- | ---: | ---: | ---: |
| CP4C | 419 / 124 / 12 | 333 / 184 / 38 | 26 | 0 | 26 |
| V14 | 123 / 380 / 31 | 86 / 391 / 57 | 26 | 0 | 26 |
| V16 | 123 / 379 / 31 | 86 / 390 / 57 | 26 | 0 | 26 |

Scores are unchanged: CP4C 570 matched / 555 missed; V14 591 / 534; V16 592 /
533. The full migration is in
[`reports/detection-gaps/classification-migration.md`](../../reports/detection-gaps/classification-migration.md).

## Live validation

All live scanner runs used local registered native Windows AMD64 artifacts and
Git-ignored output directories under `run/hi1/`.

### A. V16 default filesystem and Git lanes

Command:

```powershell
python -m harness experiment --build gl-rnc-mod-v16 --platforms windows-amd64 --suites levain,leaky-repo --out-dir run/hi1/v16-default-final
```

Result: Levain 50/85; Leaky filesystem 22/175; Leaky Git 21/65. All 22
invocations were direct scanner runs, no `--scanner-args` were supplied, and the
report is `BASELINE_COMPARABLE`. A separate RNC Lab run reproduced 369/640
filesystem and 130/160 Git.

Representative normalized template (not the literal command):

```text
'<REPO>\run\gl-rnc-mod-v16.exe' dir <TARGET> --report-format json --report-path <REPORT> --no-banner --exit-code 1
'<REPO>\run\gl-rnc-mod-v16.exe' git <TARGET> --report-format json --report-path <REPORT> --no-banner --exit-code 1
```

The actual sanitized argv for invocations 0001-0004 is in
`run/hi1/v16-default-final/20261116T234948Z-412cd046-gitleaks-11897cd27e57-default.json`
under `execution_provenance.scanner_invocations`. Markdown references are
`inv-0001` through `inv-0022`.

### B. CP4C DEFAULT detection with performance override

Command:

```powershell
python -m harness experiment --build rnc-cp4c --platforms windows-amd64 --suites levain,leaky-repo,rnclab --warmups 0 --runs 1 "--scanner-args=--workers auto" --out-dir run/hi1/cp4c-workers-auto-final
```

Result: Levain 43/85; Leaky filesystem 32/175; Leaky Git 28/65; RNC Lab
filesystem 347/640; RNC Lab Git 120/160. The report records
`DEFAULT` detection, `EXPLICIT` execution, and
`PERFORMANCE_TUNED_BASELINE_DETECTION`. The explicit record is:

```text
Flag: --workers
Category: PERFORMANCE
Requested: auto
Effective: not independently observable from the retained artifact
Accepted: unverified (process completed without an argument-level diagnostic)
Baseline effect: neutral to detection
```

The sanitized actual command for invocation `inv-0002` includes
`--workers auto`; the full argv and digest are in
`run/hi1/cp4c-workers-auto-final/20261116T235101Z-77d9db53-rnc-805e3bb79276-default.json`.

### C. Alternate operational configuration

Command:

```powershell
python -m harness experiment --build rnc-cp4c --platforms windows-amd64 --suites rnclab --warmups 0 --runs 1 "--scanner-args=--workers 1" --out-dir run/hi1/cp4c-workers-1-final
```

Result: RNC Lab filesystem 347/640 and Git 120/160. The report carries
`PERFORMANCE_TUNED_BASELINE_DETECTION`; the requested worker value is visible and
the effective value is explicitly unobservable. This is an operational contrast,
not a claim that changing workers changes detection.

### D. Negative and adversarial execution

- Duplicate flags: `--workers 1 --workers 2` -> exit 2 before launch with
  "conflicting or duplicate values are rejected".
- Reserved flag: `--root C:\temp` -> exit 2 before launch with
  "harness-controlled and cannot be overridden".
- Invalid/sensitive flag: V16 with `--scanner-args="--token synthetic-hi1-secret-2"`
  blocked the synthetic suite; the report records `EXPERIMENTAL_UNVERIFIED`, a
  failed invocation, and `<redacted>` in both the scanner argv and the harness
  command. The synthetic string does not appear in the report.
- Timeout: CP4C leaky-repo at `--timeout 1` recorded four timed-out, launched,
  `BLOCKED` invocations with `TIMEOUT` and the failed-invocation table.
- Tampered report lock: a modified CP4C SHA-256 produced exit 2 with an actionable
  "locked report SHA-256 mismatch" error and no output publication.

## Validation status

No check is marked PASS solely because a test was skipped or blocked.

| Check | Outcome | Evidence |
| --- | --- | --- |
| Full regression | PASS | 424 tests, `OK (skipped=1)`, exit 0; `run/hi1/full-suite-final.log` and `full-suite-final.exit` |
| Named targeted regression | PASS | 118 tests, OK; `run/hi1/targeted-tests.log` |
| CLI provenance | PASS | V16 and CP4C live reports, per-run invocation IDs and argv |
| Argument classification | PASS | `tests/test_provenance.py`; live default, `--workers auto`, `--workers 1`, duplicate, reserved and sensitive cases |
| Source-inspection attribution | PASS | migration table; `tests/test_detection_gaps.py` |
| Report selection/pinning | PASS | `tests/test_integrity.py`; tampered-lock live failure |
| Privacy/redaction | PASS | adversarial live run; generated-report credential-pattern audit |
| CSV/Markdown safety | PASS | generated-set audit; `tests/test_provenance.py`; LF CSV publication hashes |
| Publication integrity | PASS | `publication.json`; 31 file hashes validated; failure-injection test |
| Historical evidence invariance | PASS | unchanged `reports/baselines-20261115/`, `reports/archive/`, `reports/cp4c-matrix0/` |
| Scoring invariance | PASS | live V16/CP4C figures match references |
| Matrix/profiler modules | PASS | `tests.test_cp4c_matrix`, `tests.test_profile`, 20 tests; report-only render |
| Git/worktree hygiene | PASS | Clean worktree after commit; publication hashes match Git blobs. Implementation `b14bd52`; lock revision `ebc9132`; final docs commit follows. |

## Deferred / remaining limitations

- Betterleaks v2 is explicitly out of scope and untouched.
- The CP4C 50-configuration matrix was not rerun. Existing Matrix 0 evidence was
  used for report-only rendering; new Matrix runs will populate the new
  per-invocation fields, while pre-CP-HI1 records are labelled "not recorded".
- Docker execution was not available/used for this validation; native Windows
  AMD64 was used. Docker argv construction has unit coverage but no live container
  run in this cycle.
- `--workers auto` has no independently observable effective worker count in the
  retained artifact; the report says so rather than inventing one.
- Container inspection remains unverified for the 26 archive/database/binary
  targets. The next step is a source-unit capability probe, not a new
  `SOURCE_UNSUPPORTED` assertion.
- Report volume remains 63.2 MiB in tracked reports; the lifecycle proposal is
  documentation only.

## Merge recommendation

**CONDITIONAL GO** for operator review after the final commit/push and worktree
hygiene check. Conditions: Docker was not live-run in this cycle, and the full
50-configuration Matrix was not rerun. The certified scoring invariants and the
required native Windows checks pass. No merge is performed by the development
agent.
