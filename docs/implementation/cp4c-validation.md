# CP4C — instrumented performance and benchmark integration

> **Status:** Implementation and local Windows validation complete; controlled
> 50-configuration benchmark and operator review pending. CP4C changes execution,
> Git acquisition, history scope and profiling only. Detection rules, validators,
> backend heuristics, finding schema and policy semantics are unchanged.

## Baseline and scope

| Field | Value |
| --- | --- |
| CP4B reference baseline | `d00f71f1e2cf16ce58beb07d8b960c5ad056f915` |
| Branch | `feat/cp4c` |
| Implementation head | Recorded in the CP4C PR |
| Target | Native Windows AMD64 |
| Dataset | RNC Synthetic Secrets Lab v3, external to this repository |
| Merge/release | None; operator authority only |

CP4B remains the historical reference. The CP4B binary built from `d00f71f` must
be retained; a rebuilt CP4C binary is not a CP4B baseline substitute.

## CLI

Added:

```text
--workers 1|2|4|8|auto
--git-io process|batch
--history-mode whole|diff
--context-lines 0|1|3|5
--profile-output PATH
```

`--mode auto|whole|stream` remains content-processing control and is independent
of `--history-mode`. Invalid combinations are rejected:

- Git-only flags without `--history`;
- `--context-lines` without `--history-mode diff`;
- `--context-lines` with whole history;
- worker values outside the supported set.

`--workers auto` resolves from host parallelism, capped at eight, and records
both requested and effective values. The default remains one worker, preserving
the CP4B execution model.

## Worker architecture

- Immutable `MatchPlan`, bundle and source context are shared.
- Source units are processed in bounded batches.
- Workers scan units; the main thread performs all accounting in absolute unit
  order.
- Global byte and finding budgets never depend on worker completion order.
- `--workers 1` uses the sequential CP4B path.
- Worker batches are bounded to `workers * 4` (maximum 64).
- Deadline, candidate limits, findings limits and integrity failures preserve
  their existing classifications.
- Worker busy and queue-wait observations are accumulated separately from wall
  elapsed time.

Local differences across workers 1/2/4/8 and whole/stream with all four matching
strategies produced identical exact findings, offsets, digests and IDs. Finding
and total-byte limit tests also produced identical accounting.

## Git object acquisition

### Process

The CP4B `git cat-file blob <oid>` path is preserved and instrumented.

### Batch

A persistent `git cat-file --batch` process is serialized through a mutex. Each
response validates:

- object ID identity;
- object type `blob`;
- declared size;
- exact byte count and protocol newline;
- bounded header/stderr.

Oversized, malformed, missing and timed-out objects are rejected. The child is
killed and reaped on timeout/drop. Process and batch modes produced exactly
equivalent findings and source identities for normal objects, and both mark
oversized/missing objects as uninspected rather than clean.

Batch acquisition is serialized; it is not a concurrent protocol client.

## Git history modes

### Whole

CP4B complete changed-file revision scanning is preserved. Baseline comparison
against the original CP4B binary on the local fixture produced identical
findings, units and result codes for filesystem and Git scans.

### Diff

Unified diffs are generated against the first parent (or root), parsed into
introduced lines and hunk ranges, and matched with the bundle's maximum-match
padding. Overlapping ranges are merged. Only findings whose start line is an
introduced line are retained. Context supports a match but cannot independently
produce a finding.

Rules:

- root commit: all added lines introduced;
- merge: first-parent diff;
- deletion-only: no content revision/unit;
- binary: `GIT_DIFF_BINARY_UNSUPPORTED`, explicit incomplete coverage;
- renames: disabled, matching existing raw-diff semantics;
- no-newline and multiline values: original commit/path/blob offsets and line
  numbers are mapped from the full blob.

Diff mode has intentionally different occurrence scope from whole mode. It must
not be compared to whole mode as though the scopes were identical.

## Profiler

Profile schema version `1`, contract at
[`profiler.schema.json`](../contracts/profiler.schema.json) and
[`profiler.md`](../contracts/profiler.md).

It records:

- wall phases with exclusive time;
- accumulated worker phases (not elapsed time);
- matching literal-filter and regex time;
- context, validation and finding phases;
- Git subprocess counts/durations and bytes by operation;
- requested/effective settings and counters.

The profile contains no values, locators, evidence digests, finding IDs, Git
content or policy selectors. It is written through the atomic report destination
outside the scan root. Profile publication failure exits `30`. Profile-on and
profile-off detection output is identical.

Local profile-on/off wall comparison on small synthetic fixtures (five runs
each, not a benchmark claim):

| Workload | Profile off | Profile on | Observed overhead |
| --- | ---: | ---: | ---: |
| Filesystem, 4 workers | 235.85 ms | 282.07 ms | ~19.6% |
| Git whole, 1 worker | 775.16 ms | 802.39 ms | ~3.5% |

These are five-run local smoke measurements with high small-sample variance, not
stable benchmark results. The filesystem overhead is dominated by profile
serialization/publication on a tiny fixture; the harness must measure the
profile-on/off control at production workload sizes.

## Local validation

| Gate | Result |
| --- | --- |
| `cargo fmt --check` | PASS |
| warnings-denied Clippy | PASS |
| `cargo test --workspace --all-targets --locked` | PASS, 163 tests |
| CP4C execution suite | 10/10 |
| CP4C CLI suite | 4/4 |
| CP4B baseline comparison | Identical findings/units/results |
| Worker differential | Identical across 1/2/4/8, modes and strategies |
| Finding/total-byte limits | Identical accounting |
| Process/batch equivalence | Exact findings and identities |
| Diff scope/context | Whole 5 vs diff 4 on controlled fixture; unchanged context suppressed |
| Binary diff | Explicit incomplete coverage |
| Profile schema | JSON Schema validation PASS |
| Profile secrecy | No raw value or locator in profile |
| Release build | PASS |
| CP0/CP1/CP3 regressions | PASS |
| CP3 provider integration | 24/24 |
| Structured evidence | PASS |

### Limited matrix smoke

A reduced local matrix (workers 1/4, process/batch, whole/diff, context 0/3) ran
12 Git configurations and 4 filesystem worker configurations on the controlled
fixture. All completed; no overlapping runs. This is a smoke test, not the
50-configuration experiment.

Observed findings were stable: whole 5, diff 4, filesystem 40. Filesystem total
runtime reduced from roughly 340 ms at one worker to roughly 199 ms at four on
this small fixture; eight workers did not improve further. These numbers are
fixture-specific and not a performance conclusion.

## Known limitations

- The 50-configuration benchmark was not run.
- CP4C matrix/report implementation lives in the independent harness, outside
  this repository; only the integration handoff is provided.
- Local validation is Windows x86_64 only.
- CI checks were not triggered or monitored for this feature branch per operator
  instruction; workflow definitions remain applicable to `main` PRs.
- Batch object acquisition is serialized and may be slower than process mode for
  low-latency local objects; profiling must decide per workload.
- Diff mode adds a per-revision diff subprocess and intentionally changes
  occurrence scope.
- Diff context cannot recover a credential whose start line is unchanged.
- Binary diff history is explicitly incomplete rather than text-scanned.
- Timeout behavior is wall-clock dependent under parallelism; complete scans are
  canonically equivalent.
- Profile publication occurs after the report; a publication failure exits `30`
  but may leave a previously written report.
- No CPU throttle, new provider rules or candidate diagnostics were added.

## Deferred optimization backlog

Detection gaps found by independent evaluation are retained in
[CP5 detection backlog](cp5-detection-backlog.md). They are not CP4C changes.

## Readiness

**READY for operator review and a controlled CP4C experiment.** Performance
conclusions remain **CONDITIONAL** until the independent harness runs the full
50-configuration matrix in the operator-controlled Windows environment and
re-evaluates the preserved CP4B baseline.
