# CP4C execution, Git strategy and profiling architecture

> **Status:** Implemented for CP4C; operator review and controlled benchmark
> execution pending. This is an instrumented execution layer, not a change to
> detection rules, validators, backend selection heuristics or report schemas.

## Scope

CP4B established detection correctness but exposed unstable and expensive
Git-history execution. CP4C adds:

- configurable scan workers;
- process and persistent-batch Git object acquisition;
- whole-revision and introduced-line Git history modes;
- bounded context control for diff mode;
- an opt-in, versioned internal performance profile.

The CP4B reference behavior is preserved by
`--workers 1 --git-io process --history-mode whole`.

## CLI surface

| Flag | Values | Applies to |
| --- | --- | --- |
| `--workers` | `1`, `2`, `4`, `8`, `auto` | Filesystem and Git scans |
| `--git-io` | `process`, `batch` | Git-history scans |
| `--history-mode` | `whole`, `diff` | Git-history scans |
| `--context-lines` | `0`, `1`, `3`, `5` | `--history-mode diff` only |
| `--profile-output` | path outside scan root | Any completed scan |
| `--strategy` | `regex`, `regexset`, `prefilter`, `auto` | Matching backend |
| `--mode` | `auto`, `whole`, `stream` | Content processing |

`auto` workers resolve from host parallelism, capped at eight for bounded
memory. Requested and effective values are recorded in the profile and Git
history metadata. Explicit Git-only flags without `--history`, whole mode with
`--context-lines`, and context without diff mode are rejected rather than
ignored.

## Worker model

The matcher plan, immutable rule bundle, source root and Git source are shared.
Workers scan independent source units. Results are collected by absolute unit
order; the main thread performs all budget and coverage accounting in that
order.

```text
unit order -> bounded batch -> worker scans -> ordered result processing
                                      |
                                      +-> total bytes / findings / errors
```

This deliberately separates parallel work from accounting. A worker never
updates the global byte/finding budget, so completion order cannot change:

- inspected/uninspected/blocked counts;
- total-byte admission;
- finding-cap decisions;
- canonical finding collection;
- required-coverage classification.

`--workers 1` uses the sequential CP4B path. Worker batches are bounded by
`workers * 4` (maximum 64); this limits memory while retaining useful
parallelism. Timeout and cancellation are shared through the existing deadline.
Timeout is inherently wall-clock dependent; a faster partial scan is still
classified incomplete.

## Git process acquisition

`--git-io process` preserves `git cat-file blob <oid>` per object. The
subprocess environment and read-only constraints are unchanged. Profiling
records process duration, count and transferred bytes.

## Git batch acquisition

`--git-io batch` starts one persistent `git cat-file --batch` process per source
and serializes requests through a mutex. For every object it verifies:

- requested object ID equals the returned object ID;
- object type is `blob`;
- declared size is within the per-object limit;
- exactly the declared number of bytes plus the protocol newline are read.

The protocol rejects malformed headers, unexpected fields, missing objects,
oversized objects and EOF. Stderr is drained under a bound. A watchdog kills the
child on deadline; the reader is unblocked by process termination and the batch
is discarded. On any protocol/failure the object is rejected; the batch is not
silently reused. Both modes return identical source bytes and source identities
for normal objects.

Diff generation remains a bounded Git subprocess in both I/O modes; `--git-io`
governs object acquisition, not diff generation.

## Git history modes

### Whole

The CP4B behavior is unchanged: every changed-path revision is a source unit and
the complete blob is scanned. Deletions remain excluded; the parent revision is
already traversed separately.

### Diff

For each changed text path, CP4C obtains a unified diff against the first
parent/root and derives:

- introduced new-file line numbers;
- new-file hunk line ranges, including configured context.

The full blob is still read, preserving exact original byte coordinates and
line numbers. Matching is restricted to hunk ranges padded by the bundle's
maximum match length, with overlapping ranges merged. A finding is retained
only when its **start line** is an introduced line. Context can supply value
bytes and syntax, but a finding that begins on unchanged context is suppressed.

Definitions:

- **Root commit**: all added lines are introduced.
- **Merge commit**: diff is against the first parent, matching existing history
  traversal.
- **Deletion-only change**: no introduced content revision and no unit.
- **Binary change**: explicit `GIT_DIFF_BINARY_UNSUPPORTED` uninspected unit;
  required coverage is incomplete rather than silently clean.
- **Renames**: disabled, matching existing raw-diff semantics.
- **No-newline and multiline values**: line/byte mapping comes from the full
  blob, not the diff text.
- **Overlapping hunks/windows**: ranges are merged and findings are deduplicated
  by rule + absolute byte range.

Diff mode is intentionally a different occurrence scope from whole mode. It
must not be interpreted as an accuracy regression or improvement without
normalizing the scope difference.

## Profile model

`--profile-output` writes profile schema version `1`, documented in
[profiler.md](../contracts/profiler.md):

- wall phases and their exclusive time;
- accumulated worker phases, explicitly not elapsed time;
- operation counts and bytes;
- requested/effective settings;
- Git subprocess counts/durations by operation.

The profile contains no values, locators, digests, finding IDs or Git content.
Publication uses the existing atomic report destination outside the scan root.
A profile publication failure exits `30`. Profiling is opt-in; detector output
is identical with profiling enabled or disabled.

## Limits and failure behavior

- File/blob size, total bytes, finding cap, candidate cap and deadline remain
  authoritative.
- Parallel results are accounted in unit order, not completion order.
- A candidate-limit, findings-limit or integrity failure marks the current unit
  and subsequent units uninspected; earlier units remain represented.
- Parallel batches may read a bounded amount past a global byte/finding budget
  before ordered accounting discards the excess. The recorded inspected bytes
  and findings remain budget-correct; batch sizing bounds the temporary work.
- Git object unavailability is fatal, never clean.
- Binary diff coverage is explicit.
- Blocked units remain pre-scan blocked; exemptions remain post-detection.

## Explicit non-goals

- No detection rule, validator, confidence or backend-heuristic changes.
- No CPU throttle in the primary experiment.
- No full language parser.
- No candidate telemetry in CP4C.
- No replacement for the independent harness or its oracle.
- No 50-configuration production benchmark in this implementation task.

## Experiment boundary

The independent harness owns the CP4C matrix. The scanner exposes the
configuration and profile contract; it does not execute or score the external
matrix. See [CP4C harness handoff](../implementation/cp4c-harness-handoff.md).
