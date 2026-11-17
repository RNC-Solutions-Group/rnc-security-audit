# CP5 optimization and detection architecture

> **Status:** Implemented and locally validated. Independent harness
> re-evaluation is pending. This document records the CP5 design; it does not
> certify benchmark scores.

## Scope

CP5 changes two areas without changing the scanner's evidence, policy,
reporting or CI contracts:

1. the candidate-matching pipeline, filesystem containment open path and Git
   delta/object acquisition;
2. a bounded WordPress authentication family and reviewed HMAC/signing
   identifier aliases.

The CP4C reference configuration remains available exactly as before:

```text
--workers 1 --git-io process --history-mode whole --strategy regex
```

`auto` and the default Git acquisition strategy are deliberately changed; they
are documented below.

## Candidate pipeline

### Automatic strategy

`--strategy auto` now resolves to `prefilter`. The reference `regex` backend
remains the explicit equivalence oracle. `regexset` and `prefilter` retain their
previous candidate contract.

The prefilter plan performs one Aho-Corasick pass over the window and then runs
each selected rule's exact `regex` on the full window. It never extracts a value
from the automaton match; the exact regex remains the only producer of candidate
spans and capture groups.

### Required-literal sets

A rule now carries a *set* of proven required literals: every match must contain
at least one member. Extraction recursively handles:

- literals and small byte classes, including classes produced by the regex
  parser when it factors short alternations such as `(?:AKIA|ASIA)`;
- concatenation (choose the most selective mandatory part);
- alternation (union across branches, provided every branch has a proof);
- captures and bounded repetition with `min >= 1`.

A member that contains a shorter proven member is removed because the shorter
literal is present whenever the longer one is. The resulting set is bounded to
64 literals and 4 KiB of literal bytes; beyond that the rule keeps exact-regex
evaluation instead of a weak filter.

### Case-insensitive patterns

Many production rules begin with `(?i...)`. Parsing the original HIR produces
case-folded character classes rather than literals, which previously forced
those rules to run on every window. The planner strips only case-insensitivity
flags (`i`) from inline flag groups before literal extraction, then matches the
resulting literals ASCII-case-insensitively.

This is sound for a filter: a case-insensitive match can only add eligible rules;
every eligible rule is still evaluated by its exact regex. Other flags (`m`,
`s`, `u`, `x`, `U`, `R`) are preserved. Character classes and escapes are not
rewritten. If the rewritten pattern does not parse, the planner falls back to
the original pattern, and if no literal is proven the rule runs unfiltered.

### Candidate budget

The reference `regex` backend now enforces the aggregate candidate budget while
iterating rules, matching the existing `regexset`/`prefilter` behavior. Two
rules that each stay below 100,000 candidates can no longer combine into an
unbounded materialized vector.

Capture-group lists are borrowed from the rule definition instead of cloned for
every rule/window evaluation.

## Filesystem open path

`ContainedRoot` computes the canonical root and its normalized comparison form
once per scan. Each opened file still receives the same Windows checks:

- every path component is inspected for a reparse point before opening;
- the final component is opened with `FILE_FLAG_OPEN_REPARSE_POINT`;
- `GetFinalPathNameByHandleW` returns the final normalized path;
- that path must remain beneath the canonical root.

The change removes two `fs::canonicalize` calls and one length-probe syscall from
every file open. It does not remove a containment or reparse-point check.

## Git acquisition

### Batched delta enumeration

`rev-list --parents --topo-order --reverse` still enumerates the same commits.
Non-merge commits are then sent to one persistent `git diff-tree --stdin --root`
process in batches of 256. Output is framed by commit object ID and the existing
raw `-z` records.

Merge commits retain the exact two-tree invocation (`parent commit`) so
first-parent semantics are unchanged. A batch that exceeds the 32 MiB output
bound is retried through the exact single-commit path, preserving the previous
acceptance behavior. Malformed framing, invalid object IDs, unit/commit limits,
deletions, submodules, symlinks, binary diffs and path validation follow the
same rules as CP4C.

### Object acquisition default

`--git-io batch` is now the default. It retains the CP4C persistent
`git cat-file --batch` reader with serialized requests, object/type/size
validation, bounded stderr, timeout kill/reap and drop cleanup. If the batch
reader cannot start on a particular Git installation, acquisition falls back to
the exact process path and disables further batch attempts. Explicit
`--git-io process` remains available for the CP4C reference.

### Determinism

Discovery still produces the same `commit/<oid>/<path>` units and sorts them by
unit ID before scanning. Batch acquisition is serialized but does not reorder
units, findings or accounting. Merge diffs are applied in the original commit
order.

## Profiling

Profile schema version `1` is unchanged. CP5 adds worker phases for:

- `scan.open` — containment open and handle verification;
- `scan.read` — bounded whole-file read;
- `scan.line_index` — line-start index construction;
- `scan.hash` — content digest.

`git.deltas` now covers both the batched stdin process and the per-merge
invocation. Worker phases remain accumulated time, never wall time.

## Worker and memory findings

The CP4C memory increase at two or more workers is dominated by per-regex search
caches: reducing the configured cache bound from 2 MiB to 1 MiB or 512 KiB
increased observed private memory and did not improve time. The bound was left at
the library default.

Switching `auto` to the prefilter reduces both the number of regexes that run and
the number of caches that are populated. On the RNC Lab filesystem workload,
eight-worker peak working set fell from roughly 326 MiB to 158–192 MiB while wall
time was unchanged within noise. The default worker count remains `1`:

- `auto` adds CPU and memory to gain wall time;
- one worker preserves the deterministic reference path and the smallest
  working set;
- the operator may select `--workers auto` explicitly.

A persistent worker pool was not adopted. It would not reduce the number of
concurrently populated regex caches, and the existing bounded batch model
already preserves ordered accounting and cancellation.

## Rejected alternatives

- **RegexSet as `auto`.** Correct and similar in speed on the large filesystem
  load, but it compiles all literal patterns and retained more memory than the
  Aho-Corasick prefilter.
- **Lower per-regex cache capacity.** Measured slower and not lower in private
  memory.
- **Dropping ancestor reparse checks.** The final handle path check prevents
  escape, but component checks also prevent an inside-root link from bypassing
  path-based blocks. They were retained.
- **Parallel `diff-tree` processes.** Would reduce wall time but increase child
  process CPU and memory; one batched stdin process is simpler and deterministic.
- **Persistent worker pool.** No demonstrated memory benefit for the current
  per-regex cache model.

## Limits

- The 50-configuration production matrix was not run in CP5.
- Batched discovery is fail-closed on timeout: commits in the in-flight batch
  may be recorded uninspected instead of partially applied. This is conservative
  but can report more uninspected units under an exceptionally short deadline.
- The serialized batch reader is a throughput ceiling for very large histories
  with many large blobs.
- The prefilter still relies on literals; a rule with no proven literal runs on
  every window. All current provider rules have a proof, but future rules may not.
- Filesystem discovery and per-file containment checks remain the floor for
  many-small-file workloads.
