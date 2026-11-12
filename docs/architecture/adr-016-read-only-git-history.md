# ADR-016: read-only Git-history acquisition through a controlled Git process

**Status:** Implemented in CP4
**Date:** 2026-11-11
**Decision owner:** RNC Scanner development
**Related:** [Source acquisition](source-acquisition.md), [CP4 Git history](../implementation/cp4-git-history.md), [CP4 validation](../implementation/cp4-validation.md)

## Context

CP1-CP3 acquire local working-tree files only. A credential removed from a
working tree can remain in reachable commits. CP4 adds a read-only source
adapter without creating a second detector, changing finding identity, or
writing to the inspected repository.

The adapter must not:

- check out a revision, change branches, reset, stage or modify the index;
- run hooks, external diff drivers, textconv filters or content filters;
- fetch missing objects, authenticate to a remote, or traverse submodules;
- read outside the approved repository through object alternates;
- treat a missing/corrupt object, limit exhaustion or incomplete history as a
  completed clean scan;
- publish raw credential bytes or a private absolute repository path in a
  sanitized report.

## Options considered

| Option | Advantages | Costs and risks |
| --- | --- | --- |
| `git2` / libgit2 bindings | Library API; no Git process parsing | Native C build, platform toolchain variance, larger dependency and advisory surface, still needs explicit shallow/alternate policy |
| `gix` / gitoxide crates | Pure-Rust object access; strong typed object model | Large dependency graph and API surface; substantially longer build; must still enforce repository boundary, lazy-object and submodule policy |
| Controlled local `git` commands | No new dependency; audited read-only commands; the installed Git already understands worktrees, bare repositories and object storage; easy to bound stdout/stderr and kill on timeout | Runtime dependency on a Git executable; output grammar must be parsed strictly; local configuration and environment must be constrained |

## Decision

Use a narrowly controlled local `git` executable for history acquisition.
Every invocation is constructed without a shell and with a fixed argument
vector. The adapter uses only:

- `rev-parse` for repository identity, shallow/partial/alternate checks and
  explicit ref resolution;
- `rev-list --parents --topo-order --reverse` for bounded commit topology;
- `diff-tree --raw -z --no-renames --no-ext-diff --no-textconv` for changed-path
  metadata and blob identities;
- `cat-file blob` for bounded content reads.

The process environment removes repository-redirection and execution variables,
disables optional locks, terminal prompts, lazy fetches and replacement objects,
and limits protocol use. Shallow repositories, partial/promisor clones and
non-empty object alternates are rejected rather than silently scanned partially.
Output is capped; exceeding a cap kills the process and fails the scan.

No checkout, index operation, hook, external diff, network operation or
submodule traversal is performed. The existing rule catalog, validators, policy
engine, finding builder, execution accounting and report contracts remain
authoritative.

## Consequences

### Positive

- No new Rust or native dependency; the scanner remains a static Rust binary.
- Read-only behavior is inspectable at the command boundary and testable by
  comparing repository contents before and after a scan.
- Bare repositories, worktrees, detached HEAD and merge-parent semantics are
  delegated to Git's well-tested object model.
- Process output, deadline and kill behavior are under scanner control.

### Negative

- `rnc` history mode requires a compatible `git` executable at runtime. Missing
  Git is an explicit operational error, not a clean scan.
- The adapter depends on stable machine-readable output from `rev-list`,
  `diff-tree --raw -z` and `cat-file`; parsers reject unexpected records.
- Local Git configuration can affect repository interpretation. The adapter
  disables replacement objects and execution-capable paths, rejects alternates,
  and does not invoke hooks or diff drivers; it does not attempt to sandbox the
  Git executable itself.
- Git-history acquisition cannot prove that an object store is uncompromised.
  Corrupt or missing objects are reported as failures.

## Revisit criteria

Revisit this decision if any of the following becomes true:

- a maintained, appropriately licensed pure-Rust object reader supports the
  project's MSRV with an acceptable dependency and advisory profile;
- the Git command interface used here becomes unstable on a supported platform;
- the operator requires sandboxed history acquisition with no child process;
- performance evidence shows process-per-blob acquisition is the limiting
  factor for an approved workload.
