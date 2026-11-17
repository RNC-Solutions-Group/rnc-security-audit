# CP4 read-only Git-history acquisition

> **Status:** Implemented, locally regression-tested and covered by the CP4 CI
> workflow. This is source acquisition only. It does not add a second detection
> engine or change the ruleset, validator, policy or finding contracts.

## Command

```sh
rnc scan \
  --history \
  --root /path/to/local/repository \
  --rules rules/rnc-providers-v1.json \
  --format sanitized \
  --output /safe/evidence/history.json \
  --mode stream \
  --strategy auto
```

`--history` is required. Merely finding a `.git` directory during an ordinary
filesystem scan does not enable history acquisition and does not make `.git`
content a special source.

Optional selectors:

```sh
--ref refs/heads/main          # repeatable; exact ref or commit, not a range
--max-history-commits 2000     # fail closed beyond this commit count
--max-history-units 20000      # fail closed beyond this commit/path revision count
```

`--ref` accepts a checked ref name or commit ID. Revision operators (`..`, `^`,
`~`, `:`, `@{...}`) are rejected rather than passed to Git. With no `--ref`, the
default scope is all local reachable refs plus `HEAD`; reflogs and unreachable
objects are outside the scope.

## Traversal semantics

The adapter traverses commits in reverse topological order from the selected
refs. For each commit it computes a raw tree delta against the **first parent**;
the root commit is compared against the empty tree. A merge commit therefore
contributes its first-parent introduced/modified content, including merge
resolution changes. Side-branch commits reachable from the selected refs are
traversed separately and retain their own identities.

Changed-path semantics:

| Change | Historical treatment |
| --- | --- |
| Added file | New commit/path revision is inspected |
| Modified file | New commit/path revision is inspected |
| Deleted file | No new content revision is created. The parent revision was already inspected; the deleted credential remains in the earlier historical occurrence |
| Rename | With rename detection disabled, Git reports deletion plus addition; the new path revision is inspected. The old path remains attributed to its earlier commit |
| Merge | First-parent tree delta; resolution content is inspected under the merge commit |
| Submodule gitlink | Recorded as `UNINSPECTED` / `GIT_SUBMODULE_NOT_TRAVERSED`; no submodule traversal |
| Symlink blob | Recorded as `UNINSPECTED` / `GIT_SYMLINK_NOT_FOLLOWED`; link target is not followed |
| Binary / non-UTF-8 blob | Inspected as bytes; no text decoding is required |
| Unchanged content in a later commit | Not a new changed-path revision; a repeated value is still a distinct occurrence when it appears in a different inspected commit/path revision |

The result is a set of **commit/path content revisions**, not a full snapshot of
every file in every commit. This is the documented occurrence model. A unique
credential view may be derived from evidence digests, but it must not replace
the occurrence-level findings.

## Source identity contract

| Field | History value |
| --- | --- |
| `source_adapter.id` | `local-git-history` |
| `source_id` | `local-git-history:<first 16 hex of sha256(canonical Git directory path)>` |
| `source_kind` | `git_commit_blob` |
| `locator` | `commit/<commit-oid>/<repository-relative-path>` |
| `unit_id` | `u-` + sha256(`source_id` + NUL + `locator`) |
| `start_byte`, `end_byte` | Offsets in the original blob bytes |
| `line`, `line_end` | Lines in the original blob bytes |
| `evidence_digest` | SHA-256 of the original matched blob bytes |
| `finding_id` | Existing formula over `unit_id`, rule, version, offsets and digest |

The repository identity is a private path-derived correlation value. Sanitized
reports expose only history counts and scope, not repository paths, commit IDs or
locators. A private report can join a finding to its execution unit to recover
the commit, path and byte position.

Identical bytes in two commits or paths produce different `unit_id` and
`finding_id` values. They are separate historical occurrences; duplicate
accounting is based on occurrence identity, not raw value identity.

## Read-only and containment controls

- No checkout, branch switch, reset, merge, add, commit or index write.
- No Git hooks, external diff drivers, textconv filters or content filters.
- No fetch, remote authentication or network operation.
- No submodule traversal.
- No use of `.git` working-tree content as a substitute for object content.
- The adapter resolves the repository's Git directory and hashes its canonical
  path for identity.
- Shallow repositories are rejected because parent evidence is incomplete.
- Partial/promisor repositories and non-empty object alternates are rejected
  because required objects may be missing or outside the approved repository.
- Missing or corrupt objects become `GIT_OBJECT_UNAVAILABLE` and the final
  result is `FAILED`, never a clean scan.
- Command output, commit count, revision count, per-blob size and total bytes are
  bounded. Output-cap or deadline exhaustion is a failure.
- The Git process environment removes `GIT_DIR`, `GIT_WORK_TREE`, index/object
  redirection, external-diff, SSH, askpass and related variables; optional locks,
  prompts and lazy fetching are disabled. Replacement objects are disabled.
- Commands are executed with an argument vector, never a shell, and refs are
  validated before use.
- Report destinations remain outside the repository root under the existing
  private-publication controls.

The regression test hashes all `.git` file contents before and after a scan and
requires an unchanged `HEAD` and clean `git status`. This tests the adapter's
observable read-only behavior; it is not a claim that a hostile local Git
executable is sandboxed.

## Edge behavior

| Case | Behavior |
| --- | --- |
| Empty repository | `EMPTY_GIT_HISTORY` warning; zero required units; result `INCOMPLETE` (`NO_REQUIRED_SCOPE`) |
| Detached HEAD | Included by default and by explicit `--ref HEAD` if it resolves to a commit |
| Bare repository | Supported through `git -C <bare repository>` |
| Shallow clone | Rejected before history traversal |
| Partial/promisor clone | Rejected before history traversal |
| Object alternates | Rejected if the alternates file is non-empty |
| Corrupt or missing object | Unit `UNINSPECTED`; fatal `GIT_OBJECT_UNAVAILABLE`; result `FAILED` |
| Non-UTF-8 or non-canonical path | Fatal `GIT_INVALID_DATA`; result `FAILED` |
| Submodule gitlink | Explicit uninspected unit; result `INCOMPLETE` |
| Symlink blob | Explicit uninspected unit; result `INCOMPLETE` |
| Commit/unit/output limit | Fatal `GIT_COMMIT_LIMIT`, `GIT_UNIT_LIMIT` or `GIT_OUTPUT_LIMIT`; result `FAILED` |
| Merge commit | First-parent delta; resolution content attributed to the merge commit |
| Rename | Delete plus add under disabled rename detection; new path inspected |
| Large blob | `FILE_SIZE_LIMIT`; required coverage incomplete |
| Timeout | Remaining units accounted `TIMEOUT`; result not completed clean |
| Unreachable objects/reflogs | Excluded and documented; not silently treated as inspected |
| Submodules | Not traversed; explicit incomplete coverage |

## Policy and reporting

Historical units flow through the same pre-scan policy check before any blob read
(`LocalSource::apply_policy_to_discovery`). Blocked commit/path revisions are
`VERIFIED_BLOCKED`; no content is requested. Post-scan exemptions use the same
policy model. Reports and CI decisions consume the same execution, detection,
policy and result records.

The summary distinguishes the source and reports history counts:

```text
Source: local-git-history
History: 7 commits, 9 changed paths, 1 deletions, 7 revisions (all-reachable-refs-and-head)
```

The sanitized report adds only scope and counts. The private report includes the
repository path, refs and commit/path unit records; keep it outside the
repository and protect it as private evidence.
