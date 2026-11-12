# Source acquisition and report publication security

> **Implemented in CP2 hardening.** The guarantees below are platform-specific and deliberately stated narrowly.

## Authorized-root containment

The canonical scan root is established once. Discovery records canonical relative locators and pre-scan policy decisions before any content read. The detector never receives content for a `VERIFIED_BLOCKED` unit.

### Unix (Linux and macOS)

- The root is opened with `O_DIRECTORY | O_NOFOLLOW`.
- Every intermediate component is opened with `openat(..., O_DIRECTORY | O_NOFOLLOW)`.
- The final component is opened with `openat(..., O_RDONLY | O_NOFOLLOW)`.
- Content size, line count and hash are read from the opened descriptor. Metadata checks use the descriptor, not a re-resolved path.
- Replacing an ancestor or final component with a symlink after discovery causes the read to fail and the unit to be recorded `UNINSPECTED`; it cannot redirect content outside the root.
- Symbolic-link entries are recorded as uninspected during discovery. Directory-wide blocks are inherited while enumerating; the files are never opened.

### Windows

- The target is canonicalized and required to remain beneath the canonical root.
- Every ancestor and the final component are checked for `FILE_ATTRIBUTE_REPARSE_POINT` / symlink; a reparse point is rejected.
- The final component is opened with `FILE_FLAG_OPEN_REPARSE_POINT`.
- After opening, the implementation resolves the file handle with `GetFinalPathNameByHandleW` and rejects it if the handle resolves outside the canonical root. This closes ancestor substitution for the content read.
- Directory enumeration is still path-based on Windows; an ancestor substitution during discovery is a documented residual race. A swapped directory is rejected by canonical containment and reparse checks; the file read has the stronger final-handle guarantee.
- Windows private report files receive an explicit protected DACL (see [Private evidence on Windows](#private-evidence-on-windows)); it is not claimed to be Unix-mode equivalent.

### Other platforms

Canonicalize, verify prefix containment, and read. If a secure containment primitive is unavailable, the scanner must fail closed rather than treat a path string as proof.

## Discovery budgets

| Bound | Default |
| --- | --- |
| Entries enumerated | 1,000,000 |
| Directory depth | 128 |
| Discovery/policy deadline | overall scan timeout |
| Policy glob work | 50,000,000 estimated segment-cells |
| Selectors | 256 |
| Selector segments | 64 |
| Matched path segments | 256 |

Policy matching uses dynamic programming over pattern/path positions, avoiding combinatorial recursion on repeated `**` segments. A budget exhaustion sets `DISCOVERY_TIMEOUT`, `DISCOVERY_ENTRY_LIMIT`, `DISCOVERY_DEPTH_LIMIT` or `POLICY_BUDGET_EXCEEDED` as a fatal discovery error; the final result is `FAILED`, never a completed clean scan.

## Read-only Git history

CP4 adds a separate `local-git-history` adapter; a .git directory is not
implicitly scanned by working-tree mode. The adapter is selected with
`--history` and asks a controlled local Git executable for commit topology,
first-parent raw tree deltas and object bytes.

- No checkout, index write, branch update, hook, external diff, textconv, fetch
  or submodule traversal occurs.
- `GIT_DIR`, `GIT_WORK_TREE`, index/object redirection, replacement objects,
  external-diff, SSH and askpass variables are removed or disabled. Optional
  locks, prompts and lazy fetching are disabled.
- Shallow repositories, partial/promisor clones and non-empty object alternates
  are rejected because required evidence may be incomplete or outside the
  repository boundary.
- Missing/corrupt objects, over-limit histories, invalid paths and command
  failures are fatal; they cannot produce a clean result.
- Stdout/stderr are capped, the process is killed on deadline or output excess,
  and `cat-file` content is bounded by the per-file scan limit.
- Commit/path units are assigned `source_id = local-git-history:<hash>` and
  `locator = commit/<oid>/<path>`. Findings retain original blob offsets,
  lines, evidence digests and occurrence identity.
- Pre-scan blocks are evaluated against commit/path locators before any blob
  read. The existing policy and reporting contracts remain authoritative.

See [ADR-016](adr-016-read-only-git-history.md) and the
[CP4 history guide](../implementation/cp4-git-history.md) for the full contract
and edge behavior.

## Report publication

Report destinations are resolved relative to the process working directory. An unresolved parent is an error; the loader never falls back to the original relative spelling.

- The canonical parent and final path must be outside the canonical scan root.
- Existing final symlinks/reparse points, directories and non-regular files are rejected.
- Unix creates a unique temporary file in the already-open parent directory with `openat(O_CREAT|O_EXCL|O_NOFOLLOW)`, writes, flushes, fsyncs, sets `0600` for private evidence, and atomically `renameat`s it. A substituted parent cannot redirect the operation.
- Windows opens the parent with `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`, verifies its final handle path, creates a temporary file and confirms its handle resolves within that parent, then publishes with `NtSetInformationFile(FileRenameInformation)` using the validated parent handle. This removes the path-based parent-substitution window for publication.
- Failure or interruption leaves the prior destination untouched and the temporary file is removed where the process can do so.
- A publication failure exits `30`; it is never reported as a successful scan.

## Private evidence on Windows

Unix `0600` is enforced on the created file. CP4A also creates Windows private report temporary files with an explicit **protected DACL**, rather than relying only on inherited directory permissions. The DACL grants file-all-access to the current user, `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`, and to no other principal.

- The security descriptor is supplied to `CreateFileW` when the temporary file is created, so sensitive payload bytes are written only after restrictive access is in place.
- The opened handle's DACL is inspected before the first payload write. Unexpected, inherited, partial or duplicate ACEs cause publication to fail; the temporary file is removed and no report is published.
- The temporary file is renamed into the destination with `NtSetInformationFile`; the final report keeps the same restrictive DACL. Replacing an existing file does not inherit a broader parent ACL.
- A deliberately permissive parent, an existing destination, and unrelated low-privilege principals are covered by a Windows regression test using effective-rights checks.

This is a narrower guarantee than Unix mode bits: Windows ownership, backup/restore privileges, administrators and kernel-level access remain outside the scanner's control. Operators should still keep private reports outside inspected trees and in access-controlled storage.

## Verified non-access

A pre-scan block is recorded only when the unit is excluded during discovery and never opened. A Unix test blocks a mode-`000` file and requires `VERIFIED_BLOCKED` with no content evidence; if the scanner opened it, the operation would fail rather than produce a block record. Directory-wide blocks are inherited before file content reads.

## Residual risks

- Windows directory enumeration is path-based; an ancestor swap during discovery is a residual race. Windows private report files now have an explicit verified DACL, but ownership, administrator and kernel-level access remain outside scanner control. The file-read and report-publication operations use handle-verified paths.
- A process with write access to the authorized root can replace files with different regular files; descriptor metadata checks detect size/mtime changes but cannot prove semantic continuity for a same-size/same-timestamp replacement.
- Filesystem I/O that blocks inside the kernel may exceed cooperative deadlines; no OS-signal cancellation is implemented in CP2.
- Discovery still uses path-based `read_dir` after canonical checks on Windows; Unix file opens are fd-relative but directory enumeration is not a full openat handle walk.
