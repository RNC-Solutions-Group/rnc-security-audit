# ADR-014 — Root-contained acquisition and atomic report publication

- **Status:** Accepted for CP2 hardening
- **Date:** 11 November 2026

## Context

CP2 used `symlink_metadata` for discovery and `O_NOFOLLOW` for the final source component. Neither protects against replacing an ancestor directory with a symlink between discovery and read. Report output similarly resolved the parent and then opened by path, leaving a check-to-use window and permitting relative-path ambiguity.

## Decision

### Source acquisition

- On Unix, open the authorized root and every intermediate source directory with `openat` + `O_NOFOLLOW`, then open the final component with `O_NOFOLLOW`. The file is read from the resulting descriptor, and size/mtime checks use that descriptor.
- On Windows, canonicalize the target, prove it remains beneath the canonical root, reject reparse-point ancestors/final targets, and open the final component with `FILE_FLAG_OPEN_REPARSE_POINT`. Win32 does not expose a stable public directory-relative open chain; the residual ancestor race is documented rather than hidden.
- On other platforms, canonicalize and verify containment; fail closed if the guarantee cannot be established.
- Discovery has bounded entries, depth, time, and policy-matching work. An aborted discovery is an execution failure, never a completed clean scan.

### Report publication

- Resolve relative paths against the process working directory; never fall back to an unresolved relative path.
- Canonicalize the parent, require it outside the canonical scan root, and reject final symlinks/reparse points, directories and non-regular files.
- On Unix, create a uniquely named temporary file with `openat` and `O_NOFOLLOW`, write/fsync it, and `renameat` it into the already-open parent directory. This closes ancestor substitution and final-component redirection windows.
- On Windows, create a temporary file with `create_new`, write/fsync it, and publish with `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)` after reparse checks. The residual parent-substitution race and inherited-ACL limitation are documented.
- Private reports use mode `0600` on Unix. Windows security relies on the destination directory ACL; this is not claimed to be Unix-mode equivalent.

## Consequences

- A swapped ancestor symlink cannot redirect source reads on Unix.
- A report cannot be redirected into the scan root or through a final symlink.
- A partially written report is never published as complete evidence.
- Windows has a documented narrower guarantee than Unix; the implementation does not claim otherwise.
- Discovery and policy work cannot be driven without bound by hostile selector/path shapes.

## Validation

Unix CLI/report tests (run in a Linux container and CI), ancestor-substitution engine test, discovery-budget tests, atomic replacement/permission tests, and CP2 benchmark.
