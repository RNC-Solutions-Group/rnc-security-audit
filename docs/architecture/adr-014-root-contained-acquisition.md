# ADR-014 — Root-contained acquisition and atomic report publication

- **Status:** Accepted for CP2 hardening
- **Date:** 11 November 2026

## Context

CP2 used `symlink_metadata` for discovery and `O_NOFOLLOW` for the final source component. Neither protects against replacing an ancestor directory with a symlink between discovery and read. Report output similarly resolved the parent and then opened by path, leaving a check-to-use window and permitting relative-path ambiguity.

## Decision

### Source acquisition

- On Unix, open the authorized root and every intermediate source directory with `openat` + `O_NOFOLLOW`, then open the final component with `O_NOFOLLOW`. The file is read from the resulting descriptor, and size/mtime checks use that descriptor.
- On Windows, reject reparse-point ancestors/final targets, open the final component with `FILE_FLAG_OPEN_REPARSE_POINT`, and verify the opened handle's `GetFinalPathNameByHandleW` path remains beneath the canonical root before reading. This closes ancestor substitution for content reads; path-based directory enumeration remains a documented residual race.
- On other platforms, canonicalize and verify containment; fail closed if the guarantee cannot be established.
- Discovery has bounded entries, depth, time, and policy-matching work. An aborted discovery is an execution failure, never a completed clean scan.

### Report publication

- Resolve relative paths against the process working directory; never fall back to an unresolved relative path.
- Canonicalize the parent, require it outside the canonical scan root, and reject final symlinks/reparse points, directories and non-regular files.
- On Unix, create a uniquely named temporary file with `openat` and `O_NOFOLLOW`, write/fsync it, and `renameat` it into the already-open parent directory. This closes ancestor substitution and final-component redirection windows.
- On Windows, open and verify a parent directory handle, create a temporary file and verify its handle resolves within that parent, then publish with `NtSetInformationFile(FileRenameInformation)` relative to the verified parent handle. Windows ACL inheritance is documented; Unix modes are not claimed.
- Private reports use mode `0600` on Unix. Windows security relies on the destination directory ACL; this is not claimed to be Unix-mode equivalent.

## Consequences

- A swapped ancestor symlink cannot redirect source reads on Unix.
- A report cannot be redirected into the scan root or through a final symlink.
- A partially written report is never published as complete evidence.
- Windows uses handle-verified source reads and parent-relative publication; only path-based discovery enumeration and ACL inheritance are documented residual differences.
- Discovery and policy work cannot be driven without bound by hostile selector/path shapes.

## Validation

Unix CLI/report tests (run in a Linux container and CI), ancestor-substitution engine test, discovery-budget tests, atomic replacement/permission tests, and CP2 benchmark.
