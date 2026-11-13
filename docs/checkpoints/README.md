# Checkpoint reports

These reports are historical records of the checkpoint named in each file. They
retain the repository, branch, commit, source-build, and CLI details that were
current when the work was performed.

**Current execution model:** CP11 and later use operator-provided executables,
rules, and locally retained Docker images registered in `run/manifest.toml`.
Scanner source is not cloned, checked out, compiled, or built by the harness.
See [`CP11-local-artifact-execution-report.md`](CP11-local-artifact-execution-report.md)
and [`docs/architecture.md`](../architecture.md).

Historical references to `test/scan-harness`, `RNC-Solutions-Group/gitleaks`,
`--repo`, `--commit`, disposable checkouts, or source-built images describe the
workflow at the time of that checkpoint and are intentionally not rewritten.
Current commands and identity rules are in the harness [`README.md`](../../README.md).
