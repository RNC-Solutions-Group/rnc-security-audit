# Repository layout and local artifact policy

**Status:** current. This supersedes the CP3-era migration specification. The
harness has been relocated to `RNC-Solutions-Group/rnc-security-audit` on the
orphan `benchmark-harness` branch, and CP11 replaced source acquisition/builds
with operator-provided local artifacts.

## Current repository

- Repository: `https://github.com/RNC-Solutions-Group/rnc-security-audit`
- Branch: `benchmark-harness` (orphan; never merged into application branches)
- Scanner source is **not** cloned or compiled by the harness.
- Scanner executables, rules, and `run/manifest.toml` are local operator inputs.
- Docker images remain in the local Docker image store.

## Git-tracked

- Harness source (`harness/`) and tests (`tests/`).
- Configuration example (`harness.toml.example`).
- Local-manifest example (`run-manifest.example.toml`).
- Dataset manifests, provenance, truth manifests, and history-scope models
  (`datasets/`).
- Current contracts and methodology (`docs/scoring-contract.md`,
  `docs/history-accountability.md`, `docs/performance-methodology.md`,
  `docs/architecture.md`).
- Concise checkpoint summaries and compact, sanitized experiment evidence.
- Small sanitized experiment reports that are reviewable in a diff.

## Git-ignored / local-only

- `run/` — operator executables, rules, and the actual `run/manifest.toml`.
- Docker images — retained in Docker's local image store, never in Git.
- Dataset caches and extracted corpora (`datasets/cache/`).
- Raw scanner reports, stdout/stderr, debug logs, tracebacks, telemetry sample
  arrays, and temporary scan artifacts.
- Generated benchmark workspaces (`work/`), local reports (`reports/local/`),
  Python caches, and other disposable build/scan output.
- `AGENTS.md` is currently workstation-local; decide separately whether a
  sanitized shared version should be tracked.

## Requirements

- The verified executable SHA-256 or Docker image ID is the runtime scanner
  identity. Source commits in the manifest are provenance metadata only.
- Reports record the local manifest path/SHA-256, registered build ID,
  executable/image identity, suite/workload/platform, and exact invocation
  commands.
- Sanitized reports never contain raw credential values.
- Raw destinations must be Git-ignored or outside tracked source; the existing
  safety check remains in force.
- Historical CP1A–CP10 reports are preserved as historical evidence. They
  describe the retired source-build workflow and are not rewritten.
- The harness never deletes or retags registered scanner images or `run/`
  artifacts.
- No migration or cleanup rewrites Git history.
