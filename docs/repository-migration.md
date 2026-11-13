# Repository migration cleanup specification

**Status:** specification only. CP3 does **not** migrate repositories, delete
historical CP1A–CP2 evidence, or restructure tracked files. CP3 removes retired
harness code from this orphan branch but does not rewrite Git history.

The harness currently lives on the orphan `test/scan-harness` branch. When it is
relocated to a permanent repository, apply the following tracked/ignored split.

## Git-tracked

- Harness source (`harness/`).
- Unit/integration tests and controlled synthetic fixtures (`tests/`).
- Configuration examples (`harness.toml.example`).
- Dataset manifests and provenance (`datasets/manifest.toml`, fixture manifests).
- Truth manifests and history scope models (`datasets/leaky-repo.rnc-truth.json`,
  `datasets/leaky-repo.history-scope.json`).
- Scoring and history contracts (`docs/scoring-contract.md`,
  `docs/history-accountability.md`).
- Benchmark methodology (`docs/performance-methodology.md`).
- Concise checkpoint summaries and compact experiment evidence.
- Small sanitized experiment reports that are reviewable in a diff.

## Git-ignored or external artifact storage

- Full per-finding JSON reports, including evaluation arrays.
- Raw scanner reports and scanner stdout/stderr.
- Debug logs and tracebacks.
- Detailed execution traces.
- Runtime telemetry sample arrays.
- Temporary scanner artifacts and extracted benchmark datasets.
- Full fixture trees and caches.

## Requirements

- Full artifacts remain accessible through configurable destinations and optional
  CI artifact retention.
- Committed summaries include source repository and exact commit, checkout HEAD
  verification, scanner/product identity, manifest hashes, benchmark/performance
  version, and host/architecture labels sufficient to associate them with
  detailed evidence.
- Source commit remains the primary identity; executable hashes and image IDs are
  supporting provenance.
- Sanitized reports never contain raw credential values.
- Raw destinations must be Git-ignored or outside tracked source; the existing
  safety check is retained.
- CP1A–CP2 historical reports and CP3 experiment evidence are preserved as
  historical evidence unless a separate retention decision authorizes removal.
- The migration must not rewrite Git history.
