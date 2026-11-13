# CP11 representative local-artifact execution evidence

These reports were produced on 2026-11-13 (America/New_York) from **existing
local artifacts only**; no scanner was downloaded or built for CP11.

They are representative execution evidence, not a refreshed performance
baseline. Measurements use the `DEV` environment profile and are not publishable
release evidence. The operator's `run/manifest.toml`, executables, rules, and
Docker images are Git-ignored and are not included here.

| Report | Registered build | Artifact | Suites | Meaning |
| --- | --- | --- | --- | --- |
| `gitleaks-local-levain-…` | `gitleaks-local` | executable SHA-256 `e0831964…` | `levain` | Artifact verification, Levain detection + performance, exact argv, sequential execution |
| `rnc-cp4a-docker-synthetic-…` | `rnc-cp4a-local` | Docker image `sha256:f05f1b34…` | `synthetic-filesystem` | Local-only image ID/architecture verification, `docker run --rm --pull=never`, ruleset validation, exact Docker command, container cleanup |
| `gitleaks-bad-…` | `gitleaks-bad` | expected SHA-256 `000…` | `all` | Incorrect executable hash reported as `BLOCKED`; no scanner invocation and no substitution |

Observed results in the successful reports:

- Gitleaks Levain: 47/85 true positives, 3 false positives, 1 partial,
  2 duplicates — the existing CP10 result, unchanged by the artifact refactor.
- RNC Docker synthetic filesystem: 4/4 expected detections, 100% precision/F1
  for the controlled fixture.
- The RNC Docker report records the full `docker run` command, including
  `--rm`, `--pull=never`, image tag/ID, labels, mounts, and scanner arguments.
  Cleanup reported `images_removed: []`; the registered image remained present.

See the [CP11 implementation report](../../docs/checkpoints/CP11-local-artifact-execution-report.md)
for the full validation scope and limitations.
