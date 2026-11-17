# CP5 independent-harness handoff

> The independent RNC Scanner Harness owns scoring, the production matrix, OS
> telemetry and the consolidated report. This document defines the scanner-side
> contract. It does not authorize scanner-side scoring, oracle modification or a
> claim of independently verified results.

## Executable provenance

| Field | Value |
| --- | --- |
| CP4C reference source | `805e3bb79276b94de636e27024f38773da303b44` |
| CP5 code commit | `e885b1431820e877991f10977e818ef192eaddef` |
| CP5 branch | `feat/cp5` |
| CP5 documentation head | branch `feat/cp5` head; documentation-only delta after the code commit |
| Target | Native Windows AMD64 |
| Profile | `release`, `--locked`, LTO thin, one codegen unit, stripped |
| Toolchain | Rust 1.85.0 |
| Executable | `target/release/rnc.exe` |
| Executable SHA-256 | `2EA24B42D3E453E82CD344EC7E62210BA8A3344FA9BA49EDA33B5864482D0A4C` |
| Executable size | 3,109,888 bytes |
| Ruleset | `rnc-providers-v1` `2026.11.6` |
| Ruleset SHA-256 (bundle file) | compute in the harness workspace; the scanner reports `sha256:b893978c4a720c41951a20c0771d67f29bbb54ad1057a6bd5bf0feef68c5de2a` as the canonical digest |
| Rules | 38 rules / 23 families |

Build and verify:

```powershell
cargo build --release --locked -p rnc-cli
Get-FileHash target\release\rnc.exe -Algorithm SHA256
.\target\release\rnc.exe --version
.\target\release\rnc.exe rules validate --rules rules\rnc-providers-v1.json
```

The rules digest is the scanner's canonical JSON digest, not necessarily the raw
file hash. Record both.

## Intentional default changes from CP4C

The CP4C reference behavior is still available exactly:

```text
--workers 1 --git-io process --history-mode whole --strategy regex
```

CP5 defaults:

| Setting | CP4C default | CP5 default | Reason |
| --- | --- | --- | --- |
| `--workers` | `1` | `1` | Unchanged; `auto` remains explicit |
| `--strategy` | `auto` → `regex` | `auto` → `prefilter` | Exact candidate equivalence; material speedup |
| `--git-io` | `process` | `batch` | Exact object equivalence; process fallback |
| `--history-mode` | `whole` | `whole` | Unchanged |
| `--mode` | `auto` | `auto` | Unchanged |

The baseline CP4C executable must be run with its own ruleset and its own
defaults. Do not run the CP4C binary with the CP5 rule bundle: the CP4C binary
does not know `WORDPRESS_SALT` and rejects the bundle.

## Recommended scanner invocations

Accuracy and coverage (per corpus lane):

```text
rnc scan --root <lane-root> --rules <cp5-rules.json> --output <private.json>
         --format private --run-id <id> --workers auto --mode auto --strategy auto
```

Git history:

```text
rnc scan --history --root <repo> --rules <cp5-rules.json>
         --output <private.json> --format private --run-id <id>
         --workers auto --mode auto --strategy auto
         --history-mode whole
```

Diff history control (optional):

```text
--history --history-mode diff --context-lines 3 --git-io batch
```

Performance matrix:

- Use the 50-configuration matrix in
  [CP4C harness handoff](cp4c-harness-handoff.md), with these substitutions:
  - CP4C baseline: CP4C executable + CP4C ruleset, explicit reference flags;
  - CP5 candidate: CP5 executable + CP5 ruleset.
- Record requested and effective worker/strategy values from the private
  `execution_plan` or the profile settings.
- Separate filesystem and Git workloads.
- Keep profile-on and profile-off controls.
- Do not run the Cartesian product blindly; the CP4C matrix isolates workers,
  Git I/O, history mode and context.

## Profile ingestion

Profile schema version `1` is unchanged. New worker phases:

- `scan.open` — containment open and handle verification;
- `scan.read` — bounded read;
- `scan.line_index` — line-start index construction;
- `scan.hash` — content SHA-256.

`git.deltas` now covers batched `diff-tree --stdin` plus per-merge invocations.
Phase names remain additive; unknown phases should be ignored by an ingester.
The existing [profiler contract](../contracts/profiler.md) and
[schema](../contracts/profiler.schema.json) apply.

Profiles must remain secret-free. Reject any profile containing locators,
matched values, evidence digests, finding IDs or Git object content.

## Accuracy evidence

Local target-level comparison is recorded in [CP5 validation](cp5-validation.md).
It is **not** harness-certified. The harness must re-score the CP5 executable
against the current oracle and scoring policy.

Expected CP5-specific changes:

- New WordPress authentication findings in `wp-config.php`, `.env`,
  Kubernetes secret data and quoted assignment representations.
- New generic findings for `SIGNING_KEY`, `JWT_SIGNING_KEY`,
  `PAYMENTS_SIGNING_KEY`, `HMAC_KEY`, `HMAC_SECRET` and camelCase/hyphenated
  variants.
- No CP4C finding should disappear. Generic rule versions moved to `2026.11.6`,
  so finding IDs for the four assignment families change; compare canonical
  unit/span/digest evidence, not only finding IDs.
- Source-unit counts, commits and coverage dispositions must remain identical
  for equivalent configurations.

The harness should report new true positives, retained true positives, new false
positives, coverage changes and unresolved misses separately. Do not accept a
category-level recall claim without target-level verification.

## Required outputs

```text
cp5-performance.md
cp5-performance.json
cp5-runs.csv
cp5-detection-comparison.md
cp5-detection-comparison.json
experiment manifest and provenance
individual profile JSON artifacts
```

The report must identify:

- requested/effective scanner settings;
- executable and ruleset hashes;
- corpus and oracle revisions;
- per-configuration wall, CPU, peak memory and coverage;
- files/sec and bytes/sec;
- matching and Git phases where available;
- retained, new and lost detections with target IDs;
- false positives and incomplete coverage;
- measurement variance and host load.

## Boundaries

- Do not modify the oracle or scoring policy to improve the CP5 result.
- Do not merge the harness into the scanner or the scanner into the harness.
- Do not treat local target checks or the DEV-host timings as independent
  certification.
- Do not use Docker workflows for this native Windows experiment.
- No merge or release is authorized by this handoff; the operator owns both.
