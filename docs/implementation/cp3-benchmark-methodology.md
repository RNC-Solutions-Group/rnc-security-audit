# CP3 benchmark methodology

> **Historical CP3 evidence; internal benchmark CI retired in CP4A.** Detection
> accuracy, comparative evaluation and performance benchmarking are owned by
> the independent RNC Scanner Harness. `tools/cp3/bench.py` and the recorded CP3
> results are preserved for historical traceability, not routine required CI.
> A faster scan with a missing family was never accepted as a result.

## Harness

`tools/cp3/bench.py` drives the actual release CLI. Before accepting a timing it
checks the scanner summary count against the independently constructed workload
count. It records the effective backend from the same run.

- Binary: `target/release/rnc`, SHA-256 recorded in the report.
- Rules: `rules/rnc-providers-v1.json`, file SHA-256 recorded.
- Runs: **3** per profile; median, p95, min and max are reported.
- Modes: `whole` and `stream` (`--stream-chunk-bytes 65536`).
- Strategies: `regex`, `regexset`, `prefilter`, `auto`.
- Profiles: **11 workloads x 2 modes x 4 strategies = 88**.
- Caps: 64 MiB per file, 128 MiB total, 20,000 findings.
- Wall time: measured around the process.
- CPU and peak RSS: measured only when a GNU `time` wrapper is available. On
  Windows PowerShell the wrapper is absent, so those fields are `null`; the
  Linux CI lane provides them. Wall times from different machines are not
  presented as a controlled speed comparison.
- Rule compilation: `rnc rules validate` repeated three times; median/p95
  reported separately.

## Workloads

| Profile | Shape | Purpose |
| --- | --- | --- |
| `large-low` | 8 MiB, 64 AWS key IDs | Low-density large-file acquisition/regex cost |
| `large-high` | 8 MiB, 4,096 Google keys | High-density candidate and validation cost |
| `small-many` | 500 × 4 KiB files, one GitHub token each | Per-file discovery/open/finding overhead |
| `credential-configs` | 4 MiB, AWS/GitHub/generic assignments | Credential-heavy configuration directory |
| `fp-heavy` | 4 MiB decoys, placeholders, malformed values | Validation and false-positive filtering |
| `high-entropy` | 4 MiB random base64/hex, no assignment | Benign high-entropy content |
| `multi-family` | 16 findings per block, 64 blocks, all catalog rules | Mixed provider matching and validator cost |
| `long-pem` | 32 multiline RSA-shaped containers | Long multiline container matching |
| `github-installation-long` | 4 MiB, 256 modern `ghs_APPID_JWT` tokens | Long installation-token candidates and bounded segment matching |
| `structured` | 128 JWT Bearer + database URI pairs | Structured-token parsing cost |
| `same-line` | 256 lines with two GitHub tokens each | Same-line occurrence correctness |

The reduced local matrix keeps the full mode/strategy comparison while fitting a
developer workstation. The isolated CI benchmark uses the same workload
definitions; run-to-run comparisons must use the same host and build.

The corrected catalog has 19 rules and 12 families. The pre-correction benchmark
used 16 rules. Workload composition therefore changed, and a cross-version
number is reported as a workload-plus-engine change, never as a pure speedup.
The RegexSet strategy continues to use the required-literal filter, not the
pathological full-pattern set. `github-installation-long` was added specifically
to exercise the new bounded modern token path.

## What is and is not measured

The reported wall time covers discovery, acquisition, matching, validation,
finding construction, policy/result construction and report bookkeeping. The
current CLI does not expose separate phase timers, so acquisition, matching and
reporting costs are **not claimed separately**. Validator overhead is not
isolated from matching; a future instrumented build is required for that claim.

Filesystem cache state is not artificially controlled. Repeated runs on the same
host reduce cold-cache effects but do not eliminate them. The benchmark does not
compare different CI runners as a controlled speedup.

## Commands

```sh
cargo build --release --workspace --locked
python -m tools.cp3.bench \
  --binary target/release/rnc \
  --runs 3 \
  --build-seconds <measured> \
  --binary-sha256 <sha256> \
  --output artifacts/cp3/bench.json
```

The machine-readable artifact includes host platform, CPU count, Python version,
rule-compile statistics, per-profile samples and effective backend. It is
generated evidence, not a committed benchmark claim for another host.
