# CP2 operator guide

> Implemented in CP2. All examples use harmless synthetic markers.

## Build

```sh
rustup toolchain install 1.85.0 --profile minimal
cargo build --release --workspace --locked
target/release/rnc --version
```

## Scan

```sh
target/release/rnc scan \
  --root /approved/repository \
  --rules rules/rnc-synthetic-v1.json \
  --format summary
```

The default summary contains counts, backend, result and CI acceptance only. It never prints locators, finding IDs, evidence digests or matched bytes.

### Strategies

```sh
rnc scan ... --strategy regex       # reference; always available
rnc scan ... --strategy regexset    # multi-pattern selection + exact extraction
rnc scan ... --strategy prefilter   # required-literal prefilter + exact extraction
rnc scan ... --strategy auto        # conservative: reference regex today
```

`auto` intentionally does not promote an alternative until it has a defensible whole-workload advantage. `regexset` and `prefilter` remain explicit and are held to exact differential equivalence. `rnc rules validate --strategy ...` prints the effective plan, literal coverage and any fallback.

### Reports

```sh
# Human summary
rnc scan ... --format summary

# Sanitized machine-readable JSON (stdout, or --output outside root)
rnc scan ... --format sanitized
rnc scan ... --format sanitized --output /approved/reports/scan.json

# Private evidence (never stdout)
rnc scan ... --format private --output /approved/private/evidence.json
# json is a compatibility alias for private and requires --output
rnc scan ... --format json --output /approved/private/evidence.json
```

Private evidence is written outside the scan root with mode `0600` on Unix. It contains execution, finding and policy ledgers plus execution-plan and configuration provenance. Sanitized output contains only engine/ruleset metadata, aggregate counts, result, coverage, reason codes and CI acceptance.

### Configuration

```sh
rnc scan ... --global-config /etc/rnc/global.toml \
             --config /approved/repository/.rncscanner.toml
```

Without `--config`, the loader looks for `.rncscanner.toml` or `security.config` under the scan root. Both present is a hard failure. The global file is optional but its mandatory blocks and acceptance caps prevail. Unknown fields, unsafe reporting, symlink following and malformed selectors fail before scanning.

### Policy

```sh
rnc scan ... --exclude 'secrets/**'          # verified pre-scan block
rnc scan ... --block 'vendor/**'              # same, clearer name
rnc scan ... --exempt 'rule:synthetic-aws;path:tests/fixtures/**'
rnc scan ... --skip 'generated/**' --optional 'generated/**'
```

A block is enforced during discovery, before the adapter opens content. A skip is an uninspected unit; an optional skip does not make required coverage incomplete. An exemption is evaluated after detection, preserves the raw finding, and only changes its disposition.

### CI acceptance

```sh
rnc scan ... --accept-result 1 --accept-result 2
```

Effective acceptance is the intersection of global, repository and CLI lists. `CLEAN` and `POLICY_APPLIED` default to accepted; `ACTIONABLE` only when explicitly authorized. `INCOMPLETE` and `FAILED` always exit `20`/`30`. Process exits are `0` accepted, `10` rejected completed result, `20` incomplete, `30` failed, `64` invalid invocation/configuration/publication before or outside the scan result.

### Benchmarks

```sh
python -m tools.cp2.bench \
  --binary target/release/rnc \
  --runs 3 \
  --output artifacts/cp2/benchmark.json
```

The report records all strategies, modes, workload size, finding-count correctness, median/p95, throughput, files/s, RSS/CPU where available, build/binary identity and plan fallback metadata. It is benchmark evidence, not a production accuracy claim.

### Independent validation

```sh
python -m tools.cp0.generate_edge_corpus --output artifacts/cp2/edge
python -m tools.cp2.integration_check \
  --binary target/release/rnc \
  --output artifacts/cp2/integration.json \
  --edge-corpus artifacts/cp2/edge
python -m tools.cp2.policy_check \
  --binary target/release/rnc \
  --output artifacts/cp2/policy.json
```

These tools stage only source bytes (never truth manifests), validate the v0.2 records with the independent CP0 validator, and compare findings to independently expanded truth. The external harness remains the owner of accuracy scoring.

## Current limitations

- Single-threaded scan execution; parallel scanning is deferred.
- Cooperative deadlines only; OS-signal cancellation is not implemented.
- No external corpus execution; Levain/Leaky Repo/Prowlbench remain future work.
- Same-rule/same-line external-harness ambiguity remains; RNC findings stay byte-addressed.
- No installer/signing; x86_64 static musl is build-validated.
- Committed rules remain synthetic test rules.
