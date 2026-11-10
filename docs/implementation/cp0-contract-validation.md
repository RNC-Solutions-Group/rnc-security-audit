# CP0 — Contract validation, full synthetic corpus and Go/Rust probe

**Status:** In progress, pending observed Go/Rust benchmark results, external-corpus availability decisions and final architecture review. No production scanner code or measured RNC detection accuracy exists.

## Approved decisions

1. Benchmark **Go and Rust**, then select the detector language from evidence (not popularity).
2. Use **one versioned config schema**, with explicit mapping and no silent dual-loading of legacy `security.config`.
3. Accept `CLEAN` and `POLICY_APPLIED` by default in CI; `ACTIONABLE`, `INCOMPLETE` and `FAILED` yield nonzero unless the completed actionable state is explicitly accepted.
4. Include the **full synthetic corpus plus comparable language probes during CP0**, not merely a small conceptual decision table.

## CP0 artifacts

| Artifact | Content | Status |
| --- | --- | --- |
| [Contracts](../contracts/README.md) | Six JSON Schemas for input/finding/execution/policy/result/CI, plus cross-record rules | Drafted and locally validated |
| [ADR register](../architecture/decisions.md) | Go/Rust, config migration, CI and corpus directions | Decision recorded |
| [Threat model](../architecture/threat-model.md) | Security boundaries and failure modes | Drafted |
| `tests/fixtures/synthetic-v0/manifest.json` | Nine hand-authored targets with **14 known harmless markers** including a blocked target | Locally validated |
| `tools/cp0/generate_corpus.py` | Deterministic **1,000-target synthetic corpus** with 2,000 known markers and per-target hashes/locations/dispositions | Local repeatability verified |
| `tools/cp0/reconcile.py` | Schema-aligned reference ledger reconciliation and negative integrity checks | Unit tested; not product code |
| `tests/fixtures/synthetic-v0/outcome-cases.json` | Twelve independently declared result/precedence cases | Locally validated |
| `tools/cp0/synthetic_stub.py` | Perfect, missed-finding, false-positive output for independent harness calibration | Unit tested; not harness certified |
| `tools/cp0/probe.go` and `probe.rs` | Same literal byte-search workload, explicitly **not production regex/detection engines** | Awaiting Go/Rust toolchains and CI artifact |
| `tools/cp0/benchmark.py` | Same-hardware, same-file, pinned-toolchain, multi-size/density, alternating-run median measurements and correctness checks | Script created; execution pending |

## Local validation commands

```sh
python -m pip install -r requirements-cp0.txt
python -m tools.cp0.validate
python -m unittest discover -s tests/cp0 -v
python -m tools.cp0.generate_corpus --output /tmp/rnc-cp0-corpus
python -m tools.cp0.synthetic_stub --mode perfect
```

Once Go and Rust compilers are available on the **same machine**:

```sh
python -m tools.cp0.benchmark --runs 5 --output /tmp/rnc-cp0-benchmarks.json
```

The CI workflow is intended to collect JSON benchmark artifacts instead of committing host-dependent performance measurements. Missing toolchains must **fail openly**, not be replaced by estimates. The timed probes cover file loading and a common exact-byte search only; they are a preliminary language comparison, **not** representative credential rules, streaming, regex engines, memory profiling or real product throughput. Language choice must also assess those dimensions.

## Corpus lanes and scope honesty

| Lane | Purpose | CP0 availability |
| --- | --- | --- |
| Authored synthetic v0 (9 targets) | Known unit-level truth anchors, blocked/exempted markers, Unicode and duplicates | Included |
| Generated synthetic v0 (1,000 targets) | Reproducible breadth, line-ending variation, category labels, decoys, scope blocks and per-target truth | Generator included; artifacts created on validation/CI |
| Performance generated v0 (nine profiles) | 1/8/32 MiB × zero/low/high synthetic-marker density | Benchmark script included; result artifact pending |
| Levain `fp-corpus` | Known false-positive behavior and positive secrets | **Pinned and verified in external harness**; not vendored or run here |
| `leaky_repo` | Organic scoring and adversarial symlink/OOM behavior | **Pinned and verified in external harness**; safe-run checks pending |
| Prowlbench | Additional evaluation if licensing approved | Not imported; license pending |

**Full synthetic CP0 corpus** means all three internally defined lanes above, not an unverified claim that every external corpus or real scanner has been executed. The independent harness must later report **both organic corpus-native scoring and RNC's richer normalized score**, each with its original meaning and provenance. Do not combine them into a fabricated single accuracy figure.

See the [external corpus compatibility inventory](corpus-compatibility.md) for inspected source pins, counting units and integration gates.

## Actual local evidence — 10 November 2026

- `python -m tools.cp0.validate`: pass; six schema definitions, nine authored targets/14 known markers, twelve classification cases × three CI acceptance sets.
- `python -m unittest discover -s tests/cp0 -v`: pass, **11 tests**, including deterministic 1,000-target generation, 2,000 markers, cross-record reconciliation, synthetic stub error modes and fail-closed benchmark preflight.
- The current workspace does **not** have a Go compiler (`go` resolves to a desktop board game) or `rustc`; **no local Go/Rust benchmark has run**. CI benchmark result remains an acceptance blocker.

## CP0 exit gate

- [x] Draft all schemas and validate sample objects and status/CI precedence.
- [x] Authored + generated synthetic corpus with independent manifest truth and deterministic reproduction checks.
- [x] Stub modes to calibrate independent harness (scoring itself remains external).
- [x] Config migration and threat-model principles recorded.
- [ ] Go and Rust benchmarks observed on same CI runner; correctness, digests, versions and timing reported.
- [ ] Review real rule-engine/regex/streaming/security tradeoffs; decide and record detector language in a follow-up ADR.
- [ ] Review full corpus scope, approved external-corpus sourcing, schemas and CP1 plan; operator acceptance before CP1 implementation.
