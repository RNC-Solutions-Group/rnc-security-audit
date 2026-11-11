# Disposable representative scanner benchmark

These Go and Rust programs are **not RNC Scanner** and must not be shipped. They exist to compare equivalent scanner-shaped workloads under CP0.

## Equivalence contract

Both implementations:

- read the same `rules.tsv` rule table (8 basic rules, 64 expanded rules);
- compile the same `regex` patterns with equivalent linear-time engines;
- use identical capture-group selection and marker validation;
- deduplicate `(rule_id, path, start_byte, end_byte)` and sort findings;
- support whole-file and 256 KiB streaming with 8 KiB overlap;
- validate manifest paths against traversal and return explicit errors;
- emit the same `count`, FNV-1a checksum, rule count, mode and thread count.

The Python runner independently generates corpora and expected counts/checksums. It rejects any run whose output differs before recording latency.

## Build and run

```sh
go build -trimpath -ldflags="-s -w" -o /tmp/cp0-bench-go .
cargo build --release --locked

/tmp/cp0-bench-go --corpus CORPUS --manifest files.txt --rules rules-basic.tsv --mode whole --threads 1
target/release/cp0-bench-scanner --corpus CORPUS --manifest files.txt --rules rules-basic.tsv --mode stream --threads 4
```

The end-to-end runner is `python -m tools.cp0.bench_runner --runs 5 --output artifacts/cp0/representative-benchmarks.json`.

## Workloads

- large file, low/high marker density;
- many small files with one and four workers;
- false-positive-heavy and adversarial near-prefix inputs;
- Unicode/multibyte prefixes;
- 64-rule scale;
- PEM-like multiline values;
- whole-file versus bounded streaming.

## Limitations

- This is a language comparison, not production scanner throughput. It does not implement RNC's full rule set, policy, reporting or evidence store.
- The regexes are deliberately safe; pathological backtracking is not possible in either selected engine. Go's `regexp` and Rust's `regex` are RE2-style linear-time engines, but their performance and syntax details differ; the shared table avoids unsupported constructs.
- The Go and Rust programs are kept algorithmically equivalent on purpose. A production implementation may use additional optimizations after measurement.
- Peak RSS/CPU require GNU `time`; otherwise the runner records `null` rather than estimating.
