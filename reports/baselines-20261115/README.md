# Current-scoring Windows AMD64 baselines

These are the fresh post-scoring-integrity baselines for the eight requested
Windows AMD64 scanner programs:

The manifest currently contains nine Windows AMD64 executable entries. Eight
produced valid baselines; `betterleaks-main` is the ninth and is blocked by its
incompatible v2 CLI (documented below).

- [Gitleaks 8.25.0](gitleaks-master/)
- [Betterleaks 1.8.1](betterleaks-lts/)
- [RNC-MOD-v10](gl-rnc-mod-v10/)
- [RNC-MOD-v14](gl-rnc-mod-v14/)
- [RNC CP3](rnc-cp3/)
- [RNC CP4A](rnc-cp4a/)
- [RNC CP4B](rnc-cp4b/)
- [RNC CP4C, `--workers auto`, no profiling](rnc-cp4c/)

Each scanner was run across the requested lanes:

1. Levain
2. Leaky Repo filesystem
3. Leaky Repo Git history
4. RNC Lab filesystem
5. RNC Lab Git history
6. RNC Lab legacy x5
7. RNC Lab legacy x10

Method: native Windows AMD64, default registered configuration, **1 warmup +
3 measured runs per workload**, sequential execution, DEV environment.
Harness code: `70f98de545ab83a614ad4666f993b06e516e4e6b`.

The consolidated report is [combined-summary.md](combined-summary.md). The
machine-readable result, including target-set overlap and per-run evidence
pointers, is [combined-summary.json](combined-summary.json). All 162 accepted
measured rows are in [baseline-runs.csv](baseline-runs.csv).

Important boundaries:

- CP3 does not expose Git-history scanning; its Git cells are `NOT_APPLICABLE`.
- CP4C used the requested `--workers auto`; the other RNC builds used their
  defaults. The sanitized report records the requested command but not an
  independently observed effective worker count.
- Gitleaks and Betterleaks do not provide the same Levain source-coverage
  verification as the RNC adapter.
- RNC Lab and Leaky Git precision/F1 remain uncertified because the negative
  oracle is incomplete.
- DEV measurements are contended and are not release capacity evidence.

**Betterleaks Main v2.0.0-dev** is registered but excluded: its v2 CLI is
incompatible with the registered Betterleaks 1.8.1 adapter (`--report-format`
removed; `filesystem`/`git` command contract). The attempted run failed rather
than producing a baseline. See [blocked-betterleaks-main.md](blocked-betterleaks-main.md).

Raw experiment reports, exact commands and private evidence remain under
Git-ignored `run/reports/all-windows-baselines/`. Pre-scoring-fix reports are
indexed under [`../archive/pre-scoring-fix/`](../archive/pre-scoring-fix/README.md).
