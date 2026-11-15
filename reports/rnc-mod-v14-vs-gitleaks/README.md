# RNC-MOD-v14 vs Gitleaks — RNC Lab comparison

Requested scope: RNC Lab filesystem, RNC Lab Git history, legacy x5 and legacy
x10 only. No Levain, Leaky Repo, Docker, or CI lane was executed.

- [comparison.md](comparison.md) — compiled assessment and findings.
- [comparison.json](comparison.json) — machine-readable detection and performance comparison.
- [comparison-runs.csv](comparison-runs.csv) — the 24 primary measured runs.

Artifacts:

| Scanner | Build | Version | Source commit | Executable SHA-256 |
|---|---|---|---|---|
| RNC-MOD-v14 | `gl-rnc-mod-v14` | `v8.25.0+dev.7d7492184111` | `7d74921841114be7677a423cf60620210e832bf7` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` |
| Gitleaks | `gitleaks-master` | `8.25.0-local` | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` | `e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2` |

Method: native Windows AMD64, default registered configuration, 1 warmup + 3
measured runs per workload, DEV environment. A reverse-order control was also
run to test cache/order bias: `gitleaks-master` first, then `gl-rnc-mod-v14`.

Raw reports, exact commands and reverse-order evidence remain under the Git-ignored
`run/reports/rnc-mod-v14-vs-gitleaks/` directory.

Both scanners produced identical canonical detection results. Gitleaks was
materially faster on Git history and the x5/x10 loads; filesystem was effectively
tied in the primary order. These are preliminary DEV measurements, not release
evidence, and precision/F1 remain uncertified.
