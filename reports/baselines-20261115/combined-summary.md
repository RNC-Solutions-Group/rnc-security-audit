# Current-scoring Windows AMD64 scanner baselines

Generated: 2026-11-16T00:18:48.905405+00:00

**Epoch:** post-scoring-integrity remediation<br>
**Environment:** DEV, native Windows AMD64<br>
**Harness code:** `70f98de545ab83a614ad4666f993b06e516e4e6b`<br>
**Method:** 1 warmup + 3 measured runs per workload; sequential execution

## Scope and method

The requested workload set was executed: Levain, Leaky Repo filesystem and Git history, RNC Lab filesystem and Git history, and RNC Lab legacy x5/x10. No Docker, GitHub Actions, Levain/Leaky lanes outside the request, or synthetic fixture suites were used.

All reports were generated with the current scoring implementation after the scoring-integrity remediation. CP4C was invoked with its default configuration and `--workers auto`; profiling was disabled. The other scanners used their default registered configuration.

Performance tables report median external wall time from three measured runs. The DEV environment is contended and these are not release capacity measurements. Every individual experiment retains exact commands, per-run values, coverage evidence and sanitized findings.

## Scanner artifacts

| Scanner | Build | Version | Source commit | Executable SHA-256 (prefix) | Overall |
|---|---|---|---|---|---|
| Betterleaks 1.8.1 | `betterleaks-lts` | `1.8.1` | `5eab48332cc48565864514e3bc6de89df091a7c4` | `727820f1a9f92643…` | COMPLETE_WITH_LIMITATIONS |
| Gitleaks 8.25.0 | `gitleaks-master` | `8.25.0-local` | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` | `e0831964099a20be…` | COMPLETE_WITH_LIMITATIONS |
| RNC-MOD-v10 | `gl-rnc-mod-v10` | `v8.25.0+rnc.mod.v10` | `ee1e59e38231b84a8277131827a09fc929383ecc` | `67bd089da565ff75…` | COMPLETE_WITH_LIMITATIONS |
| RNC-MOD-v14 | `gl-rnc-mod-v14` | `v8.25.0+dev.7d7492184111` | `7d74921841114be7677a423cf60620210e832bf7` | `7f1c9bd6f61c3ae4…` | COMPLETE_WITH_LIMITATIONS |
| RNC CP3 | `rnc-cp3` | `0.1.0` | `5391d8457ea091c45733920078a7f714ec61f678` | `284c4c981401b832…` | COMPLETE_WITH_LIMITATIONS |
| RNC CP4A | `rnc-cp4a` | `0.1.0` | `93b4dda909cb3b41606a4d0f36c8ef9d06b77fde` | `6ec71c0b815b8d50…` | COMPLETE_WITH_LIMITATIONS |
| RNC CP4B | `rnc-cp4b` | `0.1.0` | `d00f71f1e2cf16ce58beb07d8b960c5ad056f915` | `d5dc4a1620da8b4a…` | COMPLETE_WITH_LIMITATIONS |
| RNC CP4C (workers=auto) | `rnc-cp4c` | `0.1.0` | `805e3bb79276b94de636e27024f38773da303b44` | `170bd1df345c4985…` | COMPLETE_WITH_LIMITATIONS |

## Detection results

### Levain

| Scanner | TP/85 | FP | Partial | Duplicates | Precision | Recall | F1 | Coverage verified |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Betterleaks 1.8.1 | 48/85 | 5 | 3 | 2 | 90.57% | 56.47% | 69.57% | False |
| Gitleaks 8.25.0 | 47/85 | 3 | 1 | 2 | 94.0% | 55.29% | 69.63% | False |
| RNC-MOD-v10 | 47/85 | 3 | 1 | 2 | 94.0% | 55.29% | 69.63% | False |
| RNC-MOD-v14 | 49/85 | 3 | 1 | 2 | 94.23% | 57.65% | 71.53% | False |
| RNC CP3 | 32/85 | 0 | 0 | 0 | 100.0% | 37.65% | 54.7% | True |
| RNC CP4A | 43/85 | 2 | 0 | 0 | 95.56% | 50.59% | 66.16% | True |
| RNC CP4B | 43/85 | 2 | 0 | 0 | 95.56% | 50.59% | 66.16% | True |
| RNC CP4C (workers=auto) | 43/85 | 2 | 0 | 0 | 95.56% | 50.59% | 66.16% | True |

### Leaky Repo

| Scanner | FS covered/175 | FS rich matched | FS value-verified | FS files | Git matched/65 | Git unique/53 | Git recall | Git verified FP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Betterleaks 1.8.1 | 37/175 | 37 | 35 | 22 | 36/65 | 28/53 | 55.38% | 0 |
| Gitleaks 8.25.0 | 22/175 | 22 | 20 | 13 | 21/65 | 15/53 | 32.31% | 0 |
| RNC-MOD-v10 | 22/175 | 22 | 20 | 13 | 21/65 | 15/53 | 32.31% | 0 |
| RNC-MOD-v14 | 22/175 | 22 | 20 | 13 | 21/65 | 15/53 | 32.31% | 0 |
| RNC CP3 | 33/175 | 32 | 30 | 18 | N/A/N/A | N/A/N/A | N/A% | N/A |
| RNC CP4A | 27/175 | 25 | 23 | 18 | 21/65 | 19/53 | 32.31% | 12 |
| RNC CP4B | 33/175 | 32 | 30 | 21 | 28/65 | 26/53 | 43.08% | 1 |
| RNC CP4C (workers=auto) | 33/175 | 32 | 30 | 21 | 28/65 | 26/53 | 43.08% | 1 |

### RNC Lab v3

| Scanner | FS TP/640 | FS unique/366 | FS recall | FS dup | FS unverified | FS verified FP | Git TP/160 | Git unique/130 | Git recall | Git dup | Git unverified | Git verified FP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Betterleaks 1.8.1 | 438/640 | 281/366 | 68.44% | 93 | 14 | 2 | 158/160 | 128/130 | 98.75% | 0 | 1 | 10 |
| Gitleaks 8.25.0 | 369/640 | 231/366 | 57.66% | 82 | 13 | 4 | 130/160 | 112/130 | 81.25% | 0 | 1 | 7 |
| RNC-MOD-v10 | 369/640 | 231/366 | 57.66% | 82 | 13 | 4 | 130/160 | 112/130 | 81.25% | 0 | 1 | 7 |
| RNC-MOD-v14 | 369/640 | 231/366 | 57.66% | 82 | 13 | 4 | 130/160 | 112/130 | 81.25% | 0 | 1 | 7 |
| RNC CP3 | 302/640 | 183/366 | 47.19% | 0 | 27 | 10 | N/A/N/A | N/A/N/A | N/A% | N/A | N/A | N/A |
| RNC CP4A | 347/640 | 208/366 | 54.22% | 0 | 21 | 10 | 115/160 | 88/130 | 71.88% | 1 | 0 | 3 |
| RNC CP4B | 347/640 | 208/366 | 54.22% | 0 | 14 | 10 | 120/160 | 93/130 | 75.0% | 1 | 0 | 3 |
| RNC CP4C (workers=auto) | 347/640 | 208/366 | 54.22% | 0 | 14 | 10 | 120/160 | 93/130 | 75.0% | 1 | 0 | 3 |

CP3 does not expose Git-history scanning; its Git cells are `NOT_APPLICABLE`, not zero. Precision/F1 are not certified for RNC Lab or Leaky Git because the negative oracle is incomplete. Levain precision/F1 are the corpus-defined metrics; Gitleaks/Betterleaks do not provide the same Levain source-coverage verification as the RNC adapter (`coverage_verified: false`).

### Target overlap (RNC Lab)

- Filesystem: 8 scanners, intersection **262**, union **453**, 191 targets covered by at least one but not all.
- Git: 7 scanners, intersection **94**, union **159**, 65 targets covered by at least one but not all.

Private-key coverage at RNC Lab is **14/28 filesystem** and **10/10 Git** for every Git-capable RNC/Gitleaks/Betterleaks baseline; CP3 is **11/28 filesystem** and has no Git lane.

## Performance results

Median external wall time (seconds); N/A = capability not supported/not executed.

| Scanner | Levain | Leaky FS | Leaky Git | RNC FS | RNC Git | Legacy x5 | Legacy x10 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Betterleaks 1.8.1 | 0.495 | 0.484 | 0.449 | 0.831 | 0.528 | 1.318 | 2.040 |
| Gitleaks 8.25.0 | 0.243 | 0.859 | 0.370 | 0.533 | 0.360 | 1.989 | 4.110 |
| RNC-MOD-v10 | 0.254 | 0.864 | 0.273 | 0.529 | 0.285 | 2.761 | 7.238 |
| RNC-MOD-v14 | 0.246* | 0.659 | 0.461 | 0.494 | 0.488 | 2.556 | 4.294 |
| RNC CP3 | 0.178 | 0.517 | N/A | 0.398 | N/A | 3.960 | 4.796 |
| RNC CP4A | 0.365 | 1.444 | 12.716 | 0.752 | 9.760 | 17.018 | 16.546 |
| RNC CP4B | 0.441 | 1.307 | 9.904 | 0.627 | 8.570 | 14.029 | 15.912 |
| RNC CP4C (workers=auto) | 0.394 | 1.122 | 4.685 | 0.534 | 5.267 | 5.121 | 6.892 |

`*` RNC-MOD-v14 Levain filesystem was classified **UNSTABLE** (CV 0.55; one 0.715 s outlier among 0.245/0.246/0.715 s). Its 0.246 s median is shown for completeness but must not be used to rank it as a performance winner.

### Load resource profile

| Scanner | x5 peak MiB | x5 CPU s | x10 peak MiB | x10 CPU s |
|---|---:|---:|---:|---:|
| Betterleaks 1.8.1 | 144.8 | 5.578 | 189.6 | 8.594 |
| Gitleaks 8.25.0 | 60.6 | 5.203 | 81.1 | 11.594 |
| RNC-MOD-v10 | 72.5 | 6.922 | 98.5 | 15.578 |
| RNC-MOD-v14 | 72.2 | 6.109 | 95.5 | 10.484 |
| RNC CP3 | 44.1 | 3.391 | 62.2 | 4.625 |
| RNC CP4A | 104.5 | 16.047 | 124.0 | 15.906 |
| RNC CP4B | 104.2 | 13.562 | 123.2 | 15.453 |
| RNC CP4C (workers=auto) | 354.7 | 22.719 | 376.9 | 26.000 |

CPU is scanner-process CPU, not a process-tree total. Peak memory is scanner-process working set. CP4C auto's higher memory is consistent with running a larger worker pool; the other RNC builds ran their defaults.

## Assessment

- **Detection leader:** Betterleaks 1.8.1 is strongest on RNC Lab filesystem (**438/640**) and Git (**158/160**) and on Leaky Repo filesystem/Git (**37/175**, **36/65**). It is not the best Levain detector: RNC-MOD-v14 leads Levain at **49/85**, with Gitleaks and RNC-MOD-v10 at **47/85**.
- **RNC product progression:** CP4A is **347/640 filesystem / 115/160 Git**, CP4B is **347/120**, and CP4C with workers auto is also **347/120**. CP4C improves RNC throughput substantially but does not change RNC Lab detection versus CP4B.
- **RNC-MOD-v14:** adds **+2 Levain TPs** versus v10/Gitleaks but has the same RNC Lab detection as v10/Gitleaks and is slower on Git and x5. Its Levain timing is unstable. It is not a general-purpose performance or detection replacement.
- **Gitleaks:** same RNC Lab detection as RNC-MOD-v10/v14 (**369/130**) and same Leaky/Git results, with low memory and the best or near-best canonical RNC timings. It is the best speed/memory choice among the Gitleaks-family builds.
- **RNC CP4C:** with `--workers auto` it is the fastest RNC build on Git (5.267 s vs CP4B 8.570 s), x5 (5.121 s vs 14.029 s), and x10 (6.892 s vs 15.912 s), but remains slower than Betterleaks and Gitleaks on the load workloads and lower on detection.
- **CP3:** fastest Levain filesystem (0.178 s) but has no Git-history capability and the lowest RNC Lab detection (302/640). It is a legacy filesystem baseline only.
- **CP4A:** slowest on Git and loads and lower Git detection than CP4B/C; not a preferred baseline.
- **No single winner:** Betterleaks wins detection breadth and x5/x10 throughput; Gitleaks wins canonical speed/memory; RNC CP4C wins the RNC product line but trails external scanners on these workloads. The union/intersection numbers show substantial complementary coverage.
- **Accuracy boundary:** precision/F1 remain uncertified for RNC Lab/Leaky Git; Gitleaks/Betterleaks Levain coverage verification is unavailable, so detect-only results from those adapters must be interpreted separately from RNC source-coverage-verified results.

## Out of scope / blocked

- **Betterleaks Main v2.0.0-dev** is the ninth Windows AMD64 executable entry in the manifest, but it is not in the requested measured-program list and is incompatible with the registered Betterleaks 1.8.1 adapter: v2 removed `--report-format`, uses the `filesystem`/`git` command contract, and requires a different output adapter. Its attempted run failed with `unknown flag --report-format`; no v2 baseline is claimed.

## Historical-report archive

All tracked reports other than `baselines-20261115/`, `cp4c-matrix0/`, and `rnc-mod-v14-vs-gitleaks/` predate the scoring remediation. They are archived at [`../archive/pre-scoring-fix/pre-scoring-fix-reports.zip`](../archive/pre-scoring-fix/pre-scoring-fix-reports.zip) and indexed with SHA-256 hashes in [`../archive/pre-scoring-fix/MANIFEST.json`](../archive/pre-scoring-fix/MANIFEST.json). The originals remain at their historical paths; this avoids rewriting or breaking immutable historical links. Use this baseline directory for current-scoring comparisons.

## Limitations

- DEV, contended developer workstation; three measured runs; not release evidence.
- CP4C workers auto was requested; the sanitized report does not expose the resolved effective worker count.
- CP3 Git and Leaky Git are `NOT_APPLICABLE` capability gaps.
- Gitleaks/Betterleaks do not verify Levain source coverage the way the RNC adapter does.
- Negative oracles for RNC Lab and Leaky Git are incomplete; precision/F1 are not certified.
- Peak memory is scanner-process only; child Git CPU/memory are unavailable.
- CP4C and the other RNC builds were not forced to the same worker count: CP4C is workers auto as requested; CP3/CP4A/CP4B used their defaults.

## Individual reports

- [Betterleaks 1.8.1](betterleaks-lts/) — `run\reports\all-windows-baselines\betterleaks-lts\betterleaks-lts-current-baseline-5eab48332cc4-default.json`
- [Gitleaks 8.25.0](gitleaks-master/) — `run\reports\all-windows-baselines\gitleaks-master\gitleaks-master-current-baseline-5f6ec56cfa6f-default.json`
- [RNC-MOD-v10](gl-rnc-mod-v10/) — `run\reports\all-windows-baselines\gl-rnc-mod-v10\gl-rnc-mod-v10-current-baseline-ee1e59e38231-default.json`
- [RNC-MOD-v14](gl-rnc-mod-v14/) — `run\reports\all-windows-baselines\gl-rnc-mod-v14\gl-rnc-mod-v14-current-baseline-7d7492184111-default.json`
- [RNC CP3](rnc-cp3/) — `run\reports\all-windows-baselines\rnc-cp3\rnc-cp3-current-baseline-5391d8457ea0-default.json`
- [RNC CP4A](rnc-cp4a/) — `run\reports\all-windows-baselines\rnc-cp4a\rnc-cp4a-current-baseline-93b4dda909cb-default.json`
- [RNC CP4B](rnc-cp4b/) — `run\reports\all-windows-baselines\rnc-cp4b\rnc-cp4b-current-baseline-d00f71f1e2cf-default.json`
- [RNC CP4C (workers=auto)](rnc-cp4c/) — `run\reports\all-windows-baselines\rnc-cp4c\rnc-cp4c-current-baseline-805e3bb79276-default.json`

## Machine-readable evidence

- [combined-summary.json](combined-summary.json) — detection, performance, target overlap and artifact index.
- [baseline-runs.csv](baseline-runs.csv) — 162 accepted measured runs.
- Raw experiment JSON/Markdown and exact commands remain under `run/reports/all-windows-baselines/`.
