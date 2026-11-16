# RNC-MOD-v14 vs Gitleaks — RNC Lab comparison

## Scope

Requested scope was limited to:

- RNC Synthetic Secrets Lab v3 filesystem
- RNC Synthetic Secrets Lab v3 Git history
- RNC Lab legacy x5
- RNC Lab legacy x10

No Levain, Leaky Repo, Docker, or CI lane was executed.

Method:

- 1 warmup + 3 measured runs per workload per scanner
- Native Windows AMD64 only
- Default registered configuration for each binary; no external rules file
- Sequential execution, no overlapping scans
- Primary order: RNC-MOD-v14, then Gitleaks
- Reverse-order control: Gitleaks, then RNC-MOD-v14
- DEV benchmark environment (contended workstation, not release evidence)

## Artifact identity

| Field | RNC-MOD-v14 | Gitleaks |
|---|---|---|
| Build ID | `gl-rnc-mod-v14` | `gitleaks-master` |
| Version | `v8.25.0+dev.7d7492184111` | `8.25.0-local` |
| Source commit | `7d74921841114be7677a423cf60620210e832bf7` | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |
| Executable SHA-256 | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | `e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2` |
| Manifest SHA-256 | `ef22463023d4aa2417a92e74074bb1a98eb85ce9cab6576878c3b047bf81a937` | same manifest |

Both are native Windows AMD64 executables and used the same Gitleaks adapter, bundled default rules, and CLI shape. The comparison therefore isolates the two binaries rather than configuration differences.

Invocation shape was identical for both:

```text
<binary> dir <RNC Lab filesystem> --report-format json --report-path <temp> --no-banner --exit-code 1
<binary> git <RNC Lab history> --report-format json --report-path <temp> --no-banner --exit-code 1
```

The exact argv and per-run evidence are retained in the raw experiment JSON; no external `--config` or custom ruleset was supplied.

## Detection result

Both binaries produced **exactly the same canonical findings** on both canonical lanes:

- Same matched target IDs and missed target IDs
- Same finding rows, including file, commit, line, rule ID, evidence digests, classification, expected target, and reason code
- Same target/finding accounting and reconciliation flags

| Lane | Scanner | TP | FN | Unique groups | Observed | Duplicates | Unverified | Verified FP | Recall |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Filesystem | RNC-MOD-v14 | 369 | 271 | 231/366 | 480 | 82 | 13 | 4 | 57.66% |
| Filesystem | Gitleaks | 369 | 271 | 231/366 | 480 | 82 | 13 | 4 | 57.66% |
| Git | RNC-MOD-v14 | 130 | 30 | 112/130 | 138 | 0 | 1 | 7 | 81.25% |
| Git | Gitleaks | 130 | 30 | 112/130 | 138 | 0 | 1 | 7 | 81.25% |

Target-set signatures, finding signatures, and category counts are **identical**. There are no scanner-only TP, FN, FP, duplicate, or unverified differences.

Category coverage is identical:

| Lane | Category | Expected | Matched |
|---|---|---:|---:|
| Filesystem | API key | 18 | 2 |
| Filesystem | HMAC secret | 80 | 76 |
| Filesystem | OTP seed | 12 | 0 |
| Filesystem | Password | 362 | 137 |
| Filesystem | Private key | 28 | 14 |
| Filesystem | Provider token | 140 | 140 |
| Git | API key | 15 | 15 |
| Git | HMAC secret | 31 | 30 |
| Git | Password | 71 | 43 |
| Git | Private key | 10 | 10 |
| Git | Provider token | 33 | 32 |

Private-key coverage is **14/28 filesystem** and **10/10 Git** for both scanners.

Precision and F1 remain **NOT CERTIFIED** because the negative oracle is not exhaustive. Verified FP counts are reported, but neither scanner can claim certified precision/F1.

## Performance — primary order

Median of three externally measured runs. Warmups are excluded from all medians.

| Workload | RNC-MOD-v14 | Gitleaks | Mod delta vs Gitleaks | Mod CPU | Gitleaks CPU | Mod peak | Gitleaks peak | Mod files/s | Gitleaks files/s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| RNC Lab filesystem | 0.390 s | 0.387 s | **+0.8%** | 0.906 s | 1.141 s | 52.2 MiB | 55.3 MiB | 951 | 959 |
| RNC Lab Git | 0.413 s | 0.282 s | **+46.5%** | 0.172 s | 0.188 s | 39.9 MiB | 39.1 MiB | 247 | 362 |
| Legacy x5 | 2.950 s | 2.357 s | **+25.2%** | 6.344 s | 5.828 s | 73.0 MiB | 59.8 MiB | 614 | 768 |
| Legacy x10 | 5.077 s | 3.890 s | **+30.5%** | 12.297 s | 11.141 s | 96.5 MiB | 72.7 MiB | 711 | 928 |

Inspected-byte throughput:

| Workload | RNC-MOD-v14 | Gitleaks | Mod delta |
|---|---:|---:|---:|
| Filesystem | 0.632 MiB/s | 0.637 MiB/s | −0.8% |
| Git | 0.096 MiB/s | 0.140 MiB/s | −31.4% |
| Legacy x5 | 22.1 MiB/s | 27.7 MiB/s | −20.1% |
| Legacy x10 | 13.1 MiB/s | 17.1 MiB/s | −23.4% |

All 24 primary measured runs completed without errors or timeouts. Every primary CV was ≤ 0.11 and every workload was classified `STABLE`.

## Reverse-order control

The reverse order was run to check whether the first-pass advantage came from warm OS caches or host drift.

| Workload | RNC-MOD-v14 | Gitleaks | Mod delta |
|---|---:|---:|---:|
| RNC Lab filesystem | 0.589 s | 0.526 s | +12.0% |
| RNC Lab Git | 0.684 s | 0.292 s | +134.2% |
| Legacy x5 | 3.009 s | 2.272 s | +32.4% |
| Legacy x10 | 5.725 s | 4.083 s | +40.2% |

Order-balanced mean of the two 3-run medians:

| Workload | RNC-MOD-v14 | Gitleaks | Mod delta |
|---|---:|---:|---:|
| Filesystem | 0.4895 s | 0.4565 s | **+7.2%** |
| Git | 0.5485 s | 0.2870 s | **+91.1%** |
| Legacy x5 | 2.9795 s | 2.3145 s | **+28.7%** |
| Legacy x10 | 5.4010 s | 3.9865 s | **+35.5%** |

The direction is consistent: Gitleaks is materially faster on Git history and both legacy loads. Filesystem is approximately tied in the primary order and only modestly worse for the mod in the reverse order, so the sub-second filesystem result is the least discriminating.

Detection remained identical in the reverse-order control.

## Assessment

1. **No detection benefit was observed for RNC-MOD-v14 on these four workloads.** Both binaries produced the same 369 filesystem TPs, 130 Git TPs, same target sets, same categories, same FP/unverified counts, and same finding identities. On RNC Lab, the mod did not add incremental detection value.

2. **Gitleaks is the stronger performer in this comparison.** It is effectively tied on the sub-second filesystem lane, but is approximately:
   - **1.46× faster** on Git history in the primary order,
   - **1.25–1.32× faster** on the legacy loads,
   - and remains clearly faster in the reverse-order control.

3. **RNC-MOD-v14 consumes more memory on the load profiles.** Peak memory is +19% to +33% on x5/x10 depending on order, with a smaller canonical-lane difference. Its scanner CPU is also higher on the loads. The mod’s canonical CPU is lower or similar, but wall time is not better.

4. **The mod’s cost is not explained by extra detections in this corpus.** The finding sets are identical. Likely explanations include additional rule/startup work, larger working set, or binary-specific acquisition behavior; this experiment cannot attribute the difference further without scanner profiling or source review.

5. **This is not evidence that RNC-MOD-v14 is universally worse.** The mod may target detection gaps outside the RNC Lab corpus. Within the requested scope, however, it provides no measured accuracy gain and a clear throughput regression on Git and load workloads.

6. **Use Gitleaks for these workloads unless a specific RNC-MOD-v14 rule is required.** If the mod is required, validate its intended additional rules against the relevant corpus first and profile its startup/rules path; do not expect a performance benefit from the v14 binary.

## Recommended next steps

- Use Gitleaks 8.25.0-local as the performance and parity reference for these four workloads.
- Treat RNC-MOD-v14 as a feature candidate, not a drop-in faster replacement.
- If v14’s distinguishing rules matter, run a targeted corpus/rule comparison rather than relying on RNC Lab aggregate detection.
- Re-run with a longer load or profiled execution before attributing the Git/load regression to a specific scanner phase.
- Do not certify precision/F1 from either result; the negative oracle is non-exhaustive.
- Do not treat this DEV run as release evidence.

## Limitations

- DEV environment on a contended developer workstation; not release or capacity evidence.
- Only three measured runs per workload; medians are descriptive, not a statistical confidence claim.
- Two sequential order passes were used to expose cache/order drift; they are a control, not additional primary samples.
- Both scanners expose final findings only; neither provides a complete source-unit execution report, so `NO_ALERT` cannot prove execution completeness.
- Legacy x5/x10 are performance workloads only and are not scored against the canonical oracle.
- The source commits are operator-supplied manifest metadata; no scanner source was checked out or built.
- Precision/F1 are not certified; verified FP counts are corpus-scoped.

## Evidence

Raw experiment reports:

- `run/reports/rnc-mod-v14-vs-gitleaks/gl-rnc-mod-v14/`
- `run/reports/rnc-mod-v14-vs-gitleaks/gitleaks-master/`
- `run/reports/rnc-mod-v14-vs-gitleaks/reverse-order/`

Machine comparison:

- `run/reports/rnc-mod-v14-vs-gitleaks/comparison.json`

Both scanners used default registered rules and identical CLI flags. No scanner source, rules, oracle, or historical report was modified.
