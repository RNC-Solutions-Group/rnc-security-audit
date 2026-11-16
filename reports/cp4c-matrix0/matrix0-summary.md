# CP4C Matrix 0 — Worker Scaling and Profiler Overhead

Generated: 2026-11-15T23:09:50.264189+00:00

## Executive outcome

Matrix 0 completed with all configurations accepted and detection equivalence preserved.

- Matrix completion: **32/32** configurations; **160/160** measured runs accepted.
- CP4B reference equivalence: **PASS**.
- Profile schema v1: **PASS**.
- Detection/coverage equivalence: **PASS**.
- Environment: **DEV** — contended developer workstation; preliminary timing

## CP4B reference and scoring context

CP4C `--workers 1`, `--git-io process`, `--history-mode whole`, profiling off, is compared with the preserved CP4B build. The published CP4B timing medians and historical detection counts are reference values, not hard thresholds.

| Workload | CP4B published median s | CP4C matrix W1/off median s | CP4B published TP | Current-scoring TP |
|---|---:|---:|---:|---:|
| rnclab-filesystem | 0.487 | 0.633 | 297 | 347 |
| rnclab-git | 6.515 | 8.04 | 110 | 120 |

The historical CP4B TP counts were produced by the pre-remediation scorer. Current scoring legitimately credits additional independently verified evidence; CP4C and CP4B raw canonical findings are identical. The reference comparison also matched canonical finding signatures, every source-unit disposition, inspected unit/byte counts, result code and coverage disposition.

## Worker scaling

Median external wall time; speedup is `T1/Tw`; efficiency is `speedup/w`. Profiler ON and OFF are separate.

| Workload | Profile | W1 s | W2 s | W4 s | W8 s | Speedup W8 | Efficiency W8 |
|---|---|---:|---:|---:|---:|---:|---:|
| legacy-10x | off | 15.273 | 11.899 | 7.419 | 5.713 | 2.673 | 0.334 |
| legacy-10x | on | 15.468 | 11.889 | 7.521 | 5.546 | 2.789 | 0.349 |
| legacy-5x | off | 13.374 | 10.566 | 6.431 | 4.688 | 2.853 | 0.357 |
| legacy-5x | on | 13.134 | 10.541 | 6.385 | 4.767 | 2.755 | 0.344 |
| rnclab-filesystem | off | 0.633 | 0.699 | 0.588 | 0.504 | 1.256 | 0.157 |
| rnclab-filesystem | on | 0.612 | 0.633 | 0.616 | 0.516 | 1.186 | 0.148 |
| rnclab-git | off | 8.04 | 6.121 | 5.544 | 4.579 | 1.756 | 0.22 |
| rnclab-git | on | 7.983 | 6.011 | 5.693 | 4.598 | 1.736 | 0.217 |

## Profiler overhead

`(ON − OFF) / OFF` using median external wall time. Negative values are retained as observed.

| Workload | Workers | OFF median s | ON median s | Delta ms | Delta % | Paired median delta ms | Paired median % | CV OFF | CV ON |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| legacy-10x | 1 | 15.273 | 15.468 | 195.0 | 1.277 | 340.0 | 2.226 | 0.027202 | 0.052294 |
| legacy-10x | 2 | 11.899 | 11.889 | -10.0 | -0.084 | 112.0 | 0.941 | 0.037282 | 0.035551 |
| legacy-10x | 4 | 7.419 | 7.521 | 102.0 | 1.375 | 123.0 | 1.658 | 0.041174 | 0.047702 |
| legacy-10x | 8 | 5.713 | 5.546 | -167.0 | -2.923 | -174.0 | -3.046 | 0.04125 | 0.035979 |
| legacy-5x | 1 | 13.374 | 13.134 | -240.0 | -1.795 | -310.0 | -2.318 | 0.026485 | 0.030338 |
| legacy-5x | 2 | 10.566 | 10.541 | -25.0 | -0.237 | -300.0 | -2.839 | 0.032376 | 0.023521 |
| legacy-5x | 4 | 6.431 | 6.385 | -46.0 | -0.715 | -52.0 | -0.809 | 0.043366 | 0.025897 |
| legacy-5x | 8 | 4.688 | 4.767 | 79.0 | 1.685 | 79.0 | 1.685 | 0.026122 | 0.049008 |
| rnclab-filesystem | 1 | 0.633 | 0.612 | -21.0 | -3.318 | -39.0 | -6.161 | 0.052805 | 0.030115 |
| rnclab-filesystem | 2 | 0.699 | 0.633 | -66.0 | -9.442 | -21.0 | -3.004 | 0.097803 | 0.225102 |
| rnclab-filesystem | 4 | 0.588 | 0.616 | 28.0 | 4.762 | 9.0 | 1.531 | 0.199422 | 0.068566 |
| rnclab-filesystem | 8 | 0.504 | 0.516 | 12.0 | 2.381 | -8.0 | -1.587 | 0.131914 | 0.074785 |
| rnclab-git | 1 | 8.04 | 7.983 | -57.0 | -0.709 | 100.0 | 1.244 | 0.046064 | 0.015109 |
| rnclab-git | 2 | 6.121 | 6.011 | -110.0 | -1.797 | -57.0 | -0.931 | 0.031691 | 0.024854 |
| rnclab-git | 4 | 5.544 | 5.693 | 149.0 | 2.688 | 64.0 | 1.154 | 0.064674 | 0.041675 |
| rnclab-git | 8 | 4.579 | 4.598 | 19.0 | 0.415 | 15.0 | 0.328 | 0.050684 | 0.042475 |

## Resource and throughput summary

CPU is scanner-process CPU time, not a process-tree total. Peak memory is scanner-process working set. Child Git CPU/memory are unavailable and are not presented as totals.

| Workload | Workers | Profile | Scanner CPU s | CPU util % | Peak MiB | Units/s | MiB/s |
|---|---:|---|---:|---:|---:|---:|---:|
| legacy-10x | 1 | off | 14.96875 | 98.008 | 123.562 | 236.299 | 3.828 |
| legacy-10x | 1 | on | 15.21875 | 98.389 | 123.621 | 233.32 | 3.78 |
| legacy-10x | 2 | off | 18.328125 | 154.031 | 375.715 | 303.303 | 4.914 |
| legacy-10x | 2 | on | 18.28125 | 153.766 | 375.656 | 303.558 | 4.918 |
| legacy-10x | 4 | off | 22.078125 | 297.589 | 376.562 | 486.454 | 7.881 |
| legacy-10x | 4 | on | 22.375 | 297.5 | 376.492 | 479.856 | 7.774 |
| legacy-10x | 8 | off | 24.640625 | 431.308 | 376.629 | 631.717 | 10.234 |
| legacy-10x | 8 | on | 24.390625 | 439.788 | 376.883 | 650.739 | 10.542 |
| legacy-5x | 1 | off | 13.0625 | 97.671 | 104.461 | 135.262 | 4.279 |
| legacy-5x | 1 | on | 12.96875 | 98.742 | 104.5 | 137.734 | 4.358 |
| legacy-5x | 2 | off | 16.59375 | 157.049 | 354.527 | 171.21 | 5.417 |
| legacy-5x | 2 | on | 16.203125 | 153.715 | 354.809 | 171.616 | 5.43 |
| legacy-5x | 4 | off | 20.28125 | 315.367 | 355.059 | 281.294 | 8.9 |
| legacy-5x | 4 | on | 20.046875 | 313.968 | 354.527 | 283.32 | 8.964 |
| legacy-5x | 8 | off | 22.4375 | 478.616 | 355.324 | 385.879 | 12.209 |
| legacy-5x | 8 | on | 22.828125 | 478.878 | 354.977 | 379.484 | 12.006 |
| rnclab-filesystem | 1 | off | 0.59375 | 93.799 | 89.473 | 568.72 | 0.39 |
| rnclab-filesystem | 1 | on | 0.609375 | 99.571 | 89.617 | 588.235 | 0.403 |
| rnclab-filesystem | 2 | off | 0.8125 | 116.237 | 329.539 | 515.021 | 0.353 |
| rnclab-filesystem | 2 | on | 0.78125 | 123.42 | 329.223 | 568.72 | 0.39 |
| rnclab-filesystem | 4 | off | 0.859375 | 146.152 | 330.137 | 612.245 | 0.419 |
| rnclab-filesystem | 4 | on | 0.890625 | 144.582 | 330.699 | 584.416 | 0.4 |
| rnclab-filesystem | 8 | off | 0.890625 | 176.711 | 330.766 | 714.286 | 0.489 |
| rnclab-filesystem | 8 | on | 0.921875 | 178.658 | 330.652 | 697.674 | 0.478 |
| rnclab-git | 1 | off | 1.078125 | 13.41 | 84.156 | 14.428 | 0.005 |
| rnclab-git | 1 | on | 1.03125 | 12.918 | 84.207 | 14.531 | 0.005 |
| rnclab-git | 2 | off | 1.171875 | 19.145 | 314.344 | 18.951 | 0.007 |
| rnclab-git | 2 | on | 1.125 | 18.716 | 314.285 | 19.298 | 0.007 |
| rnclab-git | 4 | off | 1.265625 | 22.829 | 314.484 | 20.924 | 0.008 |
| rnclab-git | 4 | on | 1.34375 | 23.604 | 314.285 | 20.376 | 0.007 |
| rnclab-git | 8 | off | 1.375 | 30.028 | 314.898 | 25.333 | 0.009 |
| rnclab-git | 8 | on | 1.34375 | 29.225 | 314.656 | 25.228 | 0.009 |

## Variability and stability

DEV stability threshold is CV ≤ 0.25. Every individual run remains in the CSV and JSON evidence.

| Workload | Workers | Profile | Wall CV | Stable |
|---|---:|---|---:|---|
| legacy-10x | 1 | off | 0.027202 | yes |
| legacy-10x | 1 | on | 0.052294 | yes |
| legacy-10x | 2 | off | 0.037282 | yes |
| legacy-10x | 2 | on | 0.035551 | yes |
| legacy-10x | 4 | off | 0.041174 | yes |
| legacy-10x | 4 | on | 0.047702 | yes |
| legacy-10x | 8 | off | 0.04125 | yes |
| legacy-10x | 8 | on | 0.035979 | yes |
| legacy-5x | 1 | off | 0.026485 | yes |
| legacy-5x | 1 | on | 0.030338 | yes |
| legacy-5x | 2 | off | 0.032376 | yes |
| legacy-5x | 2 | on | 0.023521 | yes |
| legacy-5x | 4 | off | 0.043366 | yes |
| legacy-5x | 4 | on | 0.025897 | yes |
| legacy-5x | 8 | off | 0.026122 | yes |
| legacy-5x | 8 | on | 0.049008 | yes |
| rnclab-filesystem | 1 | off | 0.052805 | yes |
| rnclab-filesystem | 1 | on | 0.030115 | yes |
| rnclab-filesystem | 2 | off | 0.097803 | yes |
| rnclab-filesystem | 2 | on | 0.225102 | yes |
| rnclab-filesystem | 4 | off | 0.199422 | yes |
| rnclab-filesystem | 4 | on | 0.068566 | yes |
| rnclab-filesystem | 8 | off | 0.131914 | yes |
| rnclab-filesystem | 8 | on | 0.074785 | yes |
| rnclab-git | 1 | off | 0.046064 | yes |
| rnclab-git | 1 | on | 0.015109 | yes |
| rnclab-git | 2 | off | 0.031691 | yes |
| rnclab-git | 2 | on | 0.024854 | yes |
| rnclab-git | 4 | off | 0.064674 | yes |
| rnclab-git | 4 | on | 0.041675 | yes |
| rnclab-git | 8 | off | 0.050684 | yes |
| rnclab-git | 8 | on | 0.042475 | yes |

## Internal profiler phases

Worker phases are accumulated time and are not elapsed wall time. Wall phases are internal attribution only; the external harness clock is authoritative.

### legacy-10x / w1

| Kind | Phase | Median ns across profile-on measured runs |
|---|---|---:|
| wall | execution | 15420015700 |
| wall | scan | 13695854600 |
| worker | matching.regex | 11704097900 |
| wall | discovery | 1160062300 |
| wall | discovery.filesystem | 1160055900 |
| wall | rules.load | 208596000 |
| wall | reporting | 62135100 |
| wall | reporting.serialize | 34423200 |
| worker | scan.validation | 21532500 |
| worker | scan.findings | 17165700 |

### legacy-10x / w8

| Kind | Phase | Median ns across profile-on measured runs |
|---|---|---:|
| worker | scheduling.worker_busy | 29298427500 |
| worker | matching.regex | 25506151000 |
| wall | execution | 5477702600 |
| wall | scan | 4055437100 |
| wall | discovery | 1077909500 |
| wall | discovery.filesystem | 1077902700 |
| worker | scheduling.queue_wait | 272129100 |
| wall | rules.load | 217546000 |
| wall | reporting | 55773100 |
| wall | reporting.serialize | 33018000 |

### legacy-5x / w1

| Kind | Phase | Median ns across profile-on measured runs |
|---|---|---:|
| wall | execution | 13092454900 |
| wall | scan | 12088617200 |
| worker | matching.regex | 11052198800 |
| wall | discovery | 563350900 |
| wall | discovery.filesystem | 563343800 |
| wall | rules.load | 227855900 |
| wall | reporting | 27991200 |
| wall | reporting.serialize | 15233700 |
| worker | scan.validation | 10242500 |
| worker | scan.findings | 8113600 |

### legacy-5x / w8

| Kind | Phase | Median ns across profile-on measured runs |
|---|---|---:|
| worker | scheduling.worker_busy | 27130474700 |
| worker | matching.regex | 25114257000 |
| wall | execution | 4686926500 |
| wall | scan | 3779988900 |
| wall | discovery | 574604000 |
| wall | discovery.filesystem | 574595900 |
| wall | rules.load | 250143400 |
| worker | scheduling.queue_wait | 144127100 |
| wall | reporting | 31554200 |
| worker | scan.validation | 16268900 |

### rnclab-filesystem / w1

| Kind | Phase | Median ns across profile-on measured runs |
|---|---|---:|
| wall | execution | 573355200 |
| wall | scan | 235501000 |
| wall | rules.load | 215041800 |
| wall | discovery | 101377500 |
| wall | discovery.filesystem | 101373700 |
| worker | matching.regex | 76999200 |
| wall | reporting | 7985200 |
| wall | reporting.write | 4953700 |
| wall | reporting.serialize | 2201100 |
| worker | scan.validation | 2010700 |

### rnclab-filesystem / w8

| Kind | Phase | Median ns across profile-on measured runs |
|---|---|---:|
| worker | scheduling.worker_busy | 586752300 |
| wall | execution | 437993600 |
| worker | matching.regex | 281771900 |
| wall | rules.load | 224566400 |
| wall | discovery | 108533700 |
| wall | discovery.filesystem | 108529700 |
| wall | scan | 91226100 |
| worker | scheduling.queue_wait | 33276800 |
| wall | reporting | 7752100 |
| wall | reporting.write | 4404900 |

### rnclab-git / w1

| Kind | Phase | Median ns across profile-on measured runs |
|---|---|---:|
| wall | execution | 7948943700 |
| wall | scan | 5085006500 |
| worker | git.acquire.process | 5047721000 |
| wall | discovery | 2687947300 |
| wall | discovery.git | 2687943100 |
| wall | git.deltas | 2369371800 |
| wall | git.command | 244676400 |
| wall | rules.load | 233626900 |
| wall | git.open | 43094300 |
| wall | git.enumerate | 42879300 |

### rnclab-git / w8

| Kind | Phase | Median ns across profile-on measured runs |
|---|---|---:|
| worker | scheduling.worker_busy | 12193729400 |
| worker | git.acquire.process | 12055330800 |
| wall | execution | 4539604900 |
| wall | discovery | 2705503600 |
| wall | discovery.git | 2705500000 |
| wall | git.deltas | 2354113300 |
| wall | scan | 1619463100 |
| wall | git.command | 250555400 |
| wall | rules.load | 245526400 |
| worker | matching.regex | 132776500 |

### Eight-worker serial floor

`serial` is `execution − scan`; it is the portion of profiled wall time not covered by the worker scan phase.

| Workload | Execution ms | Scan ms | Serial ms | Serial share | Worker busy / scan |
|---|---:|---:|---:|---:|---:|
| legacy-10x | 5477.7 | 4055.4 | 1422.3 | 26.0% | 7.224 |
| legacy-5x | 4686.9 | 3780.0 | 906.9 | 19.4% | 7.177 |
| rnclab-filesystem | 438.0 | 91.2 | 346.8 | 79.2% | 6.432 |
| rnclab-git | 4539.6 | 1619.5 | 2920.1 | 64.3% | 7.529 |

## Host load during the experiment

Host memory/disk samples: 184.
System memory load: median 66.0% (min 64.0%, max 71.0%).
Free disk: median 116.8 GiB (min 116.6 GiB).

## Detection and coverage integrity

| Workload | Reference findings | Matrix finding signatures | Source units | Inspected bytes | Coverage |
|---|---:|---|---:|---:|---|
| legacy-10x | 3710 | PASS | 3609 | 61306560 | PARTIAL |
| legacy-5x | 1855 | PASS | 1809 | 60013688 | PARTIAL |
| rnclab-filesystem | 371 | PASS | 360 | 258574 | PARTIAL |
| rnclab-git | 126 | PASS | 116 | 43879 | COMPLETE |

`PARTIAL` is expected and unchanged for canonical filesystem (11 scanner-declared symlink aliases) and legacy loads (one large file beyond the scanner's default total-byte admission). The same units are uninspected in every profiler/worker configuration; no configuration changes coverage.

## Independent post-run audit

Audit available: **True**. Records: 208; measured: 160; failed: 0. Unit dispositions equal: **True**; profile counters equal: **True**; command flags equal: **True**; raw reports present: **True**; profiles present: **True**; paired blocks: 80 (off-first 41, on-first 39); sequential: **True**; span: 27.193 min.

CP4B/CP4C reference audit: rnclab-filesystem units=True, findings=True, target_ids=True; rnclab-git units=True, findings=True, target_ids=True.

This audit independently reparses every retained private report and profile; it is separate from the run-time acceptance checks.

## Bottlenecks and interpretation

- Median profiling overhead at eight workers is +1.05% (observed range -9.44% to +4.76% across all worker/workload pairs).
- Profiling overhead does not show a consistent positive concurrency trend: the deltas are small and frequently negative, so there is no evidence of a shared profiling mutex or serialization penalty that grows with worker count. Sub-second filesystem measurements remain the noisiest.
- Worst eight-worker parallel efficiency is 0.148; scaling is bounded by serial discovery/rules work rather than pure worker count.
- legacy-10x at 8 workers: serial non-scan time is 1422.3 ms of 5477.7 ms (26.0%); worker busy/scan ratio is 7.224.
- legacy-5x at 8 workers: serial non-scan time is 906.9 ms of 4686.9 ms (19.4%); worker busy/scan ratio is 7.177.
- rnclab-filesystem at 8 workers: serial non-scan time is 346.8 ms of 438.0 ms (79.2%); worker busy/scan ratio is 6.432.
- rnclab-git at 8 workers: serial non-scan time is 2920.1 ms of 4539.6 ms (64.3%); worker busy/scan ratio is 7.529.
- legacy-10x peak scanner memory rises 3.04x from one to two workers (123.6 to 375.7 MiB), then stays near that level through eight workers.
- legacy-5x peak scanner memory rises 3.39x from one to two workers (104.5 to 354.5 MiB), then stays near that level through eight workers.
- rnclab-filesystem peak scanner memory rises 3.68x from one to two workers (89.5 to 329.5 MiB), then stays near that level through eight workers.
- rnclab-git peak scanner memory rises 3.73x from one to two workers (84.2 to 314.3 MiB), then stays near that level through eight workers.
- RNC Lab Git profiling overhead ranges from -1.80% to +2.69%.
- Independent post-run audit: 160 measured runs, 0 failures, unit dispositions equal=True, profile counters equal=True, command flags equal=True.

## Recommended changes to the full CP4C matrix

- Profiling overhead is small at the measured production-scale workloads; retain profile-on as a diagnostic control but preserve profile-off as the primary timing condition.
- Do not add more than eight workers. Keep workers 1/2/4/8 in the full matrix and report efficiency; the data do not justify a larger fan-out.
- Budget for the serial floor: rules load, discovery and reporting do not scale with workers. The full matrix should report that floor separately from scan-phase speedup.
- Do not use canonical RNC Lab filesystem as the primary worker-scaling workload: its fixed startup/rules/discovery cost dominates a sub-second scan. Use x5/x10 for throughput scaling and filesystem only for regression.
- Git whole-history scaling is capped by serial discovery and `git.deltas`; the full matrix should treat process/batch and whole/diff as the primary Git variables rather than expecting workers alone to remove that floor.
- Plan for a step increase in scanner working set at two workers (observed roughly 3-4x the single-worker value); it was flat through eight workers on this host but must be monitored at every full-matrix configuration.
- Use five measured repetitions for the full matrix, with two canonical warmups and one load warmup; retain all outliers.
- Treat the legacy x5/x10 results as throughput/memory scaling evidence only; do not score them against the canonical oracle.

## Limitations and provenance

- DEV environment: contended developer workstation; timings are preliminary and not release evidence.
- Scanner CPU and peak memory are scanner-process measurements; child Git CPU/memory are unavailable and not treated as process-tree totals.
- Profile worker-phase times are accumulated across workers and are not wall elapsed time.
- Profile wall phases are internal attribution; the external harness clock is authoritative for primary wall time.
- The RNC Lab filesystem lane includes 11 scanner-declared symlink aliases that are not followed; canonical units still reconcile.
- Legacy x5/x10 workloads are performance-only and are not scored against the canonical accuracy oracle.
- CP4C writes reports/profiles outside the scan root; the harness uses the OS temporary directory and copies evidence into the experiment directory.
- System-wide CPU utilization and thermal state were not independently instrumented; the host was declared DEV with 64-71% memory load and stable free disk during sampling.
- CP4C rejected report/profile parent handles under the workspace path with access denied; the harness wrote to the OS temporary directory and copied every artifact into this evidence tree.
- The published CP4B 297/640 filesystem and 110/160 Git counts use the pre-remediation scorer; the preserved CP4B raw findings equal CP4C raw findings and current scoring yields 347/640 and 120/160.
- Child Git process CPU/memory were not sampled; scanner-process CPU is reported separately and must not be interpreted as a process-tree total.

Artifact: `170bd1df345c4985043ff449051c247f22a1012fe9c054cae5c2edcc190fb1cb` (805e3bb79276b94de636e27024f38773da303b44)
Ruleset: `2eb315fa40553ab1e133322a1f0a014a4593ab2ca6164152149eb59c1197a6b7`
Manifest: `c43792964fd8b07317ff8e3bc8fb75c63f175387d27d2b5855814ecebd4d132b`
CP4B reference: `d5dc4a1620da8b4a9a38f298933bbcc2bd094de89fe96cde3ebd551edcba61f4` (d00f71f1e2cf16ce58beb07d8b960c5ad056f915)
Harness code: `cfc1cb001eeb95cfccc57bb41c30ea156988ccb2`

Raw reports, profiles, commands and per-run evidence remain under this Git-ignored experiment directory.
