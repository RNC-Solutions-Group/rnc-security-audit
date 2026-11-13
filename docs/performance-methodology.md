# Performance benchmark methodology

**Contract version:** `2`
**Checkpoint:** CP3 + benchmark-environment extension

Performance observation is separate from detection correctness. The experiment
runner invokes products through the scanner adapter boundary and never parses
scanner findings for performance or changes detection results. No weighted
combined accuracy/performance score is produced.

## Environment profiles

The measurement environment is declared explicitly and is never inferred from a
scanner score:

| Profile | Intended use | Contention | Stability threshold | Publishable |
| --- | --- | --- | ---: | --- |
| `DEV` | functional assessment and preliminary timing; default on a developer host | uncontrolled | CV ≤ 0.25 | No |
| `CONTROLLED` | reduced contention with documented host conditions | documented/reduced | CV ≤ 0.10 | No |
| `RELEASE` | pinned builds, default configuration, controlled hardware | controlled | CV ≤ 0.05 | Yes |

`RELEASE` must use the default stress profile. Optional `cpu`, `memory`, `io`, and
`network` stress profiles are reserved for future controlled experiments and are
reported separately from the default baseline. The profile is metadata; it never
changes scanner detection rules, the oracle, or timeout policy.

## Execution modes

- **Detection suites:** each invocation records wall-clock duration and execution
  metadata; no repeated benchmark is implied.
- **Experiment performance section:** one warm-up plus five measured runs by
  default, sequential, configurable with `--warmups` / `--runs`,
  `--benchmark-environment`, `--stress-profile`, and `[performance]`. Performance
  is part of the same experiment report as detection but remains a separate
  measurement.
- **Build timing:** source checkout, native build, and Docker build durations are
  recorded separately and are never counted as scanner execution time.

## Workload

Final evidence uses the pinned Leaky Repo working tree replicated ten times to
make short scanner runs long enough for meaningful timing and Docker sampling:

- 610 files
- 5,888,020 bytes
- 10 replicas
- no `.git` directory

## Measurements

| Measurement | Definition |
| --- | --- |
| Wall-clock runtime | Monotonic elapsed time around the scanner invocation |
| CPU time | Native process user+kernel time; Docker CPU utilization is reported separately from CPU seconds |
| Peak memory | Native process peak working set; Docker `MemStats.MemUsage` where sampled |
| CPU utilization | CPU seconds / wall-clock (native), or Docker `CPUPerc` |
| Throughput | workload bytes / median wall-clock |
| Inspected throughput | inspected bytes / median wall-clock |
| Files eligible / inspected | declared workload counts; not inferred from findings |
| Archive fields | archive files and extracted count where applicable |
| Stability | all measured runs completed and runtime CV ≤ the profile threshold |
| Failures/timeouts | explicit counts; unavailable metrics are `null`, never zero |

The report records host CPU count, RAM, disk capacity/free space, load average,
toolchain, scanner order, cache state, warm-up/measured sequence, timeouts,
resource-limit events, and every measured iteration. A prior measurement can be
compared with `performance_drift`; both documents are left unchanged. Detection
drift against a pinned build is a separate `baseline.compare_results` operation.

### Native implementation

On Windows, a polling sampler uses `OpenProcess`, `GetProcessTimes`, and
`GetProcessMemoryInfo` to capture process CPU and peak working-set memory. On
Linux it reads `/proc/<pid>/stat`. Sampling interval is 50 ms. CPU utilization can
exceed 100% because it measures process CPU across multiple cores.

### Docker implementation

Docker containers are named during benchmark runs and sampled with
`docker stats --no-stream --format {{json .}}`. `CPUPerc` is recorded as Docker's
utilization value; container CPU-seconds are not synthesized. Short containers may
finish before the first stats sample; those values are reported unavailable. On
this Windows/Docker Desktop host, `MemUsage` was often zero/unavailable for the
short-lived container, so Docker peak memory is `null` rather than zero.

## Actual results

Workload: 610 files / 5,888,020 bytes; 1 warm-up + 5 measured runs; all products
used scanner `v8.0.0-rnc.5f6ec56cfa6f`.

| Product | Median s | Min / max s | CV | CPU median s | Peak MiB | Throughput B/s | Stability |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Windows AMD64 native | 0.675 | 0.617 / 0.823 | 0.109 | 2.094 | 72.8 | 8,722,993 | STABLE |
| Docker Linux AMD64 | 2.129 | 1.878 / 2.401 | 0.082 | N/A | N/A | 2,765,627 | STABLE |
| Docker Linux ARM64 (emulated) | 5.377 | 4.985 / 7.286 | 0.150 | N/A | N/A | 1,095,038 | STABLE |

The native result is not directly comparable to either Docker result because the
execution environment differs. Docker ARM64 is emulated on the AMD64 host and is
not directly comparable to Docker AMD64. Accordingly, all three comparison
contracts are `NOT_DIRECTLY_COMPARABLE`, not a single performance ranking.

Detection metrics are attached separately in the performance comparison contract
(filesystem legacy, filesystem rich, synthetic history). They are identical across
these products in the final CP1E run; no combined score is calculated.

## CP2 historical multi-scanner measurements

CP2 compared Gitleaks and Betterleaks on all three products using one warm-up and
five measured runs. CP3 retires cross-scanner comparison from the harness; these
values remain historical evidence only. See
[`reports/cp2/performance.json`](../reports/cp2/performance.json).

| Scanner | Windows native | Docker AMD64 | Docker ARM64 (emulated) |
| --- | ---: | ---: | ---: |
| Gitleaks | 0.786 s | 3.578 s | 6.929 s |
| Betterleaks | 0.683 s | 2.870 s | 9.249 s |

## CP3 historical source-built experiments (superseded by CP11)

> **Historical note:** these CP3 measurements were produced by the retired
> source-acquisition/build workflow. CP11 executes operator-provided artifacts
> and has no scanner build step, so CP3 build times and artifact provenance are
> not directly reproducible under the current harness.

CP3 performance runs are attached to each independent source-build experiment.
No cross-scanner weighted score or comparison transaction exists. Each experiment
records source-commit metadata, executable hash/image ID, artifact verification,
every measured iteration, median/min/max/stdev/CV, file/byte counts, CPU and peak
memory where available, host toolchain, and native/container/emulated labels.
No scanner build duration exists for operator-provided CP11 artifacts.

Final representative evidence (610 files / 5,888,020 bytes; native and both
Docker products: 5 warm-ups + 7 measured runs):

| Scanner | Product | Median s | Min / max s | CV | CPU median s | Peak MiB | Stability |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Gitleaks | Windows AMD64 native | 0.699 | 0.482 / 0.912 | 0.215 | 2.328 | 67.9 | STABLE |
| Gitleaks | Docker Linux AMD64 | 2.448 | 2.044 / 2.851 | 0.106 | N/A | N/A | STABLE |
| Betterleaks | Windows AMD64 native | 0.666 | 0.516 / 0.819 | 0.160 | 1.531 | 119.4 | STABLE |
| Betterleaks | Docker Linux AMD64 | 2.196 | 1.829 / 2.904 | 0.151 | N/A | N/A | STABLE |

All four representative sets are stable after the environment correction.
Native and container results, and any emulated architecture, are not directly
comparable. Docker CPU-seconds and peak memory remain unavailable for short
containers and are `null`, not zero. The exact per-iteration evidence is in the
individual [`reports/cp3/`](../reports/cp3/) experiment JSON files.

## Limitations

- DEV measurements are contended and are not release evidence.
- The harness records declared workload/eligible/inspected counts; it does not
  infer scanner-internal archive traversal coverage from timing.
- Short Docker runs and `docker stats` sampling can lose CPU/memory values.
- Windows CPU utilization >100% reflects multiple cores, not measurement error.
- Runtime on a developer workstation is not a production capacity statement.
- Emulated ARM64 is not native ARM64 performance.
- Performance benchmarking reruns the scanner; it does not claim zero overhead.
- Stress profiles are architecture placeholders until a controlled host and
  stress driver are explicitly assigned and validated.
