# CP4C independent-harness integration handoff

> The independent RNC Scanner Harness owns the CP4C matrix, scoring, OS
> telemetry and consolidated performance report. This document defines the
> scanner-side contract only. It does not authorize scanner-side scoring or a
> benchmark implementation.

## Executable identity

Use one frozen CP4C executable and ruleset for the whole experiment. Record:

- executable SHA-256 and build commit;
- `rnc --version`;
- ruleset version/digest;
- harness version and machine identity.

The CP4B baseline must remain the original CP4B executable built from
`d00f71f1e2cf16ce58beb07d8b960c5ad056f915`; do not substitute the CP4C binary.

## Matrix

Workers: `1`, `2`, `4`, `8`, `auto`  
Git I/O: `process`, `batch`  
History mode: `whole`, `diff`  
Diff context: `0`, `1`, `3`, `5`

Whole is one configuration per worker/I/O pair; diff has four context values.

```text
5 workers x 2 I/O x (1 whole + 4 diff) = 50 configurations
```

Hold:

- `--strategy auto`;
- `--mode auto`;
- one stream-chunk setting;
- one execution-limit set;
- one ruleset;
- one dataset;
- native Windows AMD64.

Do not run Docker, GitHub Actions or overlapping benchmark processes.

## Command template

```text
rnc scan --history --root <RNC Lab v3 repository> \
  --rules <frozen rnc-providers-v1.json> \
  --format private --output <run-private.json> \
  --run-id <experiment-config-run> \
  --workers <1|2|4|8|auto> \
  --git-io <process|batch> \
  --history-mode <whole|diff> \
  [--context-lines <0|1|3|5>] \
  --mode auto --strategy auto \
  --profile-output <run-profile.json>
```

Filesystem worker scaling is a separate small comparison over
`--workers 1,2,4,8,auto`; it does not vary Git I/O, history mode or context.

Record the exact argv, working directory, environment variables relevant to Git
and the scanner, exit code, stdout/stderr, private-report path and profile path
for every run. Do not publish private report contents.

## Run plan

- One warmup and five measured runs per configuration as the initial design.
- Balanced or randomized order across configurations and repetitions.
- No overlapping runs.
- Preserve all outliers; summarize median, spread and sample count.
- Support resuming without repeating a completed `(configuration, repetition)`.
- Validate profile schema and configuration identity before accepting a run.
- Retain individual profile JSON and per-run private detection evidence.

## Profile ingestion

Profile schema: [`profiler.schema.json`](../contracts/profiler.schema.json),
version `1`. Field documentation:
[`profiler.md`](../contracts/profiler.md).

Required ingestion checks:

- `schema_version == "1"`;
- requested/effective settings match the invoked configuration and actual
  executable;
- `phases.execution` exists;
- no duplicate phase keys (JSON parser behavior must be explicit);
- profile contains no locators, values, digests, finding IDs or Git content;
- profile publication failure was observed as exit `30`, not silently ignored.

Wall phases are internal attribution only. Primary wall/CPU/memory measurements
must come from harness-side OS telemetry. Worker phases are accumulated and must
never be presented as elapsed time.

## Detection evidence

The harness reuses its existing byte-addressed scoring without modifying oracle
rules. For each configuration:

- retain the private report and exact finding set;
- compare canonical findings only for equivalent source scope;
- do not compare `whole` and `diff` occurrence counts as if they were the same
  scope;
- record incomplete coverage, binary-diff limitations, timeouts, candidate
  limits and execution failures;
- preserve the existing CP4B reference results separately.

## Required consolidated outputs

- `cp4c-performance.md`
- `cp4c-performance.json`
- `cp4c-runs.csv`
- individual profile JSON artifacts
- experiment manifest and provenance records

The human-facing report should include:

1. all 50 configurations and status;
2. runtime, CPU, memory and throughput median/spread;
3. per-phase timing and dominant costs;
4. worker scaling/efficiency;
5. process versus batch acquisition;
6. whole versus diff and context effects;
7. detection equivalence and existing accuracy outcomes;
8. incomplete coverage, instability, missing instrumentation and failures.

Do not duplicate 50 standard reports in prose; retain evidence and summarize.

## Proposed harness commands

```text
python -m harness matrix --experiment cp4c
python -m harness report --experiment cp4c
```

The report command must operate on retained evidence without rerunning the
scanner. If the harness cannot support a configuration or profile field, mark it
unsupported/absent rather than silently substituting another value.

## Windows telemetry

The harness must account for scanner child processes (`git`) or explicitly state
that child CPU/memory is unavailable. Scanner-process-only measurements must not
be presented as total experiment CPU.

## Boundaries

- No harness source, oracle or truth changes in the scanner repository.
- No scanner-side benchmark scoring.
- No 50-configuration production run without separate operator direction.
- No CPU throttle in this experiment.
