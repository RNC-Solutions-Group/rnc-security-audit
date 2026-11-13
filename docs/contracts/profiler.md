# CP4C execution profile contract

> **Schema:** [`profiler.schema.json`](profiler.schema.json), profile schema
> version `1`. Profiling is opt-in with `--profile-output PATH`. It never changes
> detection policy, finding identity, coverage accounting or CI acceptance.

## Privacy

The profile contains only phase names, integer durations, operation counts,
byte counts, configured settings and the run ID. It must never contain raw
credentials, matched values, Git object content, locators, evidence digests,
finding IDs or policy selectors. A profile is a performance artifact, not
private detection evidence.

## Timing model

All durations are integer nanoseconds.

- `phases` are **wall-clock** observations made on the main execution path. The
  `exclusive_ns` field subtracts known direct child wall phases.
- `worker_phases` are **accumulated** observations across workers. Their `ns`
  value is not elapsed time and must never be presented as wall time.
- `counters` are operation counts and effective settings, not durations.

The independent harness must use its own OS-level clock for primary wall time;
the profile is an internal attribution aid.

## Settings

`settings.requested` records the explicit CLI request. `settings.effective`
records the resolved value, including `auto` worker resolution and backend
fallback. Requested/effective values include:

- `workers`;
- `git_io`;
- `history_mode`;
- `context_lines`;
- `mode`;
- `strategy`.

## Stable phase names

| Phase | Kind | Meaning |
| --- | --- | --- |
| `execution` | wall | Total profiled execution |
| `startup.cli` | wall | CLI parse and immediate argument resolution |
| `startup.config` | wall | Effective configuration load and policy resolution |
| `rules.load` | wall | Rule bundle load and schema validation |
| `rules.plan` | wall | Backend plan construction |
| `discovery` | wall | Source discovery total |
| `discovery.filesystem` | wall | Filesystem enumeration/checks |
| `discovery.git` | wall | Git repository checks, commit enumeration and deltas |
| `git.open` | wall | Git repository safety/open checks |
| `git.enumerate` | wall | `rev-list` traversal |
| `git.deltas` | wall | `diff-tree` changed-path generation |
| `git.diff` | wall | Per-revision unified-diff generation for diff mode |
| `git.command` | wall | Other bounded Git subprocess operation |
| `scan` | wall | Candidate scanning and evidence construction |
| `reporting` | wall | Final report generation/writing |
| `matching.regex` | worker | Exact regex candidate extraction |
| `matching.literal_filter` | worker | RegexSet/Aho-Corasick required-literal filtering |
| `scan.context` | worker | Candidate context extraction and syntax gate |
| `scan.validation` | worker | Validator execution |
| `scan.findings` | worker | Line mapping, hashing, dedupe and finding construction |
| `git.acquire.process` | worker | Per-object `git cat-file blob` acquisition |
| `git.acquire.batch` | worker | Persistent `git cat-file --batch` acquisition |
| `git.batch.start` | worker | Batch child-process creation |
| `scheduling.worker_busy` | worker | Accumulated worker busy time |
| `scheduling.queue_wait` | worker | Dispatch-to-worker-start delay |
| `reporting.serialize` | wall | Report serialization |
| `reporting.write` | wall | Report publication or console output |

Phases that do not occur in a configuration are omitted.

## Counters

Common counters include `candidates`, `findings`, `units_discovered`,
`validators_accepted`, `validators_rejected`, `workers_effective`,
`bytes_inspected`, `units_uninspected`, `diff_scan_ranges`,
`diff_introduced_lines` and `diff_context_filtered`.
Counters are non-negative integers and are not durations.

## Failure semantics

Profile serialization/publication happens after the scan report is generated.
A profile publication failure prints an error and exits `30`; it is never
silently ignored. A failed scan does not produce a profile that claims complete
execution.

## Overhead

Profiling is compiled into the scanner but the recorder is absent unless
`--profile-output` is supplied. Recorder calls are aggregated per window or
subprocess where possible. Instrumented and non-instrumented detection output
must be identical; the independent performance matrix should include a
profile-on/profile-off control.
