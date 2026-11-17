# Execution provenance and scanner-argument contract

This document defines what the harness records when it executes a scanner, how
scanner arguments are classified, and what the report may claim from that
evidence. It is the implementation contract for `harness.provenance`,
`harness.execution`, the adapter boundary, and the experiment report.

## Three command layers

The report keeps these layers distinct:

1. **Harness invocation** - the command that started `python -m harness`. It is
   recorded in `execution_provenance.harness_command` and is not a scanner run.
2. **Direct scanner invocations** - the argv passed to the scanner process by an
   adapter. Every record has `direct_execution: true` and `execution_origin:
   "direct"`.
3. **Auxiliary operations** - Git inspection, dataset preparation, Docker fixture
   validation, or cleanup. These are never counted as scanner invocations. Docker
   fixture validator output may expose nested scanner runs; those records carry
   `direct_execution: false` and `execution_origin: "nested-docker-validator"`.

A failed or blocked artifact verification is not a launched scanner process. If
`process_started` is false, the report must say the process was not launched.

## Invocation record

Each actual invocation is appended to `invocations` and to
`execution_provenance.scanner_invocations`. The stable fields are:

| Field | Meaning |
| --- | --- |
| `invocation_id` | Experiment-scoped identifier, for example `20261116T...-inv-0004` |
| `experiment_id` | Harness experiment or Matrix experiment identity |
| `sequence` | Monotonic execution order |
| `scanner`, `scanner_name`, `adapter` | Adapter identity |
| `build_id`, `version` | Registered build identity |
| `artifact_identity` | Executable path/SHA-256 or image tag/ID, platform, OS, architecture, execution method, verification state |
| `source_commit`, `source_identity`, `manifest_sha256` | Manifest metadata, explicitly not a source checkout |
| `invocation_type`, `phase` | `detection`, `warmup`, `measured`, `verification`, `reference`, or `diagnostic` |
| `suite`, `workload`, `workload_context` | Suite, workload, lane, load profile, target, mode |
| `command` | Sanitized ordered argument vector as executed |
| `supplied_arguments` | Classified experiment-owned arguments |
| `command_sha256` | SHA-256 of the unredacted argv |
| `command_rendered` | Correctly quoted PowerShell and POSIX display forms |
| `command_template` | Derived normalized display template, never the literal command |
| `cwd` | Sanitized actual working directory |
| `environment` | Cleared scanner-config keys, explicit nonsecret overrides, container env |
| `configuration` | Profile, config path/digest, rules file/digest |
| `exit_code`, `accepted_exit_codes`, `exit_accepted` | Outcome interpretation |
| `process_started`, `timed_out`, `error_code`, `error_message` | Failure semantics |
| `status` | PASS, FAIL, or BLOCKED |
| `timestamps`, `duration_seconds`, `timeout_seconds` | Timing evidence |
| `evidence` | Sanitized report path, report/stdout/stderr SHA-256, raw-evidence policy |

`command` is the executed vector, not a reconstruction. The normalized template
replaces volatile values such as `<TARGET>`, `<REPORT>` and `<WORKSPACE>`. Reports
must label it as a template and must not present it as the literal command.

Credential-bearing values are redacted when a recognized sensitive flag is used,
when a URL contains userinfo, or when an argument contains an authorization header
or sensitive assignment. The unredacted argv digest is retained. Whole shell
environments are never copied into a report.

## Scanner arguments

`--scanner-args` accepts only explicit flags and values. A positional argument is
rejected because it could silently change the scanner command structure. The CLI
uses a Windows/POSIX-safe splitter that preserves unquoted Windows paths.

Arguments are classified as:

| Category | Examples | Baseline effect |
| --- | --- | --- |
| `PERFORMANCE` | `--workers`, `--threads`, `-j`, `--profile-output`, `--mode`, `--strategy`, `--git-io` | Detection may remain DEFAULT; performance result is explicitly tuned |
| `DETECTION` | `--config`, `--rules`, `--baseline-path`, rule enable/disable | Not DEFAULT-baseline comparable |
| `SCOPE` | `--log-opts`, `--history-mode`, `--no-git`, `--source`, `--ref` | Not DEFAULT-baseline comparable |
| `OUTPUT` | `--verbose`, `--log-level` | Allowed unless harness-critical; recorded as an output override |
| `SECURITY` | `--timeout`, size/archive/decode limits, container runtime controls | Not baseline-comparable without evidence |
| `UNKNOWN` | Any unregistered flag | Forwarded when the adapter accepts it, but marked `EXPERIMENTAL_UNVERIFIED` |

Each argument record carries:

- original index;
- flag and requested value;
- category and effect;
- origin (`cli`, `matrix`, `configuration`, `manifest`, `harness-generated`,
  `adapter-generated`, `scanner-default`);
- acceptance evidence;
- effective value only when independently observable;
- whether the argument is neutral to detection comparability.

An effective value is `null` when the retained artifact does not expose it.
`--workers auto` is therefore recorded as requested, with effective worker count
unknown unless a profile schema-v1 artifact is available.

### Reserved flags

The harness rejects arguments that would override its own source, output, result
accounting, or registered artifact identity. Examples:

- RNC: `--root`, `--rules`, `--config`, `--output`, `--format`, `--run-id`,
  `--history`, `--ref`;
- Gitleaks/Betterleaks: `--config`, `--source`, `--report-format`,
  `--report-path`, `--exit-code`, `--no-banner`, `--redact`.

Duplicate single-valued flags are rejected rather than resolved by last-one-wins.
This is a fail-closed policy, not a restriction on useful performance tuning.

## Comparability states

| State | Meaning |
| --- | --- |
| `BASELINE_COMPARABLE` | DEFAULT detection, default source scope, no unknown/security override |
| `PERFORMANCE_TUNED_BASELINE_DETECTION` | DEFAULT detection with explicit performance/execution settings |
| `DEFAULT_DETECTION_WITH_REPORTING_OVERRIDE` | DEFAULT detection with a benign reporting override |
| `NOT_BASELINE_COMPARABLE` | Detection, scope, security, or CUSTOM configuration changed |
| `EXPERIMENTAL_UNVERIFIED` | Unknown scanner argument; no baseline claim permitted |

`baseline_detection_comparable` and `baseline_metrics_included` are separate from
the profile name. A performance-only experiment can preserve DEFAULT detection
while carrying an explicit execution configuration.

## Failure behavior

- Invalid, duplicate, positional, or reserved arguments fail before any scanner
  process is launched.
- A process that cannot start records `process_started: false` and `BLOCKED`.
- A timeout records `timed_out: true`, `BLOCKED`, and the timeout duration.
- A missing or malformed report is a failure, never zero findings.
- Failed, skipped, and blocked invocations are rendered in a separate report
  table and are not counted as successful scans.

## Where to find the evidence

In an experiment report:

- `execution_provenance.argument_policy` - requested/effective classification;
- `execution_provenance.scanner_invocations` - machine-readable per-run records;
- `Invocation` records in the Markdown section - human-readable per-run argv;
- performance `runs[].invocation_id` - links each measured duration to the exact
  scanner invocation;
- Matrix `execution_provenance.invocations` - equivalent per-run records for
  worker/profiler configurations.

## Tests

`tests/test_provenance.py` covers argument splitting, reserved/duplicate flags,
performance-only comparability, scope/detection/unknown comparability, redaction,
quoting, Docker/native argv capture, failed starts, and template labeling.
