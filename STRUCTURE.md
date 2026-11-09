# Proposed Python package structure

> **Design sketch only.** These directories and Python modules have not been created. Module boundaries may change as Proof 1 is tested.

```text
rnc-security-audit/
├── config/
│   ├── settings.toml               # toolkit-wide defaults and scanner catalog
│   ├── red-team.toml               # future active-test policy
│   └── repo-example.config         # optional project config example (TOML)
├── docs/
│   ├── PROOF-1.md                  # proof contract and acceptance
│   ├── SETUP.md                    # future user-facing install guide
│   └── AUDIT-GUIDE.md              # future workflows and output interpretation
├── src/
│   └── rnc_security_audit/
│       ├── __init__.py
│       ├── __main__.py             # python -m entry point
│       ├── cli.py                  # one CLI; modes are commands
│       ├── core/
│       │   ├── config.py           # read and validate settings once
│       │   ├── policy.py           # authorization and non-negotiable controls
│       │   ├── preflight.py        # per-scanner READY/UNAVAILABLE/DISABLED
│       │   ├── runner.py           # independent execution + cleanup
│       │   ├── exclusions.py       # future verified file/dir bypasses
│       │   └── reporting.py        # raw evidence + sanitized/aggregate status
│       ├── modes/
│       │   ├── pr_checks.py
│       │   ├── passive_audit.py
│       │   └── red_team_ops.py
│       ├── scanners/
│       │   ├── gitleaks.py         # first adapter
│       │   ├── trivy.py            # Proof 2 candidate
│       │   └── semgrep.py          # later candidate
│       └── backends/
│           ├── docker.py          # first proof candidate
│           ├── native.py          # second backend candidate
│           └── wslc.py            # future Windows candidate
├── tests/
├── pyproject.toml
└── README.md
```

## Responsibility boundaries

- **One application:** `cli.py` exposes the three operating modes. Each mode picks policy/profiles; none duplicates the engine.
- **Core config:** loads toolkit and project TOML into a validated read-only plan; scanners do not individually parse or rewrite config.
- **Preflight:** checks each applicable enabled scanner independently. Missing backends and scanner-specific invalid config make that scanner UNAVAILABLE, not the whole run.
- **Policy:** a globally invalid/unreadable policy or impossible-to-authorize scope is a hard stop. Application/system target IDs are optional for repository-only scans.
- **Scanner adapters:** know supported targets, command argument construction, evidence expectations, and findings-versus-error exit-code behavior.
- **Backends:** execute the approved adapter command in native/container runtimes without reinterpreting scanner findings.
- **Reporting:** preserves private raw evidence and writes validated sanitized reports, with separate execution and coverage statuses. Future exclusions must be verified non-access, not just output filtering.

## Proof discipline

Only create the modules needed to complete [Proof 1](docs/PROOF-1.md) at first. The other files above are intended interfaces, not a mandate to implement every adapter/backend/mode in the first commit.

`settings.toml`, `repo-example.config`, `SETUP.md`, and `AUDIT-GUIDE.md` above are proposed files, **not present or functional today**. The only codebase will be this repository; a later packaged executable would build from it.
