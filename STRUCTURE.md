rnc-security-audit/
│
├── config/
│   ├── settings.toml
│   ├── red-team.toml
│   └── repo-example.config
│
├── docs/
│   ├── SETUP.md
│   └── AUDIT-GUIDE.md
│
├── src/
│   └── rnc_security_audit/
│       │
│       ├── __main__.py
│       ├── cli.py
│       │
│       ├── core/
│       │   ├── config.py
│       │   ├── policy.py
│       │   ├── runner.py
│       │   └── reporting.py
│       │
│       ├── modes/
│       │   ├── pr_checks.py
│       │   ├── passive_audit.py
│       │   └── red_team_ops.py
│       │
│       ├── scanners/
│       │   ├── gitleaks.py
│       │   ├── trivy.py
│       │   └── semgrep.py
│       │
│       └── backends/
│           ├── docker.py
│           ├── native.py
│           └── wslc.py
│
├── tests/
├── pyproject.toml
└── README.md