# CLI concept — interactive repository audit

> **Illustrative day-zero screen.** No CLI, scanner, report generator, or target is implemented.

```text
RNC SECURITY AUDIT

Select Operation:
  [1] PR Security Checks
  [2] Passive Security Audit
  [3] Red Team Operations (separate authorization required)

Selection: 2

Repository Path:
> C:\repos\agkwebsite

Validating repository and loading configuration...
Repository: VALID
Toolkit settings: VALID

ENABLED SCANNERS
────────────────────────────────────────
GITLEAKS                READY
  Backend: Docker
  Profile: Repository / working tree
  Applied settings: source-only; redaction required

TRIVY                   READY
  Backend: Docker
  Profile: Repository filesystem
  Applied settings: configured severity profile

SEMGREP                 UNAVAILABLE
  - Backend not found
  - Invalid Semgrep-specific repository configuration

DISABLED SCANNERS
────────────────────────────────────────
OWASP ZAP               DISABLED
  - Disabled in repository config

Raw Reports: [private configured location]
Sanitized Reports: docs/pre-production/

PREFLIGHT: 2 READY / 1 UNAVAILABLE / 1 DISABLED
Coverage will be PARTIAL if you proceed.

Proceed with available scanners? [Y/N] Y
Configuration Correct? [Y/N] Y
Begin Audit? [Y/N] Y

Running: Gitleaks, Trivy
Skipped: Semgrep (UNAVAILABLE), OWASP ZAP (DISABLED)

AUDIT EXECUTION: COMPLETED
AUDIT COVERAGE: PARTIAL
  - Completed: 2
  - Unavailable/skipped: 1
  - Disabled: 1
Reports: [validated destinations]
```

Repository-only scans do **not** prompt for an application target ID. Enabled-but-unavailable scanners do not stop independent ready scanners. A fundamental failure to establish authorized scope or parse global policy is a different, run-blocking condition.

For a future unattended CI invocation, the same preflight is non-interactive: record unavailable scanners and use the configured strict/permissive policy to decide the job exit result, while still executing ready scans where safe.
