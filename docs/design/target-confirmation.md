# Target confirmation — application and image scans

> **Design example only.** This is illustrative terminal/report output, not functionality implemented by the toolkit.

```text
RNC SECURITY AUDIT — TARGET CONFIRMATION EXAMPLE
Illustrative day-zero output; target operations are not implemented.

THIS SCAN TARGETS AN APPLICATION, SYSTEM, OR CONTAINER IMAGE
Repository-only scanners do not require target IDs.

TRIVY                    READY
  Target Type: Container image
  Target Image: agkwebsite:local
  Scanner Runtime Image: [configured separately]

Type the exact image target to confirm:
> agkwebsite:local
TARGET VERIFIED

OWASP ZAP                READY
  Target Type: Web application
  Configured Target ID: [HIDDEN]
  Target ID: READ FROM REPOSITORY CONFIG
  Authorized Scope: [non-sensitive summary of local approved scope]

Type the exact configured target ID to confirm:
> [INPUT NOT ECHOED]
TARGET VERIFIED

Configuration Correct? [Y/N]
Begin Audit? [Y/N]

POLICY NOTES
- A target ID is optional in project config unless an enabled applicable scanner requires it.
- One target confirmation is required for EACH selected image/application/system scanner.
- A mismatch, missing required target, or unauthorized scope makes that scanner UNAVAILABLE; other ready scanners may proceed.
- Unattended CI is limited to preapproved non-interactive scopes and cannot silently bypass target authorization.
- Target ID and secret inputs must never be echoed in sanitized output.
- A configured scanner runtime image is not the same thing as the image being scanned.
```
