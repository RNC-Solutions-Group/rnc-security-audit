# CP5 detection backlog

> **Status:** Deferred detection work discovered during CP4B/CP4C independent
> evaluation. CP4C is a performance-engineering pass and does not change rules,
> validators, confidence or placeholder behavior. These items require separate
> operator authorization and independent evidence.

## Priority candidates

| Candidate | Observed gap | Required treatment |
| --- | --- | --- |
| WordPress salts | 126 RNC Lab filesystem misses | Add explicit framework-name/context support with negative controls |
| Application HMAC/signing keys | 46 filesystem and 31 Git misses | Define bounded name/value context; do not treat every `hmac` token as a secret |
| Database/application passwords | Coverage gaps | Expand context rules without weakening URI/component identity |
| Generic API keys | Missed opaque shapes | Context-aware candidate model; avoid arbitrary high-entropy matching |
| OTP/TOTP seeds | Missed `otpauth`/seed contexts | Structured URI/parameter parsing with exact component offsets |
| JWT signing keys | Missed signing-secret context | Keep JWT bearer and signing-secret identities distinct |
| Private-key formats | Additional representations | Bounded structural validators and public/certificate negatives |
| ANSI-colored assignments | Regression class | Preserve exact source span while normalizing only for validation |
| Twilio SIDs | Regression class | Define identifier-vs-credential classification before adding a rule |
| Masked/redacted values | False positives | Add explicit masking indicators, not blanket suppression |
| Bot-auth tokens | False positives | Distinguish robot/auth metadata from credentials |
| Duplicate history delivery | Duplicate occurrences | Resolve at history occurrence identity/reporting boundary, not by dedupe across commits |

## PEM scoring discrepancy

The independent harness identified a PEM scoring discrepancy affecting 53 of 59
observed PEM findings. This is a **cross-scanner scoring investigation**, not a
CP4C detection change.

- Do not modify the scoring implementation or benchmark oracle in CP4C.
- Retain the affected baseline evidence.
- Apply any independently approved correction consistently to both baseline and
  candidate evidence before comparison.

## Boundaries

- No rule or validator changes in CP4C.
- No benchmark-oracle changes.
- No broad recall-only loosening.
- Each candidate requires independent fixtures, exact-byte truth and explicit
  false-positive controls before implementation.
