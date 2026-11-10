# Policy specification

> **Design contract v0.2 — not implemented.** Policy determines what may be inspected and how evidence is disposed of; it never changes the engine's matching behavior. The v0.2 policy record is `docs/contracts/schemas/policy.schema.json`.

## Two independent policy points

| Policy stage | Input | Output | Invariant |
| --- | --- | --- | --- |
| **Pre-scan scope** | Target manifest + validated effective configuration | Accepted units, verified blocked-target register, scope errors | A claimed blocked target's content never reached the engine |
| **Post-scan finding** | Immutable finding events + effective exemption rules | Per-finding `ACTIONABLE` / `EXEMPTED` dispositions with policy IDs | Every detection still exists and is countable |

Disabling a scanner in audit orchestration is a **scanner-selection decision**, not a verified block on a source file. Required unavailable scans produce coverage gaps, not `POLICY_APPLIED` by themselves.

## Configuration sources and precedence

| Layer | Illustrative location | Role |
| --- | --- | --- |
| **Global** | User/organization config directory, `settings.toml` | Baseline defaults, required coverage, approved rules and mandatory controls |
| **Repository** | `.rncscanner.toml` | Repo-specific scope, exemptions, reporting and selected settings |
| **CLI** | `--block`, `--exempt`, `--accept-results` | Explicit run-scoped choices, subject to higher-layer restrictions |

The previous project-level `security.config` TOML remains a useful **audit-orchestrator configuration concept**; choose a single shared schema/migration plan during contract freeze. Do **not** silently interpret both formats with different semantics.

Configuration is validated once into an immutable **effective policy**, with the source file, policy ID, reason, author/owner where available, policy version and applicable scope retained. Example priority for an ordinary overridable setting: CLI > repository > global. **Mandatory organization restrictions and required checks cannot be overridden** by a lower-trust repository or CLI flag. Within allowed additive collections, deduplicate by normalized ID while retaining every contributing origin. Any conflicting rule must be rejected or explicitly resolved with a recorded explanation; never silently apply last-write-wins to security exemptions.

CLI arguments cannot inject executable commands, load unapproved rules from arbitrary URLs, authorize network targets or bypass authorization gates. Unknown settings, untrusted path traversal, or invalid global policy fail safely.

## Verified blocking

An exclusion must identify a target unambiguously and be enforced **before source content is read by the detector**. The exact enforcement method is recorded—e.g. adapter-level enumeration/filtering or a verified filtered snapshot. A tool's ignore flag that suppresses output after reading **does not qualify**. Behavior must be validated per source kind (working tree is different from Git history, archive extraction and container layers).

For each requested block, store:

- policy origin, stable policy ID, reason and normalized scope;
- count of requested targets, actually blocked targets and any unresolved targets;
- adapter and method used to prove non-access;
- status `APPLIED`, `UNSUPPORTED`, `INVALID` or `NOT_MATCHED` with diagnostic reason.

The v0.2 record makes this executable rather than illustrative:

- `effective_policies` assigns every policy ID an origin, version, digest and mandatory flag. Mandatory policies must originate globally.
- `requests` retains the selector and outcome for both blocks and exemptions. `APPLIED` requests must carry the matched unit/finding IDs; `NOT_MATCHED`, `UNSUPPORTED` and `INVALID` requests carry none and do not affect classification.
- `applied_blocks` links each verified blocked unit to exactly one applied block request, enforcement method and `verified_non_access: true`.
- `dispositions` links every exempted finding to an applied exemption request. An actionable finding cannot claim an applied policy.
- `policy_valid: false` carries an error list and forces the final result to `FAILED`; an invalid global policy is not a policy-applied result.
- `effective_policy_digest` is the canonical digest of the effective-policy array. It is not a raw config-file hash.

If a required target cannot be safely blocked or inspected, record a coverage problem (`INCOMPLETE` or `FAILED` as appropriate), **not** a verified exemption. A deliberately and verifiably blocked target can coexist with complete **policy-adjusted** coverage, but that scope reduction must remain visible in the result.

## Finding exemptions

Each exemption should be narrow and auditable: rule ID, exact source/finding selector or fingerprint, scope, optional expiry, reason, policy ID and source. Broad permanent exemptions are a governance exception, not the default. Matching applies **after** the engine emits findings. An expired or nonmatching exemption remains in policy diagnostics but does not suppress a finding.

Illustrative disposition:

```json
{
  "finding_id": "f-0007",
  "disposition": "EXEMPTED",
  "policy_id": "DEV-001",
  "origin": "repository",
  "reason": "Approved synthetic test fixture",
  "applied": true
}
```

For every detected finding, exactly one effective disposition is recorded. Without a validated matching exemption it is `ACTIONABLE`. Applying an exemption does **not** lower the engine's raw detection count or alter its confidence/severity classification.

## Policy acceptance tests

1. Block exactly two known file units before ingestion, confirm the detector never receives their content, and reconcile both requested/applied counts.
2. Detect findings in inspected units first, then exempt exactly three known findings; leave remaining detections actionable and intact.
3. Demonstrate that CLI cannot remove mandatory global coverage or expand an unauthorized target scope.
4. Verify same policy expressed at multiple layers retains source attribution and explicit conflict results.
5. Verify symlinks, path normalization, Git history and archive edge cases cannot falsely claim no-read enforcement.
6. Confirm policy updates change only scope/dispositions, not engine events for unchanged inspected inputs.
