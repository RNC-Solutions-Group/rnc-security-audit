# CP0 PR #3 recovery record

> **Purpose:** Disclose a repository-governance discontinuity and the chosen recovery path. It does not rewrite the historical PR.

## Observed state at audit start

- `main` was at `e54d5bc`, a merge commit for PR #3 (`feat/cp0-contracts-corpus-benchmarks`).
- PR #3 was already **merged** on 10 November 2026; its source branch was no longer present on `origin`.
- The original CP0 branch therefore could not receive the audit commits, and the merged PR could not carry new code or a new acceptance checklist.

## Recovery strategy

1. Do not reopen or force-push the merged branch. Do not rewrite published history.
2. Create a descendant audit branch from the merged `main`: `feat/cp0-audit-hardening`.
3. Preserve the original CP0 artifacts and foundation documents; fix defects additively where possible.
4. Deliver the audit package on the descendant branch and open a new PR against `main`.
5. Add a cross-reference comment to PR #3 rather than rewriting its merged description. The complete CP0 acceptance checklist lives in the new audit PR.
6. No merge, no `main` modification, and no CP1 production engine work are performed by the audit.

This is a **continuation of CP0**, not a parallel reimplementation. The original branch's schemas, probes, fixtures and evidence are retained and explicitly audited in the CP0 report.

## Consequences

- Reviewers must use the new PR for the CP0 acceptance decision.
- PR #3 remains the historical merge point and is not retroactively marked complete.
- If the operator prefers a different recovery branch/PR name, only the branch/PR metadata changes; the audit artifacts and findings remain valid.

## Commands

```sh
git switch -c feat/cp0-audit-hardening
git push -u origin feat/cp0-audit-hardening
```

No force-push, reset or branch deletion is authorized by this record.
