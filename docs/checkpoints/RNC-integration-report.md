> **HISTORICAL CORRECTIVE REPORT (source `5391d845`).** The newer pinned source
> `93b4dda909cb3b41606a4d0f36c8ef9d06b77fde` adds Git-history and CP4A structured
> database-password evidence. See the
> [CP5 RNC modernization report](CP5-rnc-modernization-report.md) for the current
> adapter capability and actual results. This earlier report remains valid for
> its filesystem-only source scope.

# RNC Scanner integration and corrective evaluation

**Status:** Corrective pass complete and awaiting owner review. The adapter is
trustworthy within its supported filesystem capability; this report does not
claim scanner approval, production fitness, or Git-history support.

- **Scanner:** RNC Scanner (`rnc`) `0.1.0`
- **Source repository:** `RNC-Solutions-Group/rnc-security-audit`
- **Source commit:** `5391d8457ea091c45733920078a7f714ec61f678`
- **Starting harness commit:** `b48bc0fcf7a0a88082627785ceb68dd229d84323`
- **Corrective harness code commit:** `7b0e669a52b5cf61b024eb13c41fa1689d03e277`
- **Harness branch:** `test/scan-harness` (orphan)
- **Evaluation date:** 2026-11-11
- **Host:** Windows AMD64, Docker 29.9.3, Cargo/Rust 1.85.0
- **DEFAULT profile:** RNC bundled `rules/rnc-providers-v1.json`

No scanner source was modified. No Gitleaks or Betterleaks adapter or production
implementation was modified. No corpus truth or scoring formula was changed.

## Corrective summary

| Item | Disposition |
| --- | --- |
| Levain control recognition | **CORRECTED** — RNC detects the control AWS access key and GitHub token; the adapter had failed to map control digests to the expected control values |
| Negative-corpus coverage | **CORRECTED** — RNC execution coverage now proves 117/117 required units inspected; negative corpus scored with 0 findings |
| Negative precision/F1 | **CORRECTED** — precision 100.00%, recall 37.65%, F1 54.70%, with the independent negative oracle intact |
| Ruleset verification | **CORRECTED** — canonical `rnc rules validate` digest checked as well as the rule-file SHA-256 |
| Three unmatched Levain findings | **CLASSIFIED** — broader database-URI capture; not false positives and not counted as true positives |
| Process/result semantics | **VERIFIED — NO CHANGE REQUIRED** |
| Native and Docker builds | **VERIFIED — NO CHANGE REQUIRED** |
| Shared scoring behavior for other adapters | **VERIFIED — NO CHANGE REQUIRED** |
| Git history | **DEFERRED — SCANNER CAPABILITY** |
| Private-report span text for database userinfo | **BLOCKED — EXTERNAL INTERFACE** for byte-span normalization; does not block the negative score |

## Build status

| Product | Build | Execution | Version | Detail |
| --- | --- | --- | --- | --- |
| `windows-amd64` | **PASS** | Native | `0.1.0` | Cargo release build, 75.511 s |
| `docker-linux-amd64` | **PASS** | Docker | `0.1.0` | Adapter source Dockerfile, 86.848 s; `linux/amd64` verified |
| `docker-linux-arm64` | **NOT RUN** | Not assessed | — | Catalogued but not selected for this evaluation |

Native artifact SHA-256:
`f592300589a02767a75b04db79e33687dc2c3eea8edd8f4c8b3b66b87a6ce170`.

Docker image:
`sha256:5c42e2424ed6bd3cef98338bece00d10cf31ebcbe5cff522f03867039a90ebe7`.
Dockerfile SHA-256:
`f23ef4b5237b635c707ad7455eff4c6f2f636f2f2d185a5355e24647c8f4f21f`.

The Docker build uses `rust:1.85-bookworm` and copies only the release `rnc`
binary into `debian:bookworm-slim`; it does not pull a published RNC image. Both
products were built from a disposable checkout at the exact source commit.

## Scanner and ruleset provenance

| Item | Value |
| --- | --- |
| Scanner | RNC Scanner `0.1.0` |
| Source identity | Exact commit, HEAD verified |
| Language/build | Rust workspace; Cargo 1.85.0 / rustc 1.85.0 |
| Rule bundle | `rules/rnc-providers-v1.json` |
| Ruleset ID | `rnc-providers-v1` |
| Ruleset version | `2026.11.2` |
| Rule count | 19 |
| Ruleset schema | `0.2.0` |
| Rule-file SHA-256 | `0d21dfe17107e61292bc6eb2f8ff975021851cc27dcbf627e6eeef05a3bd0eb4` |
| Canonical ruleset digest | `sha256:3ddd1e0aee36ecadb67ee8a2032fbe3a6047803bb56c0d45d65f85851c9b2142` |
| Digest validation | `rnc rules validate --strategy auto` |
| Private report format | `rnc-cp2-output-v1` |

DEFAULT passes the bundled rule bundle explicitly with `--rules` and a
harness-generated empty repository config with `--config`, preventing a
target-local `.rncscanner.toml` from changing detection. CUSTOM accepts an RNC
repository TOML configuration or a JSON rule bundle; the selected path and SHA-256
are recorded by the normal profile. The controlled JSON path was exercised by the
synthetic suite; a separate production CUSTOM repository configuration was not
benchmarked.

## Suite readiness and execution

| Suite | Status | Outcome | Reason |
| --- | --- | --- | --- |
| `synthetic-filesystem` | PASS | COMPLETED_AND_SCORED | Controlled 4-item scanner/adapter/scorer path |
| `levain` | PASS | COMPLETED_AND_SCORED | Positive and negative corpora; coverage and control verified |
| `leaky-repo` filesystem | PASS | COMPLETED_AND_SCORED | Legacy count and rich line truth |
| `leaky-repo` history | NOT_APPLICABLE | NOT_APPLICABLE | No RNC Git-history source mode |
| `git-history` | NOT_APPLICABLE | NOT_APPLICABLE | No RNC Git-history source mode |
| `gitleaks` fixtures | NOT_APPLICABLE | NOT_APPLICABLE | Gitleaks-specific functional fixture |

Evidence:

- [Native report](../../reports/rnc/rnc-corrective-native-5391d8457ea0-default.md)
- [Docker AMD64 report](../../reports/rnc/rnc-corrective-docker-amd64-5391d8457ea0-default.md)
- [Native JSON](../../reports/rnc/rnc-corrective-native-5391d8457ea0-default.json)
- [Docker JSON](../../reports/rnc/rnc-corrective-docker-amd64-5391d8457ea0-default.json)

## Negative-corpus control disposition

The initial pass reported the negative corpus as unscored because the synthetic
control marker was not recognized. That conclusion was **incorrect**. RNC's
bundled provider rules detect two planted control values: the AWS access-key ID
and the GitHub token. The immediate cause was the harness adapter's digest bridge:
it mapped expected values only for scored corpus sections, so control-file
findings arrived with no value and could not witness the scan.

The corrective path is:

1. The bridge also maps the synthetic control values to their SHA-256 evidence
   digests, without adding a production detection rule to RNC.
2. The RNC adapter independently parses the private execution and coverage
   ledger. It verifies every expected generated file is present, required,
   `INSPECTED`, and content-addressed; counts reconcile; no required units are
   uninspected or blocked; execution finalized as `COMPLETED`; no timeout,
   finding limit, candidate limit, read error, or interruption is reported; and
   the ruleset ID and canonical digest match the bundle validated by the scanner.
3. The shared scorer's control requirement is unchanged when no coverage channel
   is supplied. For RNC, a verified coverage channel may substitute for a missing
   structured control detection, with the status
   `COMPLETED_COVERAGE_VERIFIED`. The negative oracle is not replaced: the scorer
   still evaluates every observed negative-corpus finding.

Actual negative-corpus result:

| Item | Result |
| --- | ---: |
| Generated files / required units | 117 |
| `INSPECTED` units | 117 |
| Uninspected units | 0 |
| Verified-blocked units | 0 |
| Corpus sections | 116 |
| Control findings | 2 (AWS access-key ID, GitHub token) |
| Corpus findings | 0 |
| False positives | **0** |
| Coverage | **COMPLETE**, independently verified |
| Result | `ACTIONABLE (3)`, exit 10 |

The control-file findings are excluded from the scored corpus. Zero findings over
116 fully inspected negative sections supports zero false positives. Precision is
therefore justified, not inferred from process completion alone.

## Detection results

### Controlled synthetic filesystem

| Metric | Result |
| --- | ---: |
| Expected credential values | 4 |
| Matched, digest-verified | 4 |
| Precision / recall / F1 | **100.00% / 100.00% / 100.00%** |
| Line-only matches | 0 |
| Unexpected findings | 0 |

This validates the adapter path, private-JSON parsing, unit-to-path mapping, exit
handling, and controlled-rule format. It is not a real-world accuracy claim.

### Levain

| Metric | Result |
| --- | ---: |
| Planted credentials | 85 |
| True positives | 32 |
| False negatives | 53 |
| False positives | 0 |
| Precision | **100.00%** |
| Recall | **37.65%** |
| F1 | **54.70%** |
| Partial matches | 0 |
| Duplicates | 0 |
| Unmatched positive-corpus findings | 3 |
| Control reported | Yes (AWS access-key ID, GitHub token) |
| Coverage verified | Yes, 46/46 positive units and 117/117 negative units |

Formulas: `precision = TP / (TP + FP) = 32/32 = 100.00%`;
`recall = TP / (TP + FN) = 32/85 = 37.65%`;
`F1 = 2 × precision × recall / (precision + recall) = 54.70%`.

The three unmatched findings are **not** false positives and are **not** counted
as true positives. Their classification follows.

## Classification of the three unmatched Levain observations

Independent reconstruction from the relevant source sections shows that RNC's
`database-connection-credential` evidence digest covers the URI's
`username:password` userinfo, while the Levain oracle counts the password token
alone. The ANSI case additionally includes terminal color escapes inside the RNC
span. No raw credential is reproduced here.

| Corpus section | Line | Oracle unit | RNC evidence unit | Classification | Confidence |
| --- | ---: | --- | --- | --- | --- |
| `postgres-connection-failure` | 6 | `url_password` | database userinfo | Rule-family / broader-context disagreement; not FP, not TP | High |
| `ansi-docker-compose-logs` | 3 | `url_password` | ANSI-decorated database userinfo | Rule-family disagreement plus ANSI normalization; not FP, not TP | High |
| `mongodb-uri` | 3 | `url_password` | database userinfo | Rule-family / broader-context disagreement; not FP, not TP | High |

The sections and lines match the expected occurrence, and the expected password
is embedded in the RNC evidence span. The mismatch is the **counting unit and
encoding**, not absence of the credential. Because the private report exposes only
the digest, the adapter cannot emit a password-only normalized value and the
harness does not rewrite the oracle to force a match. These observations remain
unscored and are excluded from both TP and FP counts. No corpus truth was changed.

## Leaky Repo filesystem

| Metric | Result |
| --- | ---: |
| Legacy upstream count units | 175 |
| Legacy count units covered | 33 |
| Legacy count coverage | **18.86%** |
| Rich line-truth expected items | 175 |
| Rich matched items | 32 |
| Rich recall | **18.29%** |
| Files covered | 18 of 44 |
| Value-verified matches | 30 |
| Line-only matches | 2 |
| Rich unexpected findings | 1 |
| Precision / F1 | **Not claimed** |
| History | **NOT_APPLICABLE** |

The legacy count is **LEGACY COUNT COVERAGE**, not verified recall. The rich line
score is independent of the upstream count grouping. Six upstream
risk/informative category conflicts remain preserved; categories were not
rewritten to force a higher score. No negative oracle exists for Leaky filesystem
precision.

## Performance

Five measured runs after warmup, ten copies of the Leaky filesystem target.

| Product | Runtime median | Runtime range | CV | Throughput | CPU median | Peak memory | Stability |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | **0.630 s** | 0.491–0.809 s | 16.16% | 9,346,063.5 B/s | 92.36% | 30,334,976 B | **STABLE** |
| `docker-linux-amd64` | **19.214 s** | 6.865–31.202 s | 45.60% | 306,444.3 B/s | 15.00% | not sampled | **UNSTABLE** |

Docker execution was highly variable on this host; the harness classified the
lane `UNSTABLE` rather than hiding it. Docker peak memory and CPU totals are
unavailable from the existing `docker_stats` sampler. Native/container timings are
not directly comparable. No performance run timed out or failed.

## Missing credential coverage

Levain: **53 missed cases across 45 credential kinds**:

`airtable_pat`, `azure_storage_key`, `bearer_token`, `capability_url_segment`,
`confluent_cloud_key`, `confluent_cloud_secret`, `custom_internal_format`,
`databricks_pat`, `discord_webhook_url`, `doppler_token`,
`dynatrace_api_token`, `elevenlabs_api_key`, `email`, `fireworks_api_key`,
`google_oauth_client_secret`, `grafana_service_account_token`, `groq_api_key`,
`http_basic_auth`, `mailgun_api_key`, `netlify_pat`, `newrelic_user_key`,
`nuget_api_key`, `openai_project_key`, `payment_card`, `perplexity_api_key`,
`pgp_private_key_block`, `pinecone_api_key`, `planetscale_token`,
`postman_api_key`, `private_key_escaped_json`, `private_key_pem`,
`replicate_api_token`, `resend_api_key`, `rubygems_api_key`,
`sentry_org_auth_token`, `shapeless_password`, `slack_webhook_url`,
`sonarqube_token`, `supabase_access_token`, `tailscale_auth_key`,
`terraform_cloud_token`, `url_password`, `vault_service_token`,
`wallet_seed_phrase`, `wrapped_token`.

Leaky Repo: **143 missed rich truth items across 26 files**. RNC's provider
catalogue does not cover many generic passwords, payment data, private-key
formats, webhook URLs, or provider-specific credentials present in that
repository.

## Unsupported capabilities and limitations

1. **Git history is unsupported.** `git-history` and Leaky history remain
   `NOT_APPLICABLE`, not zero-recall. No history capability was implemented.
2. **ARM64 was not evaluated.** The adapter catalogues the platform, but no
   ARM64 build or execution result is claimed.
3. **Database URI span is private.** RNC's private report contains evidence
   digests, not normalized match text. The three database-URI observations cannot
   be converted into password-only findings without changing scanner output or
   weakening independent matching; they remain non-scored.
4. **Docker performance is unstable on this host.** One 31.202 s run and a 45.60%
   CV prevent a stable-speed claim. This is an environment/performance limitation,
   not a detection difference.
5. **Default resource caps.** RNC defaults to 64 MiB total bytes, 8 MiB per file,
   and 10,000 findings. Leaky fits; larger corpora were not evaluated.
6. **No Leaky precision/F1.** The filesystem corpus has no negative oracle.
7. **Host report-path sensitivity.** An exploratory RNC private report under
   `C:\Dev` failed with access denied; the harness temp workspace succeeded. All
   final runs used temporary workspaces. This is documented as a host/path
   limitation, not generalized into a scanner defect.

## Regression and compatibility evidence

- **214 tests passed** after the corrective changes.
- Required RNC cases covered: `CLEAN`, `POLICY_APPLIED`, `ACTIONABLE`,
  `INCOMPLETE`, `FAILED`, missing report, malformed report, missing required
  source unit, invalid configuration, incorrect ruleset, report-publication
  failure, duplicate detection, empty findings with complete coverage, and empty
  findings with incomplete coverage.
- `COVERAGE_UNVERIFIED` is a failure and cannot be scored.
- `COMPLETED_COVERAGE_VERIFIED` is used only when complete inspection is proven
  but the synthetic control value was not extracted.
- Gitleaks and Betterleaks adapters and production code are unchanged. Their
  `assess_findings` path passes no coverage evidence and retains the original
  control requirement.
- Shared scoring formulas are unchanged. The only shared extension is an optional
  coverage-evidence argument and result field; no metric was relaxed.
- Private report isolation, run-owned cleanup, path sanitization, and raw-secret
  non-disclosure remain in force.

## Scanner-development findings

### Database URI capture span

- **Credential category:** database connection URI password.
- **Intended detection behavior:** identify the database credential-bearing URI.
- **Actual observed behavior:** RNC reports `database-connection-credential` over
  `username:password` userinfo (and ANSI escapes where present), not the password
  token alone.
- **Input context:** PostgreSQL/MongoDB connection strings in logs and YAML-like
  output; one ANSI-colored Docker log.
- **Reproduction requirements:** scan a section containing a database URI with a
  password; inspect the private finding's `evidence_digest` and rule ID on the
  matching line. No credential validation or network access.
- **Impact:** three Levain expected-password cases are not counted as TP; they are
  not false positives.
- **Confidence:** high for the span mismatch; no scanner defect is asserted
  because userinfo is a valid credential context.

### Git-history capability

- **Status:** unavailable at the pinned commit.
- **Impact:** Git-history suites are `NOT_APPLICABLE`; no history score is
  produced.
- **Required change:** a separate, authorized scanner integration assignment when
  RNC implements history acquisition.

## Exact commits and reproduction

- **Starting harness commit:** `b48bc0fcf7a0a88082627785ceb68dd229d84323`
- **Corrective harness code commit:** `7b0e669a52b5cf61b024eb13c41fa1689d03e277`
- **Source commit:** `5391d8457ea091c45733920078a7f714ec61f678`

```sh
python -m harness experiment --scanner rnc \
  --repo https://github.com/RNC-Solutions-Group/rnc-security-audit \
  --commit 5391d8457ea091c45733920078a7f714ec61f678 \
  --platforms windows-amd64 --suites all \
  --warmups 3 --runs 5 --copies 10 --offline \
  --out-dir reports/rnc --name rnc-corrective-native

python -m harness experiment --scanner rnc \
  --repo https://github.com/RNC-Solutions-Group/rnc-security-audit \
  --commit 5391d8457ea091c45733920078a7f714ec61f678 \
  --platforms docker-linux-amd64 --suites all \
  --warmups 3 --runs 5 --copies 10 --offline \
  --out-dir reports/rnc --name rnc-corrective-docker-amd64
```

The evidence was generated from harness code commit `7b0e669`; the documentation
commit that adds this report is separate and does not alter the measured code.

**Stop:** Await owner review. No merge is performed by this task.
