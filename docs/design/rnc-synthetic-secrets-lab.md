# RNC Synthetic Secrets Lab — design and rollout

**Status:** Full-scale 1,600-item design approved in principle; implementation pending strict scoring validation.  
**Priority:** After history unknown/unverified accounting and source-truth matching.  
**Placement:** A scanner-neutral, self-contained benchmark alongside Levain and Leaky Repo. Not an upstream Gitleaks fixture suite.  
**Execution and generated corpus:** Local only. No hosted/public secret corpus or external verification endpoints.

## Purpose

Create a reproducible original-content corpus to evaluate RNC Scanner and other adapters using exactly the same independent truth. Preserve the existing `synthetic-filesystem` control (which tests the adapter/scorer transport) as separate from this richer detection lab. Don't evaluate RNC against Gitleaks-specific expected rules or scanner implementation fixtures.

## Suite arrangement

| Suite | Role | Scope |
| --- | --- | --- |
| `synthetic-filesystem` | Small transport/control proof | Existing, unchanged |
| `rnc-secrets-lab` (proposed name) | Rich deterministic positive/negative and tricky credential corpus | New |
| `levain` | Third-party positive/negative corpus | Existing |
| `leaky-repo` | Historical real-world-like filesystem and Git-history source oracle | Existing |
| `gitleaks` | **Legacy Gitleaks-only fixture regression, explicit opt-in** | Preserved for scanner development; removed from shared `all` |

The new lab must **not** claim to contain production secrets or working third-party provider credentials. Provider-specific fixtures should use original, locally generated synthetic values based on publicly documented syntax, with explicit provenance and provider-format version notes. Real cryptographic keys and credentials for disposable **local services** are permitted and encouraged: they must be operationally genuine, scoped to the lab, and impossible to use against production systems.

## Local-only realism contract

**Design principle: synthetic ownership, authentic behavior.** Simulate the underlying security exposure, not merely a regex-looking token. The canonical baseline is fully offline and local; optional disposable validation services bind only to loopback or an isolated Docker network with no external egress.

| Fidelity tier | Description | Evidence required |
| --- | --- | --- |
| **F1 — Format-valid** | Field semantics, realistic provider syntax/length/prefix/checksum when independently known, correct whitespace/escaping/config placement; no real provider account access | Parser/schema validity and exact expected source value |
| **F2 — Cryptographically valid** | Locally generated RSA/Ed25519/EC keys, PKCS#8 and PuTTY containers, signed JWTs, local CA/TLS material; mathematically valid, not just random text | Independent parse, signature/decryption check and key/certificate correlation |
| **F3 — Operationally valid locally** | Functional credentials provisioned into disposable PostgreSQL/Redis/MariaDB/MongoDB/HTTP Basic/local registry or equivalent services | Successful local authentication using the planted credential and an invalid-password rejection control |
| **F4 — Historically authentic** | Full local Git repository with timed source introductions, rotations, copies, moves, deletions, renames, branches and merges | Independently verified Git provenance, value lineage, placement introduction and later persistence |

A single scenario may combine tiers, for example a real locally accepted database password inside a URL, a `.env` file, an obsolete CI log and Git history. This is one distinct credential with multiple **source occurrences**, not automatically multiple unique secrets.

## Corpus and environment isolation

- **Local-only fixture runtime:** Generate corpus data and any verification containers on the developer host. Keep instantiated credentials, private keys, raw scanner reports and working Git histories in explicitly Git-ignored local directories (e.g. `work/synthetic-secrets-lab/`); never commit or push generated secret-bearing artifacts, even though they are synthetic.
- **Recipes can be versioned:** Commit generator source, fixture recipes, schemas, test code and safe reference metadata; keep the instantiated corpus and any sensitive oracle material local. Publish only hashes, source locations, classifications and sanitized summaries.
- **No external service dependence:** The generation/validation stage may authenticate against loopback or an isolated Docker network; scanner runs must not require an Internet connection. Explicitly deny external egress for optional service containers and scanners when feasible. No production API calls or provider-token online validation.
- **Provider realism without provider accounts:** Use accurate provider-like shapes only when grounded in published specifications. Synthetic provider tokens are **structurally valid examples**, not guaranteed to be accepted by real providers. Never use active third-party accounts, personal keys, actual customer data or production identifiers.
- **True local functionality:** Generate local passwords with cryptographic randomness and configure disposable services to require them. Validate successful auth and negative controls before creating the oracle. Use RFC 2606 reserved names (`.test`, `.invalid`) and loopback addresses for non-production network identifiers.
- **Lifecycle hygiene:** Use an isolated lab Compose project, short-lived containers/volumes and a one-command teardown. Enforce loopback port bindings, no public port exposure, cleanup on failed runs, and secret hygiene in console and sanitized output. Run a safeguard that fails if generated files are staged for Git.
- **Reproducible truth:** Record a lab run ID, generation recipe version, corpus content hashes, service-proof status and stable scenario IDs. A regenerated corpus may contain different secure random values, but the scenario structure and matching semantics must be reproducible. Do not hardcode crypto secrets solely for deterministic fixtures.
- **Two-phase operation:** (1) prepare and independently verify the locally generated corpus; (2) scan the frozen corpus offline, without mutating it. Source/oracle verification must not depend on what a scanner detects.

## Realistic scenario families

Build coherent small-project snapshots rather than isolated one-line values. Include realistic innocuous content and adjacent negative metadata in the same files.

| Scenario | Positive / near-positive material | Hard-negative or informative counterpart |
| --- | --- | --- |
| Application configuration | Working local DB credentials in `.env`, Docker Compose, YAML/JSON, PHP, Python and DSNs | DB host, username, schema name, blank/null/placeholder password |
| Developer authentication | Locally valid SSH/private-key material, config key paths, authentic credentials in local registry config and `.netrc` | Public key, certificate, key identifiers, account names, fingerprint-only logs |
| Web/API | Locally signed JWTs, Basic auth, HMAC keys, session secrets, generated OAuth-like local tokens | JWT header/payload without usable signing key, public verification keys, token descriptions |
| Containers/automation | Base64 auth, Kubernetes Secret manifests, CI variables, accidental build/log leaks, local registry login | Base64 nonsecret values, images/tags, hostnames, config checksums |
| Encodings & old clients | True FileZilla `Pass` fields, JetBrains legacy obfuscation, PEM newline variants and wrapped multiline secrets | Arbitrary high entropy, encoded nonsecret material, encrypted-but-unrecoverable browser data |
| Repository history | Live-to-local introduction, duplication, rotation, deletion, rename, history-only secret, convergent branches | Pure rename of existing blob, repeated snapshots, identifier-only changes |
| Adversarial formatting | Escaped quotes, Unicode, CRLF, trailing newline, line continuation, embedded URI password and nested serialized config | Similar-looking paths/fields with non-secret values; malformed encodings |

All positive scenarios need an **explicit owner-approved scope**: a credential can be classified POSITIVE even if its original use was disabled or it was rotated, provided the source artifact exposes genuine secret material. Operational-validity metadata must remain separate from source risk classification.

## Scoring discipline for highly realistic fixtures

- The oracle is produced from independently validated generation evidence **before any scanner output is considered**. It contains source path, line/span, representation type, generated credential identity, unique-group ID, occurrence ID, effective Git introduction, review class and expected normalization.
- For F3 fixtures, store proof that local authentication succeeded and that an invalid control failed; do not store plaintext proof in sanitized reports.
- A scanner that reports a full URI or encoded container needs a **typed, source-attributed transformation** to earn value-verified credential credit; arbitrary substring overlap is not enough.
- Preserve all observed alerts: verified positive, verified negative, informative, duplicate, partial, `UNMATCHED_PENDING_REVIEW` and `UNVERIFIED_EVIDENCE`. A finding absent from the oracle is an investigation item, **not** passively ignored and not automatically false positive.
- Separate **detection quality** from **operational credential validity**. A provider-format synthetic is not a live provider key, whereas a locally working database credential is operationally verified only for that isolated lab.
- Keep **filesystem** and **Git-history** denominators independent. Verify each distinct source placement exactly once; repeated observations from a later snapshot do not create new placements.


## Recommended lab sections

1. **Clear positives:** plaintext passwords, API keys, tokens, PEM/PKCS8 and PPK private keys, authentication-bearing URLs, docker auth, FileZilla Base64 fields, JetBrains legacy obfuscation, and structured configuration.
2. **Difficult positives:** short/default values in genuinely credential-bearing fields, multiline blocks, credentials with punctuation/escaping, duplicate placements, case variations, Unicode, structured parser edge cases, and legitimate long/random secrets with unusual boundaries.
3. **Hard negatives:** identifiers, usernames, hostnames, public keys/certificates, timestamps, misleading entropy, JWT-like examples with no secret credential, OAuth placeholders, null values, and legitimate encoded but nonsecret material.
4. **Informative:** bcrypt/SHA crypt hashes, encrypted password containers, identifiers linked to other source secrets, and high-entropy material without proven secret role.
5. **History lane (later):** introduction, modification, deletion, repeated placement, pure rename, merger/convergent history, and later scanner observations of previously introduced secrets.

## Oracle design

- Immutable manifest and original corpus, pinned version/hash; independent of any scanner's output.
- Every truth row records stable ID, source path, exact location or span, credential category, owner disposition, source/event provenance, value fingerprint(s), normalization policy and unique group.
- Explicit positive, negative, informative, lineage metadata and source-confidence semantics. Historical location is never inferred only from scanner output.
- Normalize only typed, source-attributed encodings. A path/line-only match with uncertain value is **UNVERIFIED**, never an automatic primary TP.
- All scanner alerts, including no-oracle matches, remain in `UNMATCHED_PENDING_REVIEW` with a redacted investigation ledger and explicit adjudication outcomes.
- Primary occurrence and unique-group denominators are separate. Duplicate scans cannot inflate TP; every independent placement is scoreable once.
- Negative examples are **reviewed negatives**, not automatic blanket declarations that all other content is benign. Precision/F1 are not certified with unresolved observations.

## Acceptance gates

- Tests run against a content-hash-verified local corpus; no production/third-party live credentials, no external network dependency, and optional fully isolated local-service authentication proof before scanner execution.
- Section-level expected/found/missed/unknown/verified FP counts reconcile to total observed alerts.
- Intentional tests prove unknown file, wrong location, missing hash, altered hash, partial encoding, duplicate alert, informational artifact, and false-positive source review.
- Native and Docker adapters share one truth and same scoring rules. No scanner-specific truth or scoring exceptions.
- Historical matching tests prove introduction vs persistence, rename and ancestry, and how missing commit attribution becomes not-scoreable rather than false negative.
- Security tests verify no raw secrets enter sanitized reports.

## Migration sequencing

1. **Scoring contract:** Unknown/unverified diagnostics first; strict history oracle and source-lineage resolver next.
2. **Lab corpus and oracle:** Original locally generated, high-fidelity synthetics (including functional disposable local-service credentials), independent validation, full source review and versioned safe manifests. Keep generated secrets and private keys Git-ignored and local.
3. **Lab suite/adapters:** Generic invocation using existing filesystem modes; no detection-rule edits solely to pass the lab.
4. **Regression/reporting:** Compare RNC / Gitleaks / Betterleaks on the same data; retain each scanner's source commit, profile and product platform.

Do not delete the pinned Gitleaks fixtures or their supporting regression tests until explicit sunset approval; they remain useful for maintaining the fork, but are not a neutral benchmark. **Do not start the F3/F4 lab build before the strict scorer and unmatched-investigation reporting pass their acceptance tests.**

## Full-scale RNC Lab v1: 1,600-item benchmark

**Target: 1,600 independently adjudicated source-reference items.** This is not a target of 1,600 scanner alerts: scanner finding counts depend on how each scanner performs. The corpus is a stable, locally generated **endurance benchmark**, deliberately larger and slower than Levain or Leaky Repo. The oracle must be frozen before scanning and independently versioned when changed.

| Oracle class / subcategory | Count | Scoring intent |
| --- | ---: | --- |
| POSITIVE, credential-bearing source occurrences | **800** | Primary occurrence recall; separate unique-group recall |
| NEGATIVE, ordinary nonsecret references | **400** | Verify no unjustified detection; includes contextual neighbors |
| NEGATIVE, adversarial false-positive traps | **200** | Deliberately convincing lookalikes; actual false positives depend on scanner output |
| INFORMATIVE, security-relevant non-primary artifacts | **200** | Report and evaluate separately; not primary TPs |
| **Total** | **1,600** | **800 positive / 600 negative / 200 informative** |

Use the term **FP trap**, not **200 false positives**: a false positive exists only after a scanner fires on a source-adjudicated nonsecret. Cases may include real-looking public identifiers, checksums, certificates/public keys, masked values, hashes, fake credential syntax, Base64 nonsecrets, misleading key names, and high-entropy innocuous data. Informative source material remains distinguishable from known nonsecret references. Any unexpected scanner finding outside the oracle must be queued for investigation, not silently discarded or automatically marked a FP.

### CLI contract and test isolation

| CLI selector | Intended behavior | Automatic inclusion |
| --- | --- | --- |
| `--suites all` | Everyday baseline: **Levain + Leaky Repo** | Only these two |
| `--suites levain` | Levain only | No other suite |
| `--suites leaky-repo` | Leaky Repo filesystem + history when adapter supports it | No other suite |
| `--suites gitleaks` | Gitleaks fixture regressions for upstream/fork-compatible Gitleaks builds | Explicit opt-in; not a neutral benchmark |
| `--suites rnclab` | **Future:** full local RNC Synthetic Secrets Lab, isolated | Exclusive: runs lab only, no Levain or Leaky |
| `--suites synthetic-filesystem` | Existing tiny scanner/adapter transport control | Explicit diagnostic |
| `--suites git-history` | Existing synthetic history control | Explicit diagnostic |

`rnclab` is a proposed suite key and **not implemented or accepted by CLI until its runner and independent oracle are ready**. Selecting it before registration must fail clearly rather than silently running something else. No new CLI shortcut alias is implied; use the existing `--suites` selector. Preserve Gitleaks-specific regression fixtures without including them in `all` or `rnclab`.

### Lab scale and scenario allocation

Within the 800 positives, balance genuine **unique secret identities** and independent repeated/rotated/encoded **occurrences**. Do not multiply a one-line credential by scanning 20 unchanged commits and claim 20 additional expected source occurrences. A suggested planning target is ~500 unique credentials with ~300 additional placements; confirm against independently generated provenance before freezing counts.

Distribute the positive references across multiple languages and realistic systems: source/config files, containers and secrets mounts, local database credentials/dumps, application logs, structured JSON/YAML/TOML/XML/INI, HTTP authentication and local-service API handlers, valid PEM/PKCS8/PPK, signed JWTs, binary artifacts (when technically supportable), and historical commits. Keep category and difficulty strata large enough for meaningful drift trends.

**Coverage families required:**

1. **Archives and compression:** ZIP, TAR, TAR.GZ, TAR.XZ and optional 7z/zstd/bzip2; shallow/nested containers, mixed files, duplicate entries, long internal paths, and archive-contained key blocks. Bound decompression depth, total expanded size, per-file size and compression ratio. Avoid archive bombs and malformed exploit payloads.
2. **Symlinks and filesystem topology:** Valid relative and absolute links **within the lab root**, chains, benign cycles and duplicate targets. Never create or follow a link to a real user/system path. Assert visited-path counts and no runaway recursion. Mark unsupported traversal visibly.
3. **Databases:** SQLite files, SQL text dumps and controlled binary exports (e.g. BSON/RDB) plus optional disposable local PostgreSQL/MariaDB/Redis/MongoDB instances to prove credentials work. Distinguish *scanning database artifacts* from *authenticating to a local database*; do not imply a filesystem scanner provides a database connector.
4. **Real key material:** Locally generated cryptographically valid RSA/Ed25519/EC keys, certificate chains, encrypted and unencrypted key containers, sign/verify proofs, and locally accepted token signatures. No cloud-live credentials.
5. **Build/CI/runtime:** CI logs, dotenv files, Compose/Kubernetes manifests, shell history, local registry auth, dependency metadata, package manager config, build artifacts, app bundles and deployment templates.
6. **Git-history provenance:** 25+ commits, branches, merges, rotations, deletions, repeated placements, same-content renames and later persistence. This lane runs only if Git acquisition exists; unsupported mode is a visible coverage gap, never an invented zero-recall score.
7. **Adversarial source formatting:** Unicode normalization, mixed CRLF/LF, comments, quoting, escaping, extremely long lines, multiline encoded blocks, odd filename characters, harmless nested delimiters and tricky but realistic boundary conditions.
8. **Noise and entropy:** Fake tokens with accurate prefixes but unowned values, real public keys/certs, false friends in adjacent config fields, high-entropy build hashes, UUIDs, sample identities, masked/redacted strings, and seemingly confidential but non-credential artifacts.

The benchmark evaluates **what is seen**, **what is correctly recognized**, **what is not seen**, **what is misclassified**, and **what was never visited**. Archive or binary items not inspected remain a first-class **coverage failure/gap**; they are not silently excluded from headline end-to-end recall. Also report a *supported-feature-only* rate separately, with explicit capability declaration and no implicit denominators.

### Performance and drift contract

Freeze a canonical **1,600-item baseline** for regression across scanners/commits. Generate larger optional stress profiles (e.g., 2×, 5× and 10× file/byte amplification) without changing the meaning of the canonical 1,600-item detection comparison. Performance scenarios should include deep directory trees, diverse file sizes, bounded huge files, large harmless payloads, archive expansion, database snapshots and Git objects.

Report at minimum: elapsed and CPU time, wall-clock warmup and repeated-run distribution (median, p95 where sample size supports it), throughput MB/s and files/s, input bytes vs actually inspected bytes, archive expanded bytes, scanned/eligible/missed files, peak RSS, CPU utilization, disk I/O, exit status, timeouts, resource-limit hits, duplicates, unique and occurrence recall, per-category recall, verified FPs, informative alerts, pending unknowns, and run-to-run drift versus pinned prior scanner builds. Distinguish available measurements from unsupported telemetry. Never invent performance metrics.

Scoring gate: every normalized alert is accounted for in an explicit result or investigation queue. Precision/F1 are **NOT CERTIFIED** with pending unknown/unverified findings or undefined informative-alert policy; no missing category is silently excluded. Report score by category, difficulty, format, archive depth, file type and history mode. Keep all raw evidence local and sanitized outputs free from credential text.

### Operating profile

- **Local-only**, no hosted corpus, no third-party credentials. The lab generator creates and freezes raw materials in Git-ignored working directories.
- Disposable Docker services are loopback-bound or internal-network only, with verified outbound restrictions and one-command cleanup. Local authentication proof and invalid-password controls are recorded as safe attestations.
- The test is intentionally **slow and comprehensive**, not a pre-commit smoke test. Keep fast, everyday feedback in Levain/Leaky and existing synthetic controls.
- Version the recipes, generator, manifests, category distribution and safe run metadata; never commit generated private keys, raw auth credentials, secret-bearing archives or unsanitized reports.
- The new suite must not accept only successful scanner results as coverage; missing files, parser skips, archive traversal unsupported, and incomplete Git histories must be explicitly visible.

**Implementation sequencing:** finish and validate strict scoring/unknown handling first; build the independent local generator and oracle second; implement the `rnclab` runner plus reproducible benchmark/reports third. This design does not claim the runner or 1,600-item corpus already exists.
