"""Owner-approved Leaky Repo Git-history source oracle.

The oracle is a source-truth document, not a scanner output.  Loading it is
deliberately strict: counts, owner decisions, lineage policy, blob identities
and source-line evidence are validated before the matcher is allowed to use it.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from .errors import HarnessError
from .util import is_commit_sha, is_sha256, sha256_file


ORACLE_SCHEMA = "rnc-leaky-history-oracle/v1"
ORACLE_STATUS = "OWNER_APPROVED_FINAL"
EXPECTED_COUNTS = {
    "total": 184,
    "POSITIVE": 65,
    "NEGATIVE": 89,
    "INFORMATIVE": 30,
    "LINEAGE_ONLY": 0,
    "positive_occurrences": 65,
    "positive_unique_groups": 53,
    "held": 0,
    "repeat_extra_placements": 12,
    "repeat_placement_groups": 5,
}
OWNER_EXCEPTIONS = {
    "LH-0124": ("NEGATIVE", "NON_SECRET_PLACEHOLDER"),
    "LH-0170": ("INFORMATIVE", "RENAME_LINEAGE"),
}
REPEAT_GROUPS = {"SG-001": 4, "SG-010": 4, "SG-013": 4, "SG-020": 3, "SG-042": 2}
APPROVED_NON_LH_IDS = frozenset({"PNM-001", "PNM-002", "PNJ-001"})
APPROVED_IDS = frozenset(
    {f"LH-{index:04d}" for index in range(1, 182)} | APPROVED_NON_LH_IDS
)
EXACT_VALUE_NEGATIVE_IDS = APPROVED_NON_LH_IDS


class HistoryOracleError(HarnessError):
    """The approved history oracle is missing, malformed, or source-invalid."""


@dataclass(frozen=True)
class HistoryOracle:
    path: Path
    sha256: str
    document: dict
    items: tuple[dict, ...]
    validation: dict

    @property
    def oracle_id(self) -> str:
        return str(self.document["id"])

    @property
    def version(self) -> str:
        return str(self.document["version"])

    @property
    def scope(self) -> dict:
        return dict(self.document["scope"])

    @property
    def counts(self) -> dict:
        return dict(self.document["counts"])

    @property
    def policy(self) -> dict:
        return dict(self.document["policy"])

    @property
    def positives(self) -> tuple[dict, ...]:
        return tuple(item for item in self.items if item["disposition"] == "POSITIVE")

    @property
    def references(self) -> tuple[dict, ...]:
        return tuple(item for item in self.items if item["disposition"] != "POSITIVE")


def _git(source: Path, *args: str, text: bool = True):
    try:
        result = subprocess.run(
            ["git", "-C", str(source), *args],
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HistoryOracleError(f"cannot run git for history oracle validation: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
        raise HistoryOracleError(
            f"git {' '.join(args)} failed: {detail[0][:300] if detail else 'no diagnostic'}"
        )
    return result.stdout.decode("utf-8", "replace") if text else result.stdout


def _batch_blobs(source: Path, specs: list[tuple[str, str]]) -> dict[tuple[str, str], tuple[str, str]]:
    """Read many commit:path objects through one ``git cat-file --batch``.

    A per-file subprocess is prohibitively slow on Windows; the batch form keeps
    oracle validation deterministic without sacrificing source verification.
    """
    if not specs:
        return {}
    request = "".join(f"{commit}:{path}\n" for commit, path in specs).encode("utf-8")
    try:
        result = subprocess.run(
            ["git", "-C", str(source), "cat-file", "--batch"],
            input=request,
            capture_output=True,
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HistoryOracleError(f"git cat-file --batch failed: {exc}") from exc
    if result.returncode != 0:
        raise HistoryOracleError(
            "git cat-file --batch failed: "
            + result.stderr.decode("utf-8", "replace").strip()[:300]
        )
    data = result.stdout
    offset = 0
    output: dict[tuple[str, str], tuple[str, str]] = {}
    for commit, path in specs:
        newline = data.find(b"\n", offset)
        if newline < 0:
            raise HistoryOracleError("truncated git cat-file --batch output")
        header = data[offset:newline].decode("utf-8", "replace")
        offset = newline + 1
        parts = header.split()
        if len(parts) == 2 and parts[1] == "missing":
            output[(commit, path)] = ("", "")
            continue
        if len(parts) != 3 or not parts[2].isdigit():
            raise HistoryOracleError(f"unexpected git cat-file header: {header[:120]}")
        size = int(parts[2])
        content = data[offset : offset + size]
        offset += size + 1
        output[(commit, path)] = (parts[0], content.decode("utf-8", "replace"))
    return output


def _sha_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest_in_line_evidence(text: str, start: int, end: int, digest: str) -> bool:
    """Prove that a safe digest belongs to the reviewed source line/block.

    The search is intentionally limited to a single line or a full credential
    block.  It does not award scanner credit; it only validates the owner's
    source oracle against the pinned Git object.
    """
    lines = text.splitlines(keepends=True)
    if start < 1 or end > len(lines):
        return False
    selected = "".join(lines[start - 1 : end])
    without_newline = selected.rstrip("\r\n")
    stripped = selected.strip()
    candidates = {selected, without_newline, stripped}
    for line in selected.splitlines():
        candidates.add(line)
        candidates.add(line.strip())
        for match in re.finditer(r'"([^"\r\n]*)"', line):
            candidates.add(match.group(1))
        for match in re.finditer(r"'([^'\r\n]*)'", line):
            candidates.add(match.group(1))
        for match in re.finditer(r"[^\s\"'=,<>]+", line):
            candidates.add(match.group(0))
        for match in re.finditer(r"[A-Za-z0-9+/=_-]{16,}", line):
            candidates.add(match.group(0))
    if any(_sha_text(candidate) == digest for candidate in candidates):
        return True
    if len(selected) <= 300:
        # A small number of owner-reviewed values are a literal substring of
        # their labelled line (for example a quoted SMTP password).  Searching
        # that one line proves provenance without using this path for credit.
        for left in range(len(selected)):
            for right in range(left + 1, len(selected) + 1):
                if _sha_text(selected[left:right]) == digest:
                    return True
    return False


def _validate_document(
    document: object,
    *,
    expected_counts: dict | None = None,
    expected_ids: frozenset[str] | set[str] | None = None,
) -> list[str]:
    counts_profile = expected_counts or EXPECTED_COUNTS
    ids_profile = expected_ids or APPROVED_IDS
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["oracle document must be a JSON object"]
    if document.get("schema_version") != ORACLE_SCHEMA:
        errors.append(f"schema_version is {document.get('schema_version')!r}")
    if document.get("status") != ORACLE_STATUS:
        errors.append(f"status is {document.get('status')!r}, expected {ORACLE_STATUS}")
    scope = document.get("scope")
    if not isinstance(scope, dict):
        errors.append("scope must be an object")
    else:
        if not is_commit_sha(str(scope.get("head", ""))):
            errors.append("scope.head is not a full commit SHA")
        if scope.get("reachable_commits") != 25:
            errors.append("scope.reachable_commits is not 25")
        if scope.get("filesystem_truth_is_separate") is not True:
            errors.append("scope.filesystem_truth_is_separate must be true")
    policy = document.get("policy")
    if not isinstance(policy, dict):
        errors.append("policy must be an object")
    else:
        if policy.get("owner_approved") is not True:
            errors.append("policy.owner_approved must be true")
        if policy.get("runtime_history_scoring_wired") is not True:
            errors.append("policy.runtime_history_scoring_wired must be true")
        if policy.get("precision_and_f1") != "NOT_CERTIFIED":
            errors.append("policy.precision_and_f1 must remain NOT_CERTIFIED")
        if policy.get("reviewed_negatives_exhaustive") is not False:
            errors.append("reviewed negatives must not be represented as exhaustive")
        if policy.get("unmatched_findings") != "MANDATORY_INVESTIGATION_NO_SILENT_DISCARD":
            errors.append("unmatched-finding policy is not the owner-approved policy")
        if policy.get("informative") != "Report separately; excluded from primary recall.":
            errors.append("informative policy differs from owner approval")
        if policy.get("occurrences") != (
            "One per introduced or changed credential placement, not per scan snapshot; "
            "pure rename creates none."
        ):
            errors.append("occurrence policy differs from owner approval")
        if policy.get("unique_secrets") != "One per owner-approved source secret group.":
            errors.append("unique-secret policy differs from owner approval")
        if policy.get("verified_false_positive") != (
            "Requires source-adjudicated non-secret identity; unexplained/unmapped "
            "finding stays pending review."
        ):
            errors.append("false-positive policy differs from owner approval")
    items = document.get("items")
    if not isinstance(items, list):
        errors.append("items must be an array")
        return errors
    if len(items) != counts_profile["total"]:
        errors.append(
            f"item count is {len(items)}, expected {counts_profile['total']}"
        )
    ids: set[str] = set()
    dispositions: Counter[str] = Counter()
    groups: dict[str, list[dict]] = defaultdict(list)
    for index, item in enumerate(items):
        where = f"items[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{where} is not an object")
            continue
        item_id = item.get("id")
        if not isinstance(item_id, str) or not (
            re.fullmatch(r"LH-\d{4}", item_id) or item_id in APPROVED_NON_LH_IDS
        ):
            errors.append(f"{where} has an invalid id")
            continue
        if item_id in ids:
            errors.append(f"duplicate item id {item_id}")
        ids.add(item_id)
        disposition = item.get("disposition")
        if disposition not in ("POSITIVE", "NEGATIVE", "INFORMATIVE", "LINEAGE_ONLY"):
            errors.append(f"{item_id} has an invalid disposition")
            continue
        dispositions[disposition] += 1
        category = item.get("category")
        if not isinstance(category, str) or not category:
            errors.append(f"{item_id} has no category")
        source = item.get("source")
        if not isinstance(source, dict):
            errors.append(f"{item_id} has no source object")
            continue
        commit = source.get("observed_commit")
        introduced = source.get("introduced_at")
        if not is_commit_sha(str(commit)) or not is_commit_sha(str(introduced)):
            errors.append(f"{item_id} has an invalid commit identity")
        path = source.get("path")
        if not isinstance(path, str) or not path:
            errors.append(f"{item_id} has no source path")
        if not is_commit_sha(str(source.get("git_blob_sha", ""))):
            errors.append(f"{item_id} has an invalid blob object id")
        start, end = source.get("line_start"), source.get("line_end")
        if not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start:
            errors.append(f"{item_id} has an invalid line range")
        if not isinstance(source.get("change_event"), str):
            errors.append(f"{item_id} has no change event")
        if not isinstance(source.get("evidence_url"), str):
            errors.append(f"{item_id} has no evidence URL")
        identity = item.get("identity")
        if not isinstance(identity, dict):
            errors.append(f"{item_id} has no identity object")
            continue
        digest = identity.get("secret_sha256")
        if digest is not None and not is_sha256(str(digest)):
            errors.append(f"{item_id} has an invalid secret digest")
        group = identity.get("unique_group")
        if disposition == "POSITIVE":
            if not is_sha256(str(digest)):
                errors.append(f"{item_id} positive has no valid secret digest")
            if not isinstance(group, str) or not re.fullmatch(r"SG-\d{3}", group):
                errors.append(f"{item_id} positive has no valid unique group")
            groups[group].append(item)
        scoring = item.get("scoring")
        if not isinstance(scoring, dict):
            errors.append(f"{item_id} has no scoring object")
            continue
        expected = scoring.get("expected_occurrence")
        if disposition == "POSITIVE" and expected is not True:
            errors.append(f"{item_id} positive does not earn occurrence credit")
        if disposition != "POSITIVE" and expected is not False:
            errors.append(f"{item_id} non-positive unexpectedly earns occurrence credit")
        if disposition == "INFORMATIVE" and scoring.get("informative_only") is not True:
            errors.append(f"{item_id} informative lacks informative_only")
        if disposition == "NEGATIVE" and scoring.get("negative_reference") is not True:
            errors.append(f"{item_id} negative lacks negative_reference")
        if scoring.get("lineage_only") and disposition != "INFORMATIVE":
            errors.append(f"{item_id} lineage-only item must be informative")
        review_status = item.get("review", {}).get("status")
        if review_status != ORACLE_STATUS:
            errors.append(f"{item_id} lacks owner approval")
        if item_id in EXACT_VALUE_NEGATIVE_IDS:
            if digest is None:
                errors.append(f"{item_id} exact negative has no secret digest")
            if disposition != "NEGATIVE":
                errors.append(f"{item_id} exact negative is not a negative record")
    if ids != ids_profile:
        missing = sorted(ids_profile - ids)
        extra = sorted(ids - ids_profile)
        errors.append(
            f"item IDs do not match the expected profile (missing={missing[:5]}, extra={extra[:5]})"
        )
    expected_dispositions = Counter(
        {
            "POSITIVE": counts_profile["POSITIVE"],
            "NEGATIVE": counts_profile["NEGATIVE"],
            "INFORMATIVE": counts_profile["INFORMATIVE"],
        }
    )
    if dispositions != expected_dispositions:
        errors.append(f"disposition totals are {dict(dispositions)}")
    if len(groups) != counts_profile["positive_unique_groups"]:
        errors.append(
            f"unique positive groups are {len(groups)}, expected {counts_profile['positive_unique_groups']}"
        )
    repeats = {group: len(items) for group, items in groups.items() if len(items) > 1}
    if repeats != REPEAT_GROUPS:
        errors.append(f"repeat-placement groups are {repeats}, expected {REPEAT_GROUPS}")
    for item_id, (disposition, category) in OWNER_EXCEPTIONS.items():
        item = next((value for value in items if value.get("id") == item_id), None)
        if item is None:
            errors.append(f"owner exception {item_id} is absent")
            continue
        if item.get("disposition") != disposition:
            errors.append(f"{item_id} disposition is {item.get('disposition')!r}, expected {disposition}")
        if item.get("category") != category:
            errors.append(f"{item_id} category is {item.get('category')!r}, expected {category}")
        if item_id == "LH-0170" and not (item.get("scoring") or {}).get("lineage_only"):
            errors.append("LH-0170 must retain lineage_only")
    counts = document.get("counts")
    if not isinstance(counts, dict):
        errors.append("counts must be an object")
    else:
        for key, expected in counts_profile.items():
            if counts.get(key) != expected:
                errors.append(f"counts.{key} is {counts.get(key)!r}, expected {expected}")
    return errors


def load(
    path: Path | str,
    *,
    expected_sha256: str | None = None,
    source_root: Path | str | None = None,
    scope_path: Path | str | None = None,
) -> HistoryOracle:
    oracle_path = Path(path)
    if not oracle_path.is_file():
        raise HistoryOracleError(f"history oracle is missing: {oracle_path}")
    digest = sha256_file(oracle_path)
    if expected_sha256 is not None and digest != expected_sha256:
        raise HistoryOracleError(
            f"history oracle SHA-256 is {digest}, expected {expected_sha256}"
        )
    try:
        document = json.loads(oracle_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HistoryOracleError(f"cannot read history oracle: {exc}") from exc
    errors = _validate_document(document)
    if errors:
        raise HistoryOracleError("history oracle validation failed: " + "; ".join(errors[:12]))
    items = tuple(document["items"])
    validation = {
        "status": "PASS",
        "oracle_sha256": digest,
        "item_count": len(items),
        "counts": dict(document["counts"]),
        "owner_exceptions": {
            key: {"disposition": value[0], "category": value[1]}
            for key, value in OWNER_EXCEPTIONS.items()
        },
        "source_validation": None,
    }
    oracle = HistoryOracle(
        path=oracle_path.resolve(),
        sha256=digest,
        document=document,
        items=items,
        validation=validation,
    )
    if source_root is not None:
        source_validation = validate_source(oracle, Path(source_root), scope_path=scope_path)
        oracle.validation["source_validation"] = source_validation
        if source_validation["status"] != "PASS":
            raise HistoryOracleError(
                "history oracle source validation failed: "
                + "; ".join(source_validation["errors"][:12])
            )
    return oracle


def validate_scope(
    oracle: HistoryOracle,
    scope_path: Path | str,
) -> tuple[dict, list[str]]:
    path = Path(scope_path)
    errors: list[str] = []
    if not path.is_file():
        return {}, [f"history scope manifest is missing: {path}"]
    try:
        scope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {}, [f"cannot read history scope manifest: {exc}"]
    if scope.get("head") != oracle.scope.get("head"):
        errors.append("history scope HEAD differs from the oracle HEAD")
    if scope.get("commit_count") != oracle.scope.get("reachable_commits"):
        errors.append("history scope commit count differs from the oracle")
    renames = scope.get("renames")
    if not isinstance(renames, list):
        errors.append("history scope renames must be an array")
    else:
        for rename in renames:
            if not isinstance(rename, dict) or not all(
                isinstance(rename.get(key), str) and rename.get(key)
                for key in ("commit", "from", "to")
            ):
                errors.append("history scope contains an invalid rename")
    return scope, errors


def validate_source(
    oracle: HistoryOracle,
    source_root: Path | str,
    *,
    scope_path: Path | str | None = None,
) -> dict:
    source = Path(source_root)
    errors: list[str] = []
    details: dict = {
        "status": "PASS",
        "source": str(source),
        "head": None,
        "expected_head": oracle.scope.get("head"),
        "commit_count": None,
        "expected_commit_count": oracle.scope.get("reachable_commits"),
        "checked_items": 0,
        "checked_blobs": 0,
        "scope": None,
        "errors": [],
    }
    try:
        root = _git(source, "rev-parse", "--show-toplevel").strip()
        head = _git(source, "rev-parse", "HEAD").strip()
        status = _git(source, "status", "--porcelain").strip()
        count = int(_git(source, "rev-list", "--count", "HEAD").strip())
    except (HistoryOracleError, ValueError) as exc:
        details.update(status="BLOCKED", errors=[str(exc)])
        details["errors"] = [str(exc)]
        return details
    details.update(root=root, head=head, commit_count=count)
    if head != oracle.scope.get("head"):
        errors.append(f"source HEAD is {head}, expected {oracle.scope.get('head')}")
    if count != oracle.scope.get("reachable_commits"):
        errors.append(f"source has {count} reachable commits, expected 25")
    if status:
        errors.append("source working tree is not clean")
    if scope_path is not None:
        scope, scope_errors = validate_scope(oracle, scope_path)
        details["scope"] = scope or None
        errors.extend(scope_errors)
    specs = sorted(
        {
            (item["source"]["observed_commit"], item["source"]["path"])
            for item in oracle.items
        }
    )
    try:
        blobs = _batch_blobs(source, specs)
    except HistoryOracleError as exc:
        details["status"] = "BLOCKED"
        details["errors"] = errors + [str(exc)]
        return details
    for item in oracle.items:
        source_item = item["source"]
        commit = source_item["observed_commit"]
        path = source_item["path"]
        blob_sha, text = blobs.get((commit, path), ("", ""))
        if not blob_sha:
            errors.append(f"{item['id']} source object is unavailable")
            continue
        details["checked_items"] += 1
        if blob_sha != source_item["git_blob_sha"]:
            errors.append(f"{item['id']} blob SHA differs from the pinned Git object")
            continue
        details["checked_blobs"] += 1
        lines = text.splitlines()
        start, end = source_item["line_start"], source_item["line_end"]
        if start < 1 or end > len(lines):
            errors.append(f"{item['id']} line range is outside the pinned blob")
            continue
        digest = (item.get("identity") or {}).get("secret_sha256")
        if digest and not _digest_in_line_evidence(text, start, end, digest):
            errors.append(f"{item['id']} secret digest is not evidenced by its source lines")
    details["errors"] = errors
    details["status"] = "PASS" if not errors else "FAIL"
    return details


def oracle_summary(oracle: HistoryOracle) -> dict:
    return {
        "oracle_id": oracle.oracle_id,
        "oracle_version": oracle.version,
        "oracle_sha256": oracle.sha256,
        "status": oracle.document.get("status"),
        "scope": oracle.scope,
        "counts": oracle.counts,
        "precision_and_f1": oracle.policy.get("precision_and_f1"),
        "reviewed_negatives_exhaustive": oracle.policy.get("reviewed_negatives_exhaustive"),
        "source_validation": oracle.validation.get("source_validation"),
    }
