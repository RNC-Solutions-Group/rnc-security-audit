"""Pinned comparator assessment on the controlled provider corpus.

Gitleaks is run with its native default configuration against filesystem
fixtures. Findings are reconciled one-to-one against byte-addressed truth by
source path and, where the report provides trustworthy locations, exact source
bytes. Gitleaks rule IDs are mapped to broad credential families only; they are
never assumed to be equivalent to RNC rule IDs.

Reconciliation invariants:

* one observation claims at most one expected occurrence;
* one expected occurrence is claimed by at most one observation;
* repeated identical credentials remain distinct occurrences;
* a token at the wrong byte position or in the wrong file is not a true
  positive;
* a wrong-family or unknown-family observation is never silently accepted;
* duplicate, ambiguous and unscored observations are visible and excluded from
  true-positive counts;
* observation ordering does not change the deterministic result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from tools.cp3.materialize import materialize

ROOT = Path(__file__).resolve().parents[2]

# Broad family compatibility. This is deliberately not a rule-name equality
# table: many Gitleaks rule IDs detect the same RNC family, and unknown rules
# are never credited.
GITLEAKS_FAMILY = {
    "aws-access-token": "aws-credentials",
    "aws-secret-access-key": "aws-credentials",
    "gcp-api-key": "google-cloud-api-key",
    "generic-api-key": "generic",
    "github-app-token": "github-token",
    "github-fine-grained-pat": "github-token",
    "github-oauth": "github-token",
    "github-pat": "github-token",
    "gitlab-pat": "gitlab-pat",
    "jwt": "jwt-bearer",
    "npm-access-token": "npm-token",
    "private-key": "pem-private-key",
    "sendgrid-api-token": "sendgrid-api-key",
    "slack-app-token": "slack-token",
    "slack-bot-token": "slack-token",
    "stripe-access-token": "stripe-secret-key",
}
GENERIC_FAMILY = "generic"
FP_CLASSES = {
    "FALSE_POSITIVE",
    "MISALIGNED_MATCH",
    "WRONG_FAMILY",
    "WRONG_POSITION",
    "WRONG_FILE",
}
NON_TP_CLASSES = FP_CLASSES | {
    "DUPLICATE",
    "AMBIGUOUS_MATCH",
    "UNSCORED",
    "UNSCORED_RULE",
}


def _normalized_path(value: str) -> str:
    result = str(value).replace("\\", "/")
    result = posixpath.normpath(result)
    while result.startswith("./"):
        result = result[2:]
    return result


def _relative(value: str, root: Path) -> str | None:
    path = Path(value)
    if not path.is_absolute():
        normalized = _normalized_path(value)
        if normalized == ".." or normalized.startswith("../"):
            return None
        return normalized
    try:
        return _normalized_path(str(path.resolve().relative_to(root.resolve())))
    except ValueError:
        return None


def _truth_items(truth_path: Path, root: Path) -> list[dict]:
    document = json.loads(truth_path.read_text(encoding="utf-8"))
    result = []
    for item in document["items"]:
        path = _normalized_path(item["path"])
        data = (root / path).read_bytes()
        start = int(item["start_byte"])
        end = int(item["end_byte"])
        token = data[start:end]
        metadata = item.get("metadata") or {}
        result.append(
            {
                "path": path,
                "token": token,
                "start_byte": start,
                "end_byte": end,
                "family": metadata.get("provider_family", ""),
                "rule_id": item.get("expected_rule_id", ""),
                "finding_id": item.get("finding_id", ""),
            }
        )
    return result


def _text_bytes(value: object) -> bytes | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError:
        return None


def _is_redacted(value: bytes | None) -> bool:
    if not value:
        return True
    lowered = value.lower()
    return lowered in {
        b"[redacted]",
        b"redacted",
        b"***",
        b"****",
        b"<redacted>",
        b"<sensitive>",
        b"xxxxxxxx",
    } or b"redacted" in lowered


def _line_starts(data: bytes) -> list[int]:
    starts = [0]
    index = 0
    while index < len(data):
        if data[index] == 13:
            if index + 1 < len(data) and data[index + 1] == 10:
                index += 2
            else:
                index += 1
            starts.append(index)
        elif data[index] == 10:
            index += 1
            starts.append(index)
        else:
            index += 1
    return starts


def _line_feed_indices(data: bytes) -> list[int]:
    return [index for index, byte in enumerate(data) if byte == 10]


def _span_from_location(
    data: bytes,
    start_line: object,
    end_line: object,
    start_column: object,
    end_column: object,
) -> tuple[int, int] | None:
    values = (start_line, end_line, start_column, end_column)
    if not all(isinstance(value, int) and value >= 1 for value in values):
        return None
    assert isinstance(start_line, int)
    assert isinstance(end_line, int)
    assert isinstance(start_column, int)
    assert isinstance(end_column, int)
    if end_line < start_line:
        return None
    newlines = _line_feed_indices(data)
    if start_line > len(newlines) + 1 or end_line > len(newlines) + 1:
        return None
    # Gitleaks computes columns relative to the previous LF byte (0 for the
    # first line), not relative to the first character after that LF. This is
    # its report contract; reconstructing byte offsets must match it exactly.
    start_origin = 0 if start_line == 1 else newlines[start_line - 2]
    end_origin = 0 if end_line == 1 else newlines[end_line - 2]
    start = start_origin + start_column - 1
    end = end_origin + end_column
    if start < 0 or end <= start or end > len(data):
        return None
    return start, end


def _find_all(data: bytes, needle: bytes) -> list[int]:
    result = []
    cursor = 0
    while True:
        found = data.find(needle, cursor)
        if found < 0:
            return result
        result.append(found)
        cursor = found + 1


def _within_span(data: bytes, span: tuple[int, int] | None, needle: bytes) -> tuple[int, int] | None:
    if span is None or not needle:
        return None
    start, end = span
    window = data[start:end]
    offsets = _find_all(window, needle)
    if len(offsets) != 1:
        return None
    found = start + offsets[0]
    return found, found + len(needle)


def _observation(
    item: dict,
    root: Path,
    source_by_path: dict[str, bytes],
) -> dict:
    path = _relative(str(item.get("File", "")), root)
    base = {
        "index": 0,
        "path": path,
        "rule_id": str(item.get("RuleID", "unknown")),
        "fingerprint": str(item.get("Fingerprint", "")),
        "start_line": item.get("StartLine"),
        "end_line": item.get("EndLine"),
        "start_column": item.get("StartColumn"),
        "end_column": item.get("EndColumn"),
        "source_span": None,
        "token_span": None,
        "token": b"",
        "secret": b"",
        "match": b"",
        "tags": list(item.get("Tags") or []),
        "classification": None,
        "reason": "",
        "position_verified": False,
    }
    if path is None:
        base["classification"] = "UNSCORED"
        base["reason"] = "observation path is outside the controlled source root"
        return base
    source = source_by_path.get(path)
    if source is None:
        base["classification"] = "UNSCORED"
        base["reason"] = "observation path does not exist in the controlled source root"
        return base
    base["secret"] = _text_bytes(item.get("Secret")) or b""
    base["match"] = _text_bytes(item.get("Match")) or b""
    base["source_span"] = _span_from_location(
        source,
        base["start_line"],
        base["end_line"],
        base["start_column"],
        base["end_column"],
    )
    secret = base["secret"]
    match = base["match"]
    decoded = any(str(tag).startswith("decoded:") for tag in base["tags"])

    if _is_redacted(secret):
        base["classification"] = "UNSCORED"
        base["reason"] = "report omitted or redacted the secret value"
        return base

    span = base["source_span"]
    if span is not None:
        token_span = _within_span(source, span, secret)
        if token_span is None:
            token_span = _within_span(source, span, match)
        if token_span is None and decoded and source[span[0] : span[1]]:
            # Gitleaks can report a decoded payload whose bytes do not appear
            # in the source. Its line/column still identifies the encoded
            # container, which is the source occurrence being evaluated.
            token_span = span
            while token_span[1] > token_span[0] and source[token_span[1] - 1] in b"\r\n":
                token_span = (token_span[0], token_span[1] - 1)
        if token_span is None:
            base["classification"] = "MISALIGNED_MATCH"
            base["reason"] = "reported secret/match bytes do not occur at the reported source location"
            return base
        base["token_span"] = token_span
        base["token"] = source[token_span[0] : token_span[1]]
        base["position_verified"] = True
        return base

    # Without usable line/column metadata, a unique occurrence in the file is
    # sufficient. Repeated occurrences are ambiguous and are never guessed.
    for candidate in (secret, match):
        if not candidate:
            continue
        offsets = _find_all(source, candidate)
        if len(offsets) == 1:
            start = offsets[0]
            base["token_span"] = (start, start + len(candidate))
            base["token"] = candidate
            base["position_verified"] = True
            return base
        if len(offsets) > 1:
            base["classification"] = "AMBIGUOUS_MATCH"
            base["reason"] = "missing position metadata and the token occurs more than once"
            return base
    base["classification"] = "UNSCORED"
    base["reason"] = "no trustworthy byte position or unique token occurrence"
    return base


def _compatible_family(scanner_family: str, truth_family: str) -> tuple[bool, str]:
    if scanner_family == truth_family:
        return True, "family-exact"
    if scanner_family == GENERIC_FAMILY:
        return True, "generic-fallback"
    if scanner_family == "unknown":
        return False, "unknown-family"
    return False, "wrong-family"


def _build_candidates(
    observations: list[dict],
    truths: list[dict],
    root: Path,
    source_by_path: dict[str, bytes],
) -> tuple[dict[int, list[tuple[int, int, str]]], dict[int, str]]:
    truth_by_path: dict[str, list[int]] = {}
    for index, truth in enumerate(truths):
        truth_by_path.setdefault(truth["path"], []).append(index)
    truth_tokens: dict[bytes, set[str]] = {}
    for truth in truths:
        truth_tokens.setdefault(truth["token"], set()).add(truth["path"])

    edges: dict[int, list[tuple[int, int, str]]] = {}
    terminal: dict[int, str] = {}
    for observed_index, observed in enumerate(observations):
        if observed["classification"] in NON_TP_CLASSES:
            terminal[observed_index] = observed["classification"]
            continue
        path_truth = truth_by_path.get(observed["path"], [])
        if not path_truth:
            if observed["token"] in truth_tokens:
                terminal[observed_index] = "WRONG_FILE"
            else:
                terminal[observed_index] = "FALSE_POSITIVE"
            continue
        span = observed["token_span"]
        exact = [
            truth_index
            for truth_index in path_truth
            if truths[truth_index]["start_byte"] == span[0]
            and truths[truth_index]["end_byte"] == span[1]
        ]
        if len(exact) > 1:
            terminal[observed_index] = "AMBIGUOUS_MATCH"
            continue
        if len(exact) == 1:
            truth_index = exact[0]
            scanner_family = GITLEAKS_FAMILY.get(observed["rule_id"], "unknown")
            compatible, relation = _compatible_family(
                scanner_family, truths[truth_index]["family"]
            )
            if not compatible:
                terminal[observed_index] = (
                    "UNSCORED_RULE" if relation == "unknown-family" else "WRONG_FAMILY"
                )
                continue
            quality = 0 if relation == "family-exact" else 1
            edges.setdefault(observed_index, []).append(
                (quality, truth_index, relation)
            )
            continue

        overlapping = [
            truth_index
            for truth_index in path_truth
            if truths[truth_index]["start_byte"] < span[1]
            and span[0] < truths[truth_index]["end_byte"]
        ]
        if len(overlapping) > 1:
            terminal[observed_index] = "AMBIGUOUS_MATCH"
        elif len(overlapping) == 1:
            terminal[observed_index] = "MISALIGNED_MATCH"
        elif observed["token"] in truth_tokens:
            terminal[observed_index] = "WRONG_POSITION"
        else:
            terminal[observed_index] = "FALSE_POSITIVE"
    return edges, terminal


def _maximum_matching(
    edges: dict[int, list[tuple[int, int, str]]],
) -> tuple[dict[int, int], dict[int, str]]:
    """Deterministic maximum-cardinality bipartite matching.

    Ties are broken by contract quality, then by observation and truth keys.
    The result does not depend on report ordering.
    """
    ordered = {
        observed: sorted(
            candidates,
            key=lambda edge: (edge[0], edge[1]),
        )
        for observed, candidates in edges.items()
    }
    truth_to_observation: dict[int, int] = {}
    relation_by_pair: dict[tuple[int, int], str] = {
        (observed, truth): relation
        for observed, candidates in ordered.items()
        for _quality, truth, relation in candidates
    }

    def visit(observed: int, seen: set[int]) -> bool:
        for _quality, truth, _relation in ordered.get(observed, []):
            if truth in seen:
                continue
            seen.add(truth)
            previous = truth_to_observation.get(truth)
            if previous is None or visit(previous, seen):
                truth_to_observation[truth] = observed
                return True
        return False

    for observed in sorted(ordered):
        visit(observed, set())
    observation_to_truth = {
        observation: truth for truth, observation in truth_to_observation.items()
    }
    relation = {
        observation: relation_by_pair[(observation, truth)]
        for truth, observation in truth_to_observation.items()
    }
    return observation_to_truth, relation


def score_gitleaks(gitleaks: list[dict], truth: list[dict], root: Path) -> dict:
    source_by_path: dict[str, bytes] = {}
    for path in root.rglob("*"):
        if path.is_file():
            relative = _normalized_path(str(path.relative_to(root)))
            source_by_path[relative] = path.read_bytes()
    observations = [
        _observation(item, root, source_by_path) for item in gitleaks
    ]
    for index, observed in enumerate(observations):
        observed["index"] = index

    edges, terminal = _build_candidates(observations, truth, root, source_by_path)
    matched, relations = _maximum_matching(edges)
    matched_truth = set(matched.values())
    matched_keys = {
        (
            observations[observation]["path"] or "",
            observations[observation]["rule_id"],
            observations[observation]["token_span"],
        )
        for observation in matched
    }
    seen_observation_keys: set[tuple[str, str, tuple[int, int] | None]] = set(matched_keys)
    counts = Counter()
    findings = []
    unexpected = []

    for index, observed in enumerate(observations):
        rule_id = observed["rule_id"]
        path = observed["path"]
        span = observed["token_span"]
        scanner_family = GITLEAKS_FAMILY.get(rule_id, "unknown")
        if index in matched:
            truth_index = matched[index]
            expected = truth[truth_index]
            counts["EXPECTED_DETECTION"] += 1
            findings.append(
                {
                    "classification": "EXPECTED_DETECTION",
                    "path": expected["path"],
                    "family": expected["family"],
                    "gitleaks_family": scanner_family,
                    "rule_id": expected["rule_id"],
                    "gitleaks_rule": rule_id,
                    "start_byte": expected["start_byte"],
                    "end_byte": expected["end_byte"],
                    "start_line": observed["start_line"],
                    "family_relation": relations[index],
                    "position_verified": observed["position_verified"],
                }
            )
            continue
        if index in terminal:
            classification = terminal[index]
            reason = observed["reason"] or classification.lower()
        else:
            classification = "FALSE_POSITIVE"
            reason = "no unclaimed truth occurrence at this path and byte position"
        key = (path or "", rule_id, span)
        if (
            classification in {"FALSE_POSITIVE", "WRONG_POSITION", "WRONG_FILE", "MISALIGNED_MATCH"}
            and span is not None
            and key in seen_observation_keys
        ):
            classification = "DUPLICATE"
            reason = "duplicate observation identity or byte span"
        elif span is not None:
            seen_observation_keys.add(key)
        counts[classification] += 1
        entry = {
            "classification": classification,
            "path": path,
            "family": scanner_family,
            "gitleaks_family": scanner_family,
            "rule_id": rule_id,
            "gitleaks_rule": rule_id,
            "start_byte": span[0] if span else None,
            "end_byte": span[1] if span else None,
            "start_line": observed["start_line"],
            "reason": reason,
            "position_verified": observed["position_verified"],
        }
        findings.append(entry)
        if classification != "EXPECTED_DETECTION":
            unexpected.append(entry)

    fn = 0
    missed = []
    for truth_index, expected in enumerate(truth):
        if truth_index in matched_truth:
            continue
        fn += 1
        missed.append(
            {
                "path": expected["path"],
                "rule_id": expected["rule_id"],
                "family": expected["family"],
                "start_byte": expected["start_byte"],
                "end_byte": expected["end_byte"],
                "finding_id": expected["finding_id"],
            }
        )

    by_family: dict[str, dict] = {}
    for expected in truth:
        family = by_family.setdefault(
            expected["family"],
            {"expected": 0, "tp": 0, "fn": 0, "fp": 0},
        )
        family["expected"] += 1
    for truth_index, expected in enumerate(truth):
        family = by_family[expected["family"]]
        if truth_index in matched_truth:
            family["tp"] += 1
        else:
            family["fn"] += 1
    for entry in findings:
        if entry["classification"] in FP_CLASSES:
            family = by_family.setdefault(
                entry.get("family") or "unattributed",
                {"expected": 0, "tp": 0, "fn": 0, "fp": 0},
            )
            family["fp"] += 1

    tp = counts["EXPECTED_DETECTION"]
    fp = sum(counts[name] for name in FP_CLASSES)
    duplicates = counts["DUPLICATE"]
    ambiguous = counts["AMBIGUOUS_MATCH"]
    unscored = counts["UNSCORED"] + counts["UNSCORED_RULE"]
    precision = round(100.0 * tp / (tp + fp), 2) if tp + fp else None
    recall = round(100.0 * tp / (tp + fn), 2) if tp + fn else None
    f1 = (
        round(2 * precision * recall / (precision + recall), 2)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    for family in by_family.values():
        family["precision_percent"] = (
            round(100.0 * family["tp"] / (family["tp"] + family["fp"]), 2)
            if family["tp"] + family["fp"]
            else None
        )
        family["recall_percent"] = (
            round(100.0 * family["tp"] / family["expected"], 2)
            if family["expected"]
            else None
        )
    return {
        "expected": len(truth),
        "observed": len(observations),
        "scored_observations": len(observations) - unscored,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "duplicates": duplicates,
        "ambiguous": ambiguous,
        "unscored": unscored,
        "wrong_family": counts["WRONG_FAMILY"],
        "wrong_position": counts["WRONG_POSITION"],
        "wrong_file": counts["WRONG_FILE"],
        "misaligned": counts["MISALIGNED_MATCH"],
        "false_positive": counts["FALSE_POSITIVE"],
        "precision_percent": precision,
        "recall_percent": recall,
        "f1_percent": f1,
        "by_family": dict(sorted(by_family.items())),
        "unexpected": unexpected,
        "matched": [entry for entry in findings if entry["classification"] == "EXPECTED_DETECTION"],
        "missed": missed,
        "gitleaks_rule_counts": dict(sorted(Counter(item["rule_id"] for item in observations).items())),
        "methodology": {
            "one_to_one": True,
            "position_policy": (
                "line/column bytes are verified against source; repeated values require "
                "trustworthy positions or a unique file occurrence; otherwise ambiguous"
            ),
            "family_policy": (
                "Gitleaks rule IDs map to broad provider families; generic-api-key may "
                "fall back to any exact token, but unknown or wrong families are not credited"
            ),
            "ordering_policy": "deterministic maximum-cardinality matching, sorted by quality and keys",
        },
    }


def run_gitleaks(binary: Path, root: Path, report: Path) -> list[dict]:
    command = [
        str(binary),
        "dir",
        str(root),
        "--report-format",
        "json",
        "--report-path",
        str(report),
        "--redact=0",
        "--exit-code",
        "0",
        "--no-banner",
        "--log-level",
        "error",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=300)
    if completed.returncode != 0:
        raise RuntimeError(
            f"Gitleaks failed ({completed.returncode}): {completed.stderr.strip()[:400]}"
        )
    if not report.is_file():
        return []
    document = json.loads(report.read_text(encoding="utf-8"))
    return document or []


def _rnc_case(integration: dict | None, dataset: str) -> dict | None:
    if not integration:
        return None
    for case in integration.get("cases", []):
        if (
            case.get("dataset") == dataset
            and case.get("mode") == "whole"
            and case.get("strategy") == "regex"
        ):
            return case["metrics"]
    return None


def run(
    gitleaks_binary: Path,
    expected_sha256: str,
    integration_path: Path | None,
) -> dict:
    actual_sha256 = hashlib.sha256(gitleaks_binary.read_bytes()).hexdigest()
    if expected_sha256 and actual_sha256.lower() != expected_sha256.lower():
        raise RuntimeError(
            f"Gitleaks binary hash {actual_sha256} does not match pinned {expected_sha256}"
        )
    integration = (
        json.loads(integration_path.read_text(encoding="utf-8")) if integration_path else None
    )
    cases = []
    with tempfile.TemporaryDirectory(prefix="rnc-cp3-gitleaks-") as temp:
        workspace = Path(temp)
        for name, dataset in (
            ("tier2", "rnc-provider-fixtures-tier2"),
            ("tier3", "rnc-provider-fixtures-tier3-heldout"),
        ):
            root = ROOT / f"tests/fixtures/providers/{name}"
            if not root.is_dir():
                root = materialize(name, workspace / "fixtures")
            truth_path = ROOT / (
                "tests/cp3/provider-truth-tier2.json"
                if name == "tier2"
                else "tests/cp3/provider-truth-tier3-heldout.json"
            )
            report = workspace / f"gitleaks-{name}.json"
            gitleaks = run_gitleaks(gitleaks_binary, root, report)
            truth = _truth_items(truth_path, root)
            scored = score_gitleaks(gitleaks, truth, root)
            scored.update(
                {
                    "dataset": dataset,
                    "root": f"tests/fixtures/providers/{name}",
                    "rnc_reference_metrics": _rnc_case(integration, dataset),
                    "scanner": "gitleaks",
                    "scanner_version": "unavailable (local build metadata did not set a version)",
                    "binary_sha256": actual_sha256,
                    "configuration": "native default configuration; no custom config",
                    "source_type": "filesystem working tree",
                    "git_history_compared": False,
                    "betterleaks_compared": False,
                }
            )
            cases.append(scored)
    return {
        "comparison": "CP3 controlled provider fixtures: RNC vs pinned Gitleaks build",
        "validity": {
            "same_source_type": "filesystem working tree only",
            "same_rules": False,
            "same_native_configuration": False,
            "rnc_ruleset": "rnc-providers-v1",
            "gitleaks_ruleset": "native default configuration",
            "claim": (
                "This is a coverage-and-detection comparison on the same controlled fixtures, "
                "not a general product ranking. Gitleaks supports many families outside the RNC "
                "catalog, and RNC does not implement a Git-history adapter."
            ),
        },
        "gitleaks": {
            "binary": "pinned local Gitleaks build",
            "binary_sha256": actual_sha256,
            "version": "unavailable",
            "report_redaction": "temporary report contained fixture values only; it was deleted after normalization",
        },
        "betterleaks": {
            "executed": False,
            "reason": "no pinned Betterleaks binary or image is available in this environment",
        },
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gitleaks", type=Path, required=True)
    parser.add_argument("--gitleaks-sha256", default="")
    parser.add_argument("--rnc-integration", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = run(args.gitleaks, args.gitleaks_sha256, args.rnc_integration)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
