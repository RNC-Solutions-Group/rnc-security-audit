"""CP3 end-to-end provider-catalog integration and byte-accuracy evidence.

Runs the actual Rust CLI, validates CP0 v0.2 records, scores exact byte spans
with the independent scorer, writes external-harness handoffs, and checks that
all supported matching strategies and acquisition modes agree.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator

from tools.cp0.contracts import schema_registry, validate_records
from tools.cp3.adapter import build_handoff
from tools.cp3.materialize import materialize
from tools.cp3.score import score_files

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "rules/rnc-providers-v1.json"


def _run_cli(
    binary: Path,
    source_root: Path,
    output: Path,
    mode: str,
    strategy: str,
    run_id: str,
) -> tuple[dict, str]:
    command = [
        str(binary),
        "scan",
        "--root",
        str(source_root),
        "--rules",
        str(RULES),
        "--format",
        "json",
        "--output",
        str(output),
        "--run-id",
        run_id,
        "--mode",
        mode,
        "--strategy",
        strategy,
        "--stream-chunk-bytes",
        "64",
        "--accept-result",
        "3",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=180)
    if completed.returncode != 0:
        raise RuntimeError(
            f"CLI failed for {mode}/{strategy} ({completed.returncode}): "
            f"{completed.stderr.strip()[:500]}"
        )
    document = json.loads(output.read_text(encoding="utf-8"))
    return document, completed.stdout


def _contents_by_unit(document: dict, source_root: Path) -> dict[str, bytes]:
    contents = {}
    for unit in document["execution"]["units"]:
        if unit["disposition"] == "INSPECTED":
            contents[unit["unit_id"]] = (source_root / unit["locator"]).read_bytes()
    return contents


def _validate(document: dict, source_root: Path) -> None:
    schemas, registry = schema_registry()
    for name, value in (
        ("execution.schema.json", document["execution"]),
        ("policy.schema.json", document["policy"]),
        ("result.schema.json", document["result"]),
        ("ci-decision.schema.json", document["ci"]),
    ):
        Draft202012Validator(schemas[name], registry=registry).validate(value)
    for unit in document["execution"]["units"]:
        Draft202012Validator(schemas["source-unit.schema.json"], registry=registry).validate(unit)
    for finding in document["findings"]:
        Draft202012Validator(schemas["finding.schema.json"], registry=registry).validate(finding)
    validate_records(
        document["execution"],
        document["findings"],
        document["policy"],
        document["result"],
        document["ci"],
        contents=_contents_by_unit(document, source_root),
    )


def _raw_tokens(document: dict, source_root: Path) -> set[bytes]:
    tokens = set()
    for item in document["items"]:
        data = (source_root / item["path"]).read_bytes()
        tokens.add(data[item["start_byte"] : item["end_byte"]])
    return tokens


def _summary(document: dict) -> tuple:
    units = {unit["unit_id"]: unit["locator"] for unit in document["execution"]["units"]}
    return tuple(
        sorted(
            (
                units[finding["unit_id"]],
                finding["rule_id"],
                finding["start_byte"],
                finding["end_byte"],
                finding["evidence_digest"],
                finding["finding_id"],
                finding["confidence"],
                tuple(finding["validation"]),
            )
            for finding in document["findings"]
        )
    )


def run_case(
    binary: Path,
    dataset_root: Path,
    truth_path: Path,
    mode: str,
    strategy: str,
    handoff_dir: Path | None = None,
) -> dict:
    truth_document = json.loads(truth_path.read_text(encoding="utf-8"))
    rules_document = json.loads(RULES.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="rnc-cp3-integration-") as temp:
        root = Path(temp)
        output = root / "findings.json"
        run_id = f"cp3-{dataset_root.name}-{mode}-{strategy}"
        document, stdout = _run_cli(binary, dataset_root, output, mode, strategy, run_id)
        _validate(document, dataset_root)
        if document["result"]["result_code"] != 3:
            raise AssertionError(f"{mode}/{strategy}: expected ACTIONABLE, got {document['result']}")
        if document["ci"]["process_exit_code"] != 0:
            raise AssertionError(f"{mode}/{strategy}: accepted ACTIONABLE did not exit 0")
        for token in _raw_tokens(truth_document, dataset_root):
            if token in stdout.encode("utf-8"):
                raise AssertionError(f"{mode}/{strategy}: summary leaked a fixture value")
            if token in output.read_bytes():
                raise AssertionError(f"{mode}/{strategy}: private report leaked a fixture value")
        score = score_files(
            output,
            truth_path,
            RULES,
            dataset_root,
            backend=strategy,
            mode=mode,
            platform="integration",
        )
        metrics = score["metrics"]
        if score["scoring_status"] != "COMPLETED":
            raise AssertionError(f"{mode}/{strategy}: scoring status {score['scoring_status']}")
        if metrics["tp"] != metrics["expected_count"] or metrics["fp"] or metrics["fn"]:
            raise AssertionError(f"{mode}/{strategy}: accuracy mismatch {metrics}")
        if metrics["duplicates"] or metrics["ambiguous"]:
            raise AssertionError(f"{mode}/{strategy}: duplicate/ambiguous observations")
        handoff = None
        if handoff_dir is not None:
            handoff = build_handoff(document, truth_document, rules_document)
            handoff_dir.mkdir(parents=True, exist_ok=True)
            destination = handoff_dir / f"{dataset_root.name}-{mode}-{strategy}.json"
            destination.write_text(
                json.dumps(handoff, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        return {
            "dataset": truth_document["dataset_id"],
            "mode": mode,
            "strategy": strategy,
            "effective_strategy": document["execution_plan"]["effective"],
            "run_id": run_id,
            "exit_code": 0,
            "result_code": document["result"]["result_code"],
            "findings": len(document["findings"]),
            "metrics": {
                key: metrics[key]
                for key in (
                    "expected_count",
                    "observed_count",
                    "tp",
                    "fp",
                    "fn",
                    "precision_percent",
                    "recall_percent",
                    "f1_percent",
                    "duplicates",
                    "ambiguous",
                    "required_coverage_percent",
                )
            },
            "score": score,
            "summary": _summary(document),
            "handoff": handoff,
            "ruleset_digest": document["execution"]["ruleset_digest"],
        }


def run(binary: Path, handoff_dir: Path | None = None) -> dict:
    cases = []
    with tempfile.TemporaryDirectory(prefix="rnc-cp3-fixtures-") as fixture_temp:
        tier2 = materialize("tier2", Path(fixture_temp))
        tier3 = materialize("tier3", Path(fixture_temp))
        for dataset_root, truth_path in (
            (tier2, ROOT / "tests/cp3/provider-truth-tier2.json"),
            (tier3, ROOT / "tests/cp3/provider-truth-tier3-heldout.json"),
        ):
            for mode in ("whole", "stream"):
                for strategy in ("regex", "regexset", "prefilter", "auto"):
                    cases.append(
                        run_case(binary, dataset_root, truth_path, mode, strategy, handoff_dir)
                    )
    baseline = cases[0]["summary"]
    equivalent = all(case["summary"] == baseline for case in cases[:8])
    tier3_equivalent = all(case["summary"] == cases[8]["summary"] for case in cases[8:])
    if not equivalent or not tier3_equivalent:
        raise AssertionError("provider findings differ across modes or matching strategies")
    return {
        "integration": "CP3 provider catalog, byte truth and matching strategies",
        "cases": [
            {
                key: value
                for key, value in case.items()
                if key not in {"score", "summary", "handoff"}
            }
            for case in cases
        ],
        "all_correct": all(
            case["metrics"]["tp"] == case["metrics"]["expected_count"]
            and case["metrics"]["fp"] == 0
            and case["metrics"]["fn"] == 0
            for case in cases
        ),
        "backend_equivalent": equivalent and tier3_equivalent,
        "external_corpora_executed": False,
        "scanner_accuracy_claim": (
            "Independent controlled provider-format fixtures only; not a real-world corpus claim."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--handoff-dir", type=Path)
    args = parser.parse_args()
    document = run(args.binary, args.handoff_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0 if document["all_correct"] and document["backend_equivalent"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
