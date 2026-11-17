"""CP2 integrated strategy differential and independent truth check.

Runs the actual CLI with every portable matching strategy, validates the three
v0.2 ledgers, compares canonical findings against independent synthetic truth,
and requires byte-for-byte logical equivalence across strategies.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator

from tools.cp0.contracts import schema_registry, validate_records
from tools.cp0.corpus import load_v0, load_v1, validate_manifest
from tools.cp0.harness_adapter import build_handoff
from tools.cp1.integration_check import _compare_truth, _stage
from tools.cp1.rules import canonical_digest as rules_digest, load as load_rules
from tools.cp2.common import stable_findings, units_without_private_plan


ROOT = Path(__file__).resolve().parents[2]
RULES_V0 = ROOT / "rules/rnc-synthetic-v0.json"
RULES_V1 = ROOT / "rules/rnc-synthetic-v1.json"
STRATEGIES = ("regex", "regexset", "prefilter", "auto")


def _run(binary: Path, stage: Path, rules: Path, output: Path, corpus: str, mode: str, strategy: str) -> tuple[dict, str, int]:
    excludes = ["blocked.txt"] if corpus in {"v0", "v1"} else []
    skips = ["uninspected-optional.txt"] if corpus == "v1" else []
    optional = ["uninspected-optional.txt", "optional-clean.txt"] if corpus == "v1" else []
    command = [
        str(binary), "scan",
        "--root", str(stage),
        "--rules", str(rules),
        "--format", "private",
        "--output", str(output),
        "--run-id", f"cp2-{corpus}-{mode}-{strategy}",
        "--mode", mode,
        "--strategy", strategy,
        "--stream-chunk-bytes", "64",
    ]
    for selector in excludes:
        command.extend(["--exclude", selector])
    for selector in skips:
        command.extend(["--skip", selector])
    for selector in optional:
        command.extend(["--optional", selector])
    completed = subprocess.run(command, capture_output=True, text=True, timeout=180)
    if completed.returncode not in (0, 10, 20):
        raise RuntimeError(f"{corpus}/{mode}/{strategy}: CLI exit {completed.returncode}: {completed.stderr.strip()}")
    document = json.loads(output.read_text(encoding="utf-8"))
    return document, completed.stdout, completed.returncode


def _validate(document: dict, loaded: dict, contents: dict[str, bytes], label: str) -> dict:
    schemas, registry = schema_registry()
    execution = document["execution"]
    findings = document["findings"]
    policy = document["policy"]
    result = document["result"]
    ci = document["ci"]
    for name, value in (
        ("execution.schema.json", execution),
        ("policy.schema.json", policy),
        ("result.schema.json", result),
        ("ci-decision.schema.json", ci),
    ):
        Draft202012Validator(schemas[name], registry=registry).validate(value)
    for unit in execution["units"]:
        Draft202012Validator(schemas["source-unit.schema.json"], registry=registry).validate(unit)
    for finding in findings:
        Draft202012Validator(schemas["finding.schema.json"], registry=registry).validate(finding)
    content_by_unit = {
        unit["unit_id"]: contents[
            next(target["id"] for target in loaded["targets"] if target["path"] == unit["locator"])
        ]
        for unit in execution["units"]
        if unit["disposition"] == "INSPECTED"
    }
    validate_records(execution, findings, policy, result, ci, contents=content_by_unit)
    return {
        "result_code": result["result_code"],
        "coverage": result["coverage"],
        "ci_exit": ci["process_exit_code"],
        "plan": document.get("execution_plan", {}),
        "findings": stable_findings(execution, findings),
        "units": units_without_private_plan(execution),
    }


def run_case(binary: Path, corpus: str, mode: str, strategy: str, handoff_dir: Path | None = None) -> dict:
    loaded = load_v0() if corpus == "v0" else load_v1()
    rules = RULES_V0 if corpus == "v0" else RULES_V1
    with tempfile.TemporaryDirectory(prefix=f"rnc-cp2-{corpus}-{mode}-{strategy}-") as temp:
        root = Path(temp)
        stage = root / "stage"
        stage.mkdir()
        contents = _stage(loaded, stage)
        output = root / "evidence.json"
        document, stdout, exit_code = _run(binary, stage, rules, output, corpus, mode, strategy)
        if document["execution"]["ruleset_digest"] != rules_digest(load_rules(rules)):
            raise AssertionError("ruleset digest mismatch")
        if "RNC_SYNTH_KEY_" in stdout or "evidence_digest" in stdout or "finding_id" in stdout:
            raise AssertionError("summary leaked sensitive evidence")
        observed = _validate(document, loaded, contents, f"{corpus}/{mode}/{strategy}")
        metrics = _compare_truth(loaded, document, contents, corpus)
        if observed["ci_exit"] != exit_code:
            raise AssertionError("CI exit does not match process exit")
        if observed["result_code"] != 3:
            raise AssertionError(f"expected ACTIONABLE, got {observed['result_code']}")
        if handoff_dir is not None:
            handoff_dir.mkdir(parents=True, exist_ok=True)
            handoff = build_handoff({
                "adapter": "rnc-cli",
                "mode": mode,
                "execution": document["execution"],
                "findings": document["findings"],
                "policy": document["policy"],
                "result": document["result"],
                "ci": document["ci"],
            }, loaded)
            (handoff_dir / f"{corpus}-{mode}-{strategy}.json").write_text(
                json.dumps(handoff, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
            )
        return {
            "corpus": corpus,
            "mode": mode,
            "strategy": strategy,
            "exit_code": exit_code,
            "metrics": metrics,
            "result_code": observed["result_code"],
            "coverage": observed["coverage"],
            "ci_exit": observed["ci_exit"],
            "plan": observed["plan"],
            "findings": observed["findings"],
            "units": observed["units"],
        }


def run_edge(binary: Path, edge_root: Path, strategy: str) -> dict:
    loaded = validate_manifest(edge_root / "manifest.json")
    with tempfile.TemporaryDirectory(prefix=f"rnc-cp2-edge-{strategy}-") as temp:
        root = Path(temp)
        stage = root / "stage"
        stage.mkdir()
        for target in loaded["targets"]:
            destination = stage / target["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(edge_root / target["path"], destination)
        output = root / "evidence.json"
        document, stdout, exit_code = _run(binary, stage, RULES_V1, output, "edge", "stream", strategy)
        observed = _validate(document, loaded, loaded["contents"], f"edge/{strategy}")
        metrics = _compare_truth(loaded, document, loaded["contents"], "edge")
        if observed["result_code"] != 4 or observed["ci_exit"] != 20:
            raise AssertionError(f"edge: expected INCOMPLETE/20, got {observed['result_code']}/{observed['ci_exit']}")
        return {
            "corpus": "edge",
            "mode": "stream",
            "strategy": strategy,
            "exit_code": exit_code,
            "metrics": metrics,
            "result_code": observed["result_code"],
            "coverage": observed["coverage"],
            "ci_exit": observed["ci_exit"],
            "plan": observed["plan"],
            "findings": observed["findings"],
            "units": observed["units"],
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--edge-corpus", type=Path)
    parser.add_argument("--handoff-dir", type=Path)
    args = parser.parse_args()
    cases = []
    for corpus in ("v1", "v0"):
        for mode in ("whole", "stream"):
            for strategy in STRATEGIES:
                cases.append(run_case(args.binary, corpus, mode, strategy, args.handoff_dir))
    if args.edge_corpus:
        for strategy in STRATEGIES:
            cases.append(run_edge(args.binary, args.edge_corpus, strategy))

    by_key: dict[tuple[str, str], list[dict]] = {}
    for case in cases:
        by_key.setdefault((case["corpus"], case["mode"]), []).append(case)
    equivalence = []
    for (corpus, mode), group in sorted(by_key.items()):
        baseline = next(case for case in group if case["strategy"] == "regex")
        for case in group:
            same_findings = case["findings"] == baseline["findings"]
            same_units = case["units"] == baseline["units"]
            equivalence.append({
                "corpus": corpus,
                "mode": mode,
                "strategy": case["strategy"],
                "same_findings": same_findings,
                "same_units": same_units,
                "same_result": case["result_code"] == baseline["result_code"],
                "same_ci": case["ci_exit"] == baseline["ci_exit"],
            })
            if not (same_findings and same_units and case["result_code"] == baseline["result_code"] and case["ci_exit"] == baseline["ci_exit"]):
                raise AssertionError(f"backend equivalence failed: {corpus}/{mode}/{case['strategy']}")

    public_cases = [
        {key: value for key, value in case.items() if key not in {"findings", "units"}}
        for case in cases
    ]
    document = {
        "integration": "CP2 multi-strategy integration vs CP0 independent truth",
        "scanner_accuracy_claim": False,
        "external_corpora_executed": False,
        "strategies": list(STRATEGIES),
        "cases": public_cases,
        "equivalence": equivalence,
        "all_correct": all(case["metrics"]["expected"] == case["metrics"]["actual"] for case in cases),
        "all_equivalent": all(item["same_findings"] and item["same_units"] and item["same_result"] and item["same_ci"] for item in equivalence),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({k: document[k] for k in ("integration", "all_correct", "all_equivalent", "strategies")}, indent=2))
    if not document["all_correct"] or not document["all_equivalent"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
