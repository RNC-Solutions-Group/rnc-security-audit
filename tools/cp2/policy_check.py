"""CP2 configuration, pre-scan policy, exemption and classification checks."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "rules/rnc-synthetic-v1.json"


def _write(path: Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8", newline="\n")
    else:
        path.write_bytes(data)


def _config(directory: Path, name: str, text: str) -> Path:
    path = directory / name
    _write(path, text)
    return path


def _run(binary: Path, root: Path, *, config: Path | None = None, global_config: Path | None = None, args: list[str] | None = None, output: Path | None = None, run_id: str = "cp2-policy") -> tuple[subprocess.CompletedProcess, dict | None, Path]:
    output = output or root.parent / f"{run_id}.json"
    command = [
        str(binary), "scan", "--root", str(root), "--rules", str(RULES),
        "--format", "private", "--output", str(output), "--run-id", run_id,
    ]
    if config is not None:
        command.extend(["--config", str(config)])
    if global_config is not None:
        command.extend(["--global-config", str(global_config)])
    command.extend(args or [])
    completed = subprocess.run(command, capture_output=True, text=True, timeout=120)
    document = json.loads(output.read_text(encoding="utf-8")) if output.exists() else None
    return completed, document, output


def _base(root: Path) -> None:
    _write(root / "clean.txt", "benign\n")


def _findings_without_run(document: dict) -> list[dict]:
    return [{k: v for k, v in finding.items() if k != "run_id"} for finding in document["findings"]]


def run(binary: Path) -> dict:
    cases = []
    with tempfile.TemporaryDirectory(prefix="rnc-cp2-policy-") as temp:
        base = Path(temp)

        # 1. Clean completed scan.
        root = base / "clean"
        _base(root)
        completed, doc, _ = _run(binary, root, run_id="clean")
        assert completed.returncode == 0 and doc["result"]["result_code"] == 1
        cases.append({"case": "clean", "exit": completed.returncode, "result": 1})

        # 2. Verified block without reading content. The marker in the blocked
        # file would be detected if the adapter opened it.
        root = base / "block"
        _write(root / "secrets/a.txt", "RNC_SYNTH_KEY_GENERIC_BLOCKED_ALPHA\n")
        _base(root)
        config = _config(
            base,
            "block.toml",
            'schema_version = "0.2.0"\n[policy]\n[[policy.blocks]]\npolicy_id = "REPO-BLOCK"\nselector = "secrets/**"\nreason = "test"\n',
        )
        completed, doc, _ = _run(binary, root, config=config, run_id="block")
        assert completed.returncode == 0 and doc["result"]["result_code"] == 2
        blocked = next(unit for unit in doc["execution"]["units"] if unit["locator"] == "secrets/a.txt")
        assert blocked["disposition"] == "VERIFIED_BLOCKED" and "content_sha256" not in blocked
        assert doc["policy"]["requests"][0]["status"] == "APPLIED"
        assert doc["findings"] == []
        cases.append({"case": "verified_block", "exit": completed.returncode, "result": 2})

        # 3/4. Exemption preserves raw evidence; mixed dispositions remain visible.
        root = base / "exempt"
        _write(root / "a.txt", "RNC_SYNTH_KEY_GENERIC_ALPHA\n")
        _write(root / "b.txt", "RNC_SYNTH_KEY_GENERIC_BRAVO\n")
        plain = base / "plain.toml"
        _write(plain, 'schema_version = "0.2.0"\n')
        _, raw, _ = _run(binary, root, config=plain, run_id="raw")
        exempt = _config(
            base,
            "exempt.toml",
            'schema_version = "0.2.0"\n[policy]\n[[policy.exemptions]]\npolicy_id = "REPO-EXEMPT"\nselector = "path:a.txt"\nreason = "approved"\n',
        )
        _, filtered, _ = _run(binary, root, config=exempt, run_id="exempt")
        assert _findings_without_run(raw) == _findings_without_run(filtered)
        assert filtered["result"]["result_code"] == 3
        assert filtered["result"]["counts"]["detected"] == 2
        assert filtered["result"]["counts"]["exempted"] == 1
        assert filtered["result"]["counts"]["actionable"] == 1
        assert any(item["status"] == "EXEMPTED" for item in filtered["policy"]["dispositions"])
        cases.append({"case": "mixed_exemption", "exit": 10, "result": 3})

        # 5. Fully exempted findings -> POLICY_APPLIED, never CLEAN.
        _, all_exempt, _ = _run(binary, root, config=exempt, args=["--exempt", "path:b.txt"], run_id="all-exempt")
        assert all_exempt["result"]["result_code"] == 2
        assert all_exempt["result"]["counts"]["actionable"] == 0
        cases.append({"case": "fully_exempted", "exit": 0, "result": 2})

        # 6. Required oversize unit -> INCOMPLETE, exit 20.
        root = base / "incomplete"
        _write(root / "large.txt", "x" * 200)
        completed, doc, _ = _run(binary, root, args=["--max-file-bytes", "10", "--max-total-bytes", "20"], run_id="incomplete")
        assert completed.returncode == 20 and doc["result"]["result_code"] == 4
        assert doc["result"]["coverage"] in {"NONE", "PARTIAL"}
        cases.append({"case": "incomplete", "exit": 20, "result": 4})

        # 7. Finding limit -> FAILED, exit 30.
        root = base / "failed"
        _write(root / "two.txt", "RNC_SYNTH_KEY_GENERIC_ALPHA\nRNC_SYNTH_KEY_GENERIC_BRAVO\n")
        completed, doc, _ = _run(binary, root, args=["--max-findings", "1"], run_id="failed")
        assert completed.returncode == 30 and doc["result"]["result_code"] == 5
        cases.append({"case": "failed", "exit": 30, "result": 5})

        # 8. Optional uninspected unit does not fail a clean scan.
        root = base / "optional"
        _base(root)
        _write(root / "opt.txt", "RNC_SYNTH_KEY_GENERIC_OPTIONAL_ALPHA\n")
        completed, doc, _ = _run(
            binary, root,
            args=["--skip", "opt.txt", "--optional", "opt.txt"],
            run_id="optional",
        )
        assert completed.returncode == 0 and doc["result"]["result_code"] == 1
        assert doc["result"]["counts"]["uninspected"] == 1
        cases.append({"case": "optional_uninspected", "exit": 0, "result": 1})

        # 9. Zero required scope -> INCOMPLETE.
        root = base / "zero"
        _write(root / "only-optional.txt", "RNC_SYNTH_KEY_GENERIC_OPTIONAL_ALPHA\n")
        completed, doc, _ = _run(
            binary, root,
            args=["--skip", "only-optional.txt", "--optional", "only-optional.txt"],
            run_id="zero-required",
        )
        assert completed.returncode == 20 and doc["result"]["result_code"] == 4
        assert "NO_REQUIRED_SCOPE" in doc["result"]["reason_codes"]
        cases.append({"case": "zero_required", "exit": 20, "result": 4})

        # 10. Requested but unmatched block/exemption remain visible and do not
        # create POLICY_APPLIED.
        root = base / "unmatched"
        _write(root / "a.txt", "RNC_SYNTH_KEY_GENERIC_ALPHA\n")
        config = _config(
            base,
            "unmatched.toml",
            'schema_version = "0.2.0"\n[policy]\n[[policy.blocks]]\npolicy_id = "B"\nselector = "never/**"\nreason = "unused"\n[[policy.exemptions]]\npolicy_id = "E"\nselector = "path:never/**"\nreason = "unused"\n',
        )
        completed, doc, _ = _run(binary, root, config=config, run_id="unmatched")
        assert completed.returncode == 10 and doc["result"]["result_code"] == 3
        statuses = {request["kind"]: request["status"] for request in doc["policy"]["requests"]}
        assert statuses == {"BLOCK": "NOT_MATCHED", "EXEMPTION": "NOT_MATCHED"}
        cases.append({"case": "unmatched_requests", "exit": 10, "result": 3})

        # 11. Mandatory global block cannot be removed by repository or CLI.
        root = base / "mandatory"
        _write(root / "secrets/a.txt", "RNC_SYNTH_KEY_GENERIC_SECRET_ALPHA\n")
        _base(root)
        global_config = _config(
            base,
            "global.toml",
            'schema_version = "0.2.0"\n[ci]\naccepted_result_codes = [1, 2]\n[policy]\n[[policy.blocks]]\npolicy_id = "GLOBAL-BLOCK"\nselector = "secrets/**"\nreason = "global"\nmandatory = true\n',
        )
        repo_config = _config(base, "repo.toml", 'schema_version = "0.2.0"\n')
        completed, doc, _ = _run(binary, root, config=repo_config, global_config=global_config, run_id="mandatory")
        assert completed.returncode == 0 and doc["result"]["result_code"] == 2
        assert any(unit["locator"] == "secrets/a.txt" and unit["disposition"] == "VERIFIED_BLOCKED" for unit in doc["execution"]["units"])
        assert doc["policy"]["effective_policies"][0]["mandatory"] is True
        cases.append({"case": "mandatory_global", "exit": 0, "result": 2})

        # 12. CLI cannot broaden the global accepted-result cap.
        completed = subprocess.run(
            [
                str(binary), "scan", "--root", str(root), "--rules", str(RULES),
                "--global-config", str(global_config), "--config", str(repo_config),
                "--accept-result", "3", "--format", "summary",
            ],
            capture_output=True, text=True, timeout=60,
        )
        assert completed.returncode == 64, completed
        cases.append({"case": "mandatory_acceptance", "exit": 64, "result": None})

        # 13. Dual repository sources are a hard failure.
        root = base / "dual"
        _base(root)
        _write(root / ".rncscanner.toml", 'schema_version = "0.2.0"\n')
        _write(root / "security.config", 'version = 1\n[secret_detection]\nenabled = true\nruleset = "x"\nruleset_digest = "sha256:abc"\n')
        completed, _, _ = _run(binary, root, run_id="dual")
        assert completed.returncode == 64
        cases.append({"case": "dual_config", "exit": 64, "result": None})

        # 14. Legacy exclusion migrates to a verified block.
        root = base / "legacy"
        _write(root / "secret.txt", "RNC_SYNTH_KEY_GENERIC_LEGACY_ALPHA\n")
        _base(root)
        _write(
            root / "security.config",
            'version = 1\n[secret_detection]\nenabled = true\nruleset = "rnc-synthetic-v1"\nruleset_digest = "sha256:6a68625a57f75adcf1aaebd3f8ef1470c339b68fa0b80ab85ecdfc37af33f73d"\n[exclusions]\npaths = ["secret.txt"]\n',
        )
        completed, doc, _ = _run(binary, root, run_id="legacy")
        assert completed.returncode == 0 and doc["result"]["result_code"] == 2
        assert any(unit["locator"] == "secret.txt" and unit["disposition"] == "VERIFIED_BLOCKED" for unit in doc["execution"]["units"])
        cases.append({"case": "legacy_migration", "exit": 0, "result": 2})

        # 15. CLI caps narrow global limits; a file over the cap is incomplete.
        root = base / "limits"
        _write(root / "large.txt", "RNC_SYNTH_KEY_GENERIC_LARGE_ALPHA\n" + "x" * 100)
        global_limits = _config(
            base,
            "limits-global.toml",
            'schema_version = "0.2.0"\n[scan]\nmax_file_bytes = 10\nmax_total_bytes = 20\n',
        )
        completed, doc, _ = _run(
            binary, root,
            global_config=global_limits,
            args=["--max-file-bytes", "1000", "--max-total-bytes", "2000"],
            run_id="limits",
        )
        assert completed.returncode == 20 and doc["result"]["result_code"] == 4
        cases.append({"case": "limit_precedence", "exit": 20, "result": 4})

        # 16. Invalid selector is rejected before a scan.
        root = base / "invalid"
        _base(root)
        invalid = _config(
            base,
            "invalid.toml",
            'schema_version = "0.2.0"\n[policy]\n[[policy.blocks]]\npolicy_id = "B"\nselector = "../escape"\nreason = "bad"\n',
        )
        completed, _, _ = _run(binary, root, config=invalid, run_id="invalid")
        assert completed.returncode == 64
        cases.append({"case": "invalid_selector", "exit": 64, "result": None})

        # 17. Sanitized output contains no private fields or matched bytes.
        root = base / "sanitized"
        _write(root / "a.txt", "RNC_SYNTH_KEY_GENERIC_ALPHA\n")
        completed = subprocess.run(
            [
                str(binary), "scan", "--root", str(root), "--rules", str(RULES),
                "--format", "sanitized", "--run-id", "safe",
            ],
            capture_output=True, text=True, timeout=60,
        )
        assert completed.returncode == 10
        public = json.loads(completed.stdout)
        serialized = json.dumps(public)
        for forbidden in ("RNC_SYNTH_KEY_", "finding_id", "evidence_digest", "a.txt", "locator"):
            assert forbidden not in serialized
        assert public["result_code"] == 3 and public["accepted"] is False
        cases.append({"case": "sanitized", "exit": 10, "result": 3})

        # 19. Explicit authorized acceptance of ACTIONABLE changes only CI
        # enforcement, never the immutable result.
        root = base / "accept-actionable"
        _write(root / "a.txt", "RNC_SYNTH_KEY_GENERIC_ALPHA\n")
        accept_all = _config(
            base,
            "accept-all.toml",
            'schema_version = "0.2.0"\n[ci]\naccepted_result_codes = [1, 2, 3]\n',
        )
        completed, doc, _ = _run(binary, root, config=accept_all, run_id="accept-actionable")
        assert completed.returncode == 0 and doc["result"]["result_code"] == 3
        assert doc["ci"]["accepted"] is True
        cases.append({"case": "accept_actionable", "exit": 0, "result": 3})

        # 20. POLICY_APPLIED is rejected or accepted only by CI policy; its
        # result code never changes.
        root = base / "policy-ci"
        _write(root / "blocked.txt", "RNC_SYNTH_KEY_GENERIC_BLOCKED_ALPHA\n")
        _base(root)
        narrow_ci = _config(
            base,
            "narrow-ci.toml",
            'schema_version = "0.2.0"\n[ci]\naccepted_result_codes = [1]\n[policy]\n[[policy.blocks]]\npolicy_id = "B"\nselector = "blocked.txt"\nreason = "test"\n',
        )
        completed, doc, _ = _run(binary, root, config=narrow_ci, run_id="policy-rejected")
        assert completed.returncode == 10 and doc["result"]["result_code"] == 2
        assert doc["ci"]["accepted"] is False
        cases.append({"case": "policy_rejected", "exit": 10, "result": 2})
        completed, doc, _ = _run(binary, root, config=narrow_ci, args=["--accept-result", "1"], run_id="policy-narrow")
        assert completed.returncode == 10 and doc["result"]["result_code"] == 2
        cases.append({"case": "policy_rejected_narrow", "exit": 10, "result": 2})

        # 21. Incomplete coverage preserves lower-priority actionable evidence.
        root = base / "incomplete-findings"
        _write(root / "small.txt", "RNC_SYNTH_KEY_GENERIC_ALPHA\n")
        _write(root / "large.txt", "x" * 200)
        completed, doc, _ = _run(
            binary, root,
            args=["--max-file-bytes", "50", "--max-total-bytes", "100"],
            run_id="incomplete-findings",
        )
        assert completed.returncode == 20 and doc["result"]["result_code"] == 4
        assert doc["result"]["counts"]["detected"] == 1
        assert doc["result"]["counts"]["actionable"] == 1
        assert len(doc["findings"]) == 1
        cases.append({"case": "incomplete_with_findings", "exit": 20, "result": 4})

        # 22. Overlapping blocks resolve one winner and keep the other request
        # visible as UNSUPPORTED.
        root = base / "collision"
        _write(root / "secrets/a.txt", "RNC_SYNTH_KEY_GENERIC_ALPHA\n")
        collision = _config(
            base,
            "collision.toml",
            'schema_version = "0.2.0"\n[policy]\n[[policy.blocks]]\npolicy_id = "WIDE"\nselector = "secrets/**"\nreason = "wide"\n[[policy.blocks]]\npolicy_id = "NARROW"\nselector = "secrets/a.txt"\nreason = "narrow"\n',
        )
        completed, doc, _ = _run(binary, root, config=collision, run_id="collision")
        assert completed.returncode == 0 and doc["result"]["result_code"] == 2
        statuses = {request["policy_id"]: request["status"] for request in doc["policy"]["requests"]}
        assert statuses == {"WIDE": "UNSUPPORTED", "NARROW": "APPLIED"}
        assert len(doc["policy"]["applied_blocks"]) == 1
        cases.append({"case": "block_collision", "exit": 0, "result": 2})

        # 18. Pre-scan block on an unreadable file proves non-access on Unix.
        if os.name == "posix":
            root = base / "noaccess"
            _write(root / "blocked.txt", "RNC_SYNTH_KEY_GENERIC_BLOCKED_ALPHA\n")
            _base(root)
            os.chmod(root / "blocked.txt", 0o000)
            try:
                completed, doc, _ = _run(
                    binary, root,
                    args=["--exclude", "blocked.txt"],
                    run_id="noaccess",
                )
                assert completed.returncode == 0
                unit = next(unit for unit in doc["execution"]["units"] if unit["locator"] == "blocked.txt")
                assert unit["disposition"] == "VERIFIED_BLOCKED"
                cases.append({"case": "blocked_no_open", "exit": 0, "result": 2})
            finally:
                os.chmod(root / "blocked.txt", 0o600)
    return {
        "contract": "cp2-policy-classification-v1",
        "cases": cases,
        "all_passed": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.binary)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"cases": len(report["cases"]), "all_passed": True}))


if __name__ == "__main__":
    main()
