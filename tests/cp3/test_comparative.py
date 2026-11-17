"""Negative controls for one-to-one Gitleaks reconciliation."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.cp3.comparative import _span_from_location, score_gitleaks


def truth_item(
    path: str,
    token: bytes,
    start: int,
    end: int,
    *,
    rule: str,
    family: str,
    identifier: str,
) -> dict:
    return {
        "path": path,
        "token": token,
        "start_byte": start,
        "end_byte": end,
        "rule_id": rule,
        "family": family,
        "finding_id": identifier,
    }


def location(source: bytes, start: int, end: int) -> dict:
    line = source.count(b"\n", 0, start) + 1
    end_line = source.count(b"\n", 0, end) + 1
    start_origin = source.rfind(b"\n", 0, start) if line > 1 else 0
    end_origin = source.rfind(b"\n", 0, end) if end_line > 1 else 0
    if start_origin < 0:
        start_origin = 0
    if end_origin < 0:
        end_origin = 0
    return {
        "StartLine": line,
        "EndLine": end_line,
        "StartColumn": start - start_origin + 1,
        "EndColumn": end - end_origin,
    }


def observation(
    path: Path,
    source: bytes,
    token: bytes,
    *,
    rule: str,
    start: int | None = None,
    end: int | None = None,
    secret: bytes | None = None,
    match: bytes | None = None,
    columns: bool = True,
) -> dict:
    if start is None:
        start = source.index(token)
    if end is None:
        end = start + len(token)
    item = {
        "File": str(path),
        "RuleID": rule,
        "Secret": (secret if secret is not None else token).decode("utf-8"),
        "Match": (match if match is not None else token).decode("utf-8"),
    }
    if columns:
        item.update(location(source, start, end))
    return item


class ComparatorNegativeControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rnc-cp3-comparative-")
        self.root = Path(self.temp.name)
        self.github = b"ghp_" + b"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        self.other = b"ghp_" + b"B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6Q7r8S9"

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def github_truth(self, path: str, source: bytes, start: int, end: int, identifier: str) -> dict:
        return truth_item(
            path,
            source[start:end],
            start,
            end,
            rule="github-classic-pat",
            family="github-token",
            identifier=identifier,
        )

    def test_gitleaks_column_contract_reconstructs_exact_source_bytes(self):
        data = b"first line\nsecond=" + self.github + b"\n"
        start = data.index(self.github)
        end = start + 40
        previous_newline = data.rfind(b"\n", 0, start)
        span = _span_from_location(
            data,
            2,
            2,
            start - previous_newline + 1,
            end - previous_newline,
        )
        self.assertEqual(span, (start, end))

    def test_finding_in_negative_file_is_a_false_positive_not_unscored(self):
        source = b"token=" + self.github + b"\n"
        a = self.write("a.txt", source)
        b = self.write("b.txt", b"noise only\n")
        truth = [self.github_truth("a.txt", source, 6, 46, "t-1")]
        item = observation(b, b"noise only\n", b"noise", rule="github-pat")
        result = score_gitleaks([item], truth, self.root)
        self.assertEqual(result["tp"], 0)
        self.assertEqual(result["false_positive"], 1)
        self.assertEqual(result["unscored"], 0)
        self.assertTrue(a.is_file())

    def test_unknown_rule_id_is_not_credited(self):
        source = b"token=" + self.github + b"\n"
        path = self.write("a.txt", source)
        truth = [self.github_truth("a.txt", source, 6, 46, "t-1")]
        item = observation(path, source, self.github, rule="unseen-vendor-rule")
        result = score_gitleaks([item], truth, self.root)
        self.assertEqual(result["tp"], 0)
        self.assertEqual(result["unscored"], 1)
        self.assertEqual(result["fn"], 1)

    def test_zero_findings_is_not_a_clean_accuracy_claim(self):
        source = b"token=" + self.github + b"\n"
        path = self.write("a.txt", source)
        truth = [self.github_truth("a.txt", source, 6, 46, "t-1")]
        result = score_gitleaks([], truth, self.root)
        self.assertEqual(result["tp"], 0)
        self.assertEqual(result["fn"], 1)
        self.assertIsNone(result["precision_percent"])
        self.assertEqual(result["recall_percent"], 0.0)
        self.assertIsNone(result["f1_percent"])
        self.assertTrue(path.is_file())

    def test_reporting_every_candidate_is_penalized(self):
        source = b"token=" + self.github + b"\nnoise\n"
        self.write("a.txt", source)
        truth = [self.github_truth("a.txt", source, 6, 46, "t-1")]
        noisy = observation(
            self.root / "a.txt",
            source,
            b"noise",
            rule="github-pat",
            start=source.index(b"noise"),
        )
        exact = observation(self.root / "a.txt", source, self.github, rule="github-pat")
        result = score_gitleaks([exact, noisy], truth, self.root)
        self.assertEqual(result["tp"], 1)
        self.assertEqual(result["fp"], 1)
        self.assertEqual(result["fn"], 0)
        self.assertEqual(result["precision_percent"], 50.0)

    def test_one_of_two_repeated_secrets_misses_the_second(self):
        source = b"a=" + self.github + b" b=" + self.github + b"\n"
        self.write("a.txt", source)
        first = source.index(self.github)
        second = source.index(self.github, first + 1)
        truth = [
            self.github_truth("a.txt", source, first, first + 40, "t-1"),
            self.github_truth("a.txt", source, second, second + 40, "t-2"),
        ]
        result = score_gitleaks(
            [observation(self.root / "a.txt", source, self.github, rule="github-pat", start=first)],
            truth,
            self.root,
        )
        self.assertEqual(result["tp"], 1)
        self.assertEqual(result["fn"], 1)
        self.assertEqual(result["recall_percent"], 50.0)

    def test_one_observation_cannot_satisfy_two_repeated_expectations(self):
        source = b"a=" + self.github + b" b=" + self.github + b"\n"
        path = self.write("a.txt", source)
        first = source.index(self.github)
        second = source.index(self.github, first + 1)
        truth = [
            self.github_truth("a.txt", source, first, first + 40, "t-1"),
            self.github_truth("a.txt", source, second, second + 40, "t-2"),
        ]
        ambiguous = observation(
            path,
            source,
            self.github,
            rule="github-pat",
            columns=False,
        )
        result = score_gitleaks([ambiguous], truth, self.root)
        self.assertEqual(result["tp"], 0)
        self.assertEqual(result["fn"], 2)
        self.assertEqual(result["ambiguous"], 1)
        self.assertEqual(result["precision_percent"], None)

    def test_two_observations_for_one_expectation_are_duplicates(self):
        source = b"token=" + self.github + b"\n"
        path = self.write("a.txt", source)
        truth = [self.github_truth("a.txt", source, 6, 46, "t-1")]
        first = observation(path, source, self.github, rule="github-pat")
        second = observation(path, source, self.github, rule="github-pat")
        result = score_gitleaks([first, second], truth, self.root)
        self.assertEqual(result["tp"], 1)
        self.assertEqual(result["duplicates"], 1)
        self.assertEqual(result["fp"], 0)
        self.assertEqual(result["precision_percent"], 100.0)

    def test_two_different_secrets_on_one_line_remain_distinct(self):
        source = b"a=" + self.github + b" b=" + self.other + b"\n"
        path = self.write("a.txt", source)
        first = source.index(self.github)
        second = source.index(self.other)
        truth = [
            self.github_truth("a.txt", source, first, first + 40, "t-1"),
            self.github_truth("a.txt", source, second, second + 40, "t-2"),
        ]
        result = score_gitleaks(
            [
                observation(path, source, self.github, rule="github-pat"),
                observation(path, source, self.other, rule="github-pat"),
            ],
            truth,
            self.root,
        )
        self.assertEqual(result["tp"], 2)
        self.assertEqual(result["fn"], 0)
        self.assertEqual(result["precision_percent"], 100.0)

    def test_correct_secret_at_wrong_position_is_not_a_true_positive(self):
        source = b"a=" + self.github + b" b=" + self.github + b"\n"
        path = self.write("a.txt", source)
        first = source.index(self.github)
        second = source.index(self.github, first + 1)
        truth = [self.github_truth("a.txt", source, first, first + 40, "t-1")]
        shifted = observation(
            path,
            source,
            self.github,
            rule="github-pat",
            start=second,
        )
        result = score_gitleaks([shifted], truth, self.root)
        self.assertEqual(result["tp"], 0)
        self.assertEqual(result["wrong_position"], 1)
        self.assertEqual(result["fn"], 1)

    def test_correct_secret_in_wrong_file_is_not_a_true_positive(self):
        source = b"token=" + self.github + b"\n"
        self.write("a.txt", source)
        other = self.write("b.txt", source)
        truth = [self.github_truth("a.txt", source, 6, 46, "t-1")]
        result = score_gitleaks(
            [observation(other, source, self.github, rule="github-pat")],
            truth,
            self.root,
        )
        self.assertEqual(result["tp"], 0)
        self.assertEqual(result["wrong_file"], 1)
        self.assertEqual(result["fn"], 1)

    def test_wrong_family_is_not_silently_accepted(self):
        source = b"token=" + self.github + b"\n"
        path = self.write("a.txt", source)
        truth = [
            truth_item(
                "a.txt",
                source[6:46],
                6,
                46,
                rule="aws-access-key-id",
                family="aws-credentials",
                identifier="t-1",
            )
        ]
        result = score_gitleaks(
            [observation(path, source, self.github, rule="github-pat")],
            truth,
            self.root,
        )
        self.assertEqual(result["tp"], 0)
        self.assertEqual(result["wrong_family"], 1)
        self.assertEqual(result["fp"], 1)
        self.assertEqual(result["fn"], 1)

    def test_overlapping_but_misaligned_observation_is_not_a_true_positive(self):
        source = b"token=" + self.github + b"\n"
        path = self.write("a.txt", source)
        truth = [self.github_truth("a.txt", source, 6, 46, "t-1")]
        misaligned = observation(
            path,
            source,
            self.github,
            rule="github-pat",
            start=7,
            end=47,
        )
        result = score_gitleaks([misaligned], truth, self.root)
        self.assertEqual(result["tp"], 0)
        self.assertEqual(result["misaligned"], 1)
        self.assertEqual(result["fp"], 1)

    def test_multiline_private_key_is_a_true_positive(self):
        source = b"-----BEGIN PRIVATE KEY-----\nQUJDREVGR0g=\n-----END PRIVATE KEY-----\n"
        path = self.write("key.pem", source)
        truth = [
            truth_item(
                "key.pem",
                source,
                0,
                len(source) - 1,
                rule="pem-private-key",
                family="pem-private-key",
                identifier="t-1",
            )
        ]
        item = observation(path, source, source[:-1], rule="private-key")
        result = score_gitleaks([item], truth, self.root)
        self.assertEqual(result["tp"], 1)
        self.assertEqual(result["fn"], 0)

    def test_assignment_context_does_not_change_secret_identity(self):
        source = b'api_key = "' + self.github + b'"\n'
        path = self.write("a.txt", source)
        start = source.index(self.github)
        truth = [self.github_truth("a.txt", source, start, start + 40, "t-1")]
        item = observation(
            path,
            source,
            self.github,
            rule="github-pat",
            start=0,
            end=len(source) - 1,
            match=b"api_key = " + self.github,
        )
        result = score_gitleaks([item], truth, self.root)
        self.assertEqual(result["tp"], 1)
        self.assertEqual(result["fn"], 0)

    def test_malformed_or_missing_location_is_not_guessed(self):
        source = b"a=" + self.github + b" b=" + self.github + b"\n"
        path = self.write("a.txt", source)
        first = source.index(self.github)
        second = source.index(self.github, first + 1)
        truth = [
            self.github_truth("a.txt", source, first, first + 40, "t-1"),
            self.github_truth("a.txt", source, second, second + 40, "t-2"),
        ]
        item = observation(
            path,
            source,
            self.github,
            rule="github-pat",
            columns=False,
        )
        item["StartLine"] = 99
        item["StartColumn"] = 0
        result = score_gitleaks([item], truth, self.root)
        self.assertEqual(result["tp"], 0)
        self.assertEqual(result["ambiguous"], 1)
        self.assertEqual(result["fn"], 2)

    def test_duplicate_observation_identity_never_adds_tp(self):
        source = b"token=" + self.github + b"\n"
        path = self.write("a.txt", source)
        truth = [self.github_truth("a.txt", source, 6, 46, "t-1")]
        item = observation(path, source, self.github, rule="github-pat")
        result = score_gitleaks([item, dict(item), dict(item)], truth, self.root)
        self.assertEqual(result["tp"], 1)
        self.assertEqual(result["duplicates"], 2)
        self.assertEqual(result["fp"], 0)

    def test_observation_order_does_not_change_metrics(self):
        source = b"a=" + self.github + b" b=" + self.other + b"\n"
        path = self.write("a.txt", source)
        first = source.index(self.github)
        second = source.index(self.other)
        truth = [
            self.github_truth("a.txt", source, first, first + 40, "t-1"),
            self.github_truth("a.txt", source, second, second + 40, "t-2"),
        ]
        observations = [
            observation(path, source, self.github, rule="github-pat"),
            observation(path, source, self.other, rule="github-pat"),
        ]
        forward = score_gitleaks(observations, truth, self.root)
        reverse = score_gitleaks(list(reversed(observations)), truth, self.root)
        keys = (
            "tp",
            "fp",
            "fn",
            "duplicates",
            "ambiguous",
            "unscored",
            "precision_percent",
            "recall_percent",
            "f1_percent",
        )
        for key in keys:
            self.assertEqual(forward[key], reverse[key], key)
        self.assertEqual(forward["tp"], 2)


if __name__ == "__main__":
    unittest.main()
