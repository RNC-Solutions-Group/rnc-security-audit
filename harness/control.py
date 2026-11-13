"""Positive control planted beside a precision corpus.

The control file is never scored. It witnesses that a scanner actually inspected
the directory **and extracted an expected credential**. A finding that merely
names ``000-control.log`` is not enough, and a control value echoed in raw
stdout/stderr is not a structured detection; both are reported as diagnostics
only.

All values are synthetic and assembled from fragments so this source file does
not itself match the credential shapes it describes.
"""

from __future__ import annotations

from .matching import best_match, normalize_text
from .model import ControlResult, Finding
from .util import basename

CONTROL_FILE = "000-control.log"

CONTROL_SECRETS: tuple[tuple[str, str], ...] = (
    ("aws-access-key-id", "AKIA" + "3XQ7ZR2LMWD5TKVB"),
    ("github-token", "ghp_" + "9tR2mV6xQ0aL4bN8" + "cW1eK5jH7dS3fG0uY2iP"),
    ("private-key", "-----BEGIN " + "RSA PRIVATE KEY-----"),
)

# Clearly synthetic filler: base64 of "synthetic-key-body", split so no single
# long high-entropy run appears in this source file. It is not a credential.
_CONTROL_BODY = "c3ludGhldGlj" + "LWtleS1ib2R5"
_PEM_END = "-----END " + "RSA PRIVATE KEY-----"


def secret_values() -> tuple[str, ...]:
    return tuple(value for _, value in CONTROL_SECRETS)


def control_text() -> str:
    aws, github, pem = secret_values()
    return "\n".join(
        [
            "# %s -- planted by the scan harness. NOT part of the corpus." % CONTROL_FILE,
            "#",
            "# Every credential below is synthetic. It exists only to prove that a",
            "# scanner actually read these bytes. Control findings are never scored.",
            "2026-01-04T09:12:45Z deploy[1] aws_access_key_id=" + aws,
            "2026-01-04T09:12:45Z deploy[1] github_token=" + github,
            "2026-01-04T09:12:46Z deploy[1] reading signing key /etc/keys/deploy.pem",
            pem,
            _CONTROL_BODY,
            "-----END " + "RSA PRIVATE KEY-----",
            "",
        ]
    )


def _is_control(finding: Finding) -> bool:
    return basename(finding.file) == CONTROL_FILE


def _detects(kind: str, expected: str, finding: Finding) -> bool:
    match = best_match(expected, finding)
    if match.eligible:
        return True
    if kind == "private-key" and match.classification == "partial" and match.relation == "finding_contains_expected":
        evidence = normalize_text(finding.secret or finding.match)
        return expected in evidence and _PEM_END in evidence
    return False


def _echoed_in(kind: str, value: str, text: str) -> bool:
    if not value:
        return False
    if kind == "private-key":
        # The PEM header also occurs in corpus private-key findings. Require the
        # unique synthetic control body as well before calling it a control echo.
        return value in text and _CONTROL_BODY in text and _PEM_END in text
    return value in text


def control_result(findings: list[Finding], raw_texts: tuple[str, ...]) -> ControlResult:
    on_file = [finding for finding in findings if _is_control(finding)]
    detected: list[str] = []
    matching_findings = 0
    for finding in on_file:
        matched_any = False
        for kind, expected in CONTROL_SECRETS:
            if _detects(kind, expected, finding):
                matched_any = True
                if kind not in detected:
                    detected.append(kind)
        if matched_any:
            matching_findings += 1

    echoed = tuple(
        kind
        for kind, value in CONTROL_SECRETS
        if any(_echoed_in(kind, value, text) for text in raw_texts)
    )
    notes: list[str] = []
    if not on_file:
        notes.append("no finding named the control file")
    elif not detected:
        notes.append(
            "the control file was scanned, but none of its planted credentials "
            "appeared in a structured finding"
        )
    if echoed and not detected:
        notes.append(
            "control values appeared in raw scanner output but were not a "
            "structured detection; this does not validate the scan"
        )
    return ControlResult(
        file=CONTROL_FILE,
        reported=bool(detected),
        file_encountered=bool(on_file),
        findings_on_file=len(on_file),
        credential_findings=matching_findings,
        kinds_detected=tuple(detected),
        kinds_echoed=echoed,
        planted=tuple(kind for kind, _ in CONTROL_SECRETS),
        unmatched_findings=max(0, len(on_file) - matching_findings),
        notes=tuple(notes),
    )
