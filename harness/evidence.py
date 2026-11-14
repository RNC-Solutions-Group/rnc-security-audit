"""Common evidence-resolution primitives for scoring.

The resolver deliberately separates *source identity* from *credential value
identity*.  A scanner may prove it found the exact oracle source span without
exposing the plaintext value (RNC does this by design).  It may also provide a
decoded identity or transient text.  Scoring must treat those evidence kinds
consistently and must not require a particular scanner's redaction strategy.

Only representation-specific transformations are defined here.  There is no
generic ``strip()`` across all credential families.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass

# Evidence kinds.
IDENTITY_DIGEST = "identity_digest"
SOURCE_SPAN_EXACT = "source_span_exact"
SOURCE_SPAN_NORMALIZED = "source_span_normalized"
DECODED_IDENTITY = "decoded_identity"
PRIVATE_KEY_MATERIAL = "private_key_material"
PUBLIC_KEY_ONLY = "public_key_only"
TRANSIENT_TEXT = "transient_text"

# Authoritative evidence-strength contract. Higher is stronger. Candidate
# construction, ambiguity assessment, and assignment must all use this map (or a
# rank tuple beginning with it); no caller may invent a local ordering.
EVIDENCE_STRENGTH = {
    PRIVATE_KEY_MATERIAL: 6,
    IDENTITY_DIGEST: 5,
    SOURCE_SPAN_EXACT: 4,
    SOURCE_SPAN_NORMALIZED: 3,
    DECODED_IDENTITY: 2,
    PUBLIC_KEY_ONLY: 0,
    TRANSIENT_TEXT: 0,
}

# Verification stages.
STAGE_ADAPTER = "ADAPTER"
STAGE_SOURCE_IDENTITY = "SOURCE_IDENTITY"
STAGE_CANDIDATE_DISCOVERY = "CANDIDATE_DISCOVERY"
STAGE_VALUE = "VALUE"
STAGE_LOCATION = "LOCATION"
STAGE_MATERIAL = "MATERIAL"
STAGE_ATTRIBUTION = "ATTRIBUTION"

# Controlled reason codes.  These are diagnostics; they are not terminal
# classifications.
EVIDENCE_MISSING = "EVIDENCE_MISSING"
EVIDENCE_CONFLICT = "EVIDENCE_CONFLICT"
REPRESENTATION_UNSUPPORTED = "REPRESENTATION_UNSUPPORTED"
PRIVATE_MATERIAL_UNPROVEN = "PRIVATE_MATERIAL_UNPROVEN"
LOCATION_UNVERIFIED = "LOCATION_UNVERIFIED"
LOCATION_LINE_MISMATCH = "LOCATION_LINE_MISMATCH"
LOCATION_OFFSET_MISMATCH = "LOCATION_OFFSET_MISMATCH"
MEMBER_MISMATCH = "MEMBER_MISMATCH"
CANDIDATE_AMBIGUOUS = "CANDIDATE_AMBIGUOUS"
SOURCE_OCCURRENCE_MISMATCH = "SOURCE_OCCURRENCE_MISMATCH"
VALUE_TRUNCATED = "VALUE_TRUNCATED"
VALUE_EXTENDED = "VALUE_EXTENDED"
VALUE_MISMATCH = "VALUE_MISMATCH"
PARTIAL_MATERIAL = "PARTIAL_MATERIAL"
UNSUPPORTED_NORMALIZATION = "UNSUPPORTED_NORMALIZATION"
ORACLE_COVERAGE_UNKNOWN = "ORACLE_COVERAGE_UNKNOWN"
ADAPTER_CONTRACT_FAILURE = "ADAPTER_CONTRACT_FAILURE"

_PEM_RE = re.compile(
    rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
    rb".*?"
    rb"-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    re.DOTALL,
)
_PEM_HEADER = b"-----BEGIN "
_PEM_PRIVATE_MARKER = b"PRIVATE KEY-----"
_PEM_FOOTER = b"-----END "


@dataclass(frozen=True)
class EvidenceAlias:
    kind: str
    digest: str
    detail: str = ""


def digest_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _looks_like_complete_private_pem(value: bytes) -> bool:
    """Return true only for a complete private-key PEM block.

    Trailing whitespace after the footer is allowed; missing header/footer,
    public-key blocks, certificates, and incomplete bodies are not.
    """
    if not value.startswith(_PEM_HEADER):
        return False
    if _PEM_PRIVATE_MARKER not in value:
        return False
    match = _PEM_RE.search(value)
    if match is None or match.start() != 0:
        return False
    tail = value[match.end() :]
    return all(byte in b" \t\r\n" for byte in tail)


def pem_span_aliases(span: bytes) -> tuple[EvidenceAlias, ...]:
    """Approved aliases for a complete private-key PEM source span.

    The oracle may include one terminal newline that a scanner omits because it
    trims the block.  Only terminal line ending/whitespace variation is allowed.
    No leading trim, no body modification, and no generic substring handling.
    """
    if not _looks_like_complete_private_pem(span):
        return ()
    values: list[tuple[str, bytes, str]] = []
    values.append((SOURCE_SPAN_EXACT, span, "exact oracle span"))

    no_crlf = span.rstrip(b"\r\n")
    values.append((SOURCE_SPAN_NORMALIZED, no_crlf, "PEM without terminal CR/LF"))

    no_ws = span.rstrip()
    if no_ws.endswith(b"PRIVATE KEY-----"):
        values.append((SOURCE_SPAN_NORMALIZED, no_ws, "PEM without terminal whitespace"))

    lf = span.replace(b"\r\n", b"\n")
    values.append((SOURCE_SPAN_NORMALIZED, lf, "PEM with LF line endings"))

    crlf = lf.replace(b"\n", b"\r\n")
    values.append((SOURCE_SPAN_NORMALIZED, crlf, "PEM with CRLF line endings"))

    seen: set[str] = set()
    aliases: list[EvidenceAlias] = []
    for kind, value, detail in values:
        digest = digest_sha256(value)
        if digest in seen:
            continue
        seen.add(digest)
        aliases.append(EvidenceAlias(kind=kind, digest=digest, detail=detail))
    return tuple(aliases)


def _private_pem_from_bytes(value: bytes) -> bool:
    return _looks_like_complete_private_pem(value)


def _base64_decode_candidates(value: bytes) -> list[bytes]:
    """Decode bounded base64 text without accepting arbitrary binary."""
    text = value.strip()
    if not text or len(text) < 16:
        return []
    candidates: list[bytes] = []
    # Standard and URL-safe alphabets, with optional missing padding.
    padded = text + b"=" * ((4 - len(text) % 4) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(padded)
        except (ValueError, binascii.Error):
            continue
        if decoded and decoded not in candidates:
            candidates.append(decoded)
    return candidates


def private_span_aliases(
    span: bytes, representation: str | None = None
) -> tuple[EvidenceAlias, ...]:
    """Return approved private-key aliases from a source span.

    PEM/OpenSSH spans use the direct block.  Kubernetes/Base64 spans are
    decoded first; public-key-only, malformed, or encrypted payloads that do not
    decode to a complete private PEM produce no decoded aliases.
    """
    aliases = list(pem_span_aliases(span))
    representation = representation or ""
    if representation.startswith("kubernetes_") or representation == "kubeconfig_client_key":
        for candidate in _base64_decode_candidates(span):
            if not _private_pem_from_bytes(candidate):
                continue
            for alias in pem_span_aliases(candidate):
                aliases.append(
                    EvidenceAlias(
                        kind=alias.kind,
                        digest=alias.digest,
                        detail=f"decoded {representation}: {alias.detail}",
                    )
                )
    seen: set[str] = set()
    unique: list[EvidenceAlias] = []
    for alias in aliases:
        if alias.digest in seen:
            continue
        seen.add(alias.digest)
        unique.append(alias)
    return tuple(unique)


def private_key_material(span: bytes, representation: str | None = None) -> bool:
    """Validate private-key material from an oracle source span only.

    The span is the oracle's exact source bytes.  For PEM/OpenSSH this must be a
    complete private block.  For Kubernetes/Base64 representations the encoded
    span is decoded and must produce a complete private PEM block.
    """
    if _private_pem_from_bytes(span):
        return True
    representation = representation or ""
    if representation.startswith("kubernetes_") or representation == "kubeconfig_client_key":
        return any(_private_pem_from_bytes(candidate) for candidate in _base64_decode_candidates(span))
    if representation in ("putty_ppk_v2", "pkcs12_der"):
        # These formats do not use PEM headers.  Their material is private but
        # cannot be validated by the PEM detector; the oracle representation is
        # the only safe signal.  Callers must not treat this as public-only.
        return representation == "putty_ppk_v2" and span.startswith(b"PuTTY-User-Key-File-")
    return False


def is_public_key_span(span: bytes) -> bool:
    head = span[:256].lstrip()
    return head.startswith(b"ssh-rsa ") or head.startswith(b"ssh-ed25519 ") or b"PUBLIC KEY-----" in head


def value_relation(
    span: bytes,
    *,
    finding_digest: str | None,
    finding_text: str | None = None,
) -> tuple[str | None, str]:
    """Conservatively classify a value-level relation for near-miss diagnostics.

    Exact and authorized normalized matches are handled by the resolver before
    this function.  This helper only identifies *proven* truncation/extension
    relations.  It never uses path or line proximity.
    """
    if not finding_digest:
        return None, EVIDENCE_MISSING
    exact = digest_sha256(span)
    if finding_digest == exact:
        return SOURCE_SPAN_EXACT, "exact source span"
    for alias in pem_span_aliases(span):
        if finding_digest == alias.digest:
            return alias.kind, alias.detail
    # Truncation: only small terminal truncations, and only when the digest is
    # of a strict prefix of the authoritative span.  This is diagnostic, never
    # TP credit.
    for removed in range(1, min(17, len(span))):
        if finding_digest == digest_sha256(span[:-removed]):
            return VALUE_TRUNCATED, f"value is {removed} byte(s) shorter than span"
    # Extension/truncation using transient text when the scanner provides it.
    if finding_text:
        text = finding_text.strip()
        try:
            source_text = span.decode("utf-8")
        except UnicodeDecodeError:
            source_text = ""
        if source_text and text:
            if source_text in text and len(text) > len(source_text):
                return VALUE_EXTENDED, "finding text contains the full source span plus extra bytes"
            if text in source_text and len(text) < len(source_text):
                return VALUE_TRUNCATED, "finding text is a prefix/substring of the source span"
    if finding_digest == digest_sha256(span.strip()):
        return VALUE_MISMATCH, "only non-representation-specific whitespace would match"
    return None, EVIDENCE_CONFLICT


def stable_text(value: str | None) -> str:
    return value or ""


def stable_finding_key(
    *,
    file: str,
    line: int | None,
    commit: str | None,
    rule_id: str,
    secret_sha256: str | None,
    match_sha256: str | None,
    byte_start: int | None = None,
    byte_end: int | None = None,
) -> tuple:
    """Order-independent identity for a normalized finding.

    The key deliberately excludes list position.  Identical duplicate findings
    share a key; the caller can use a secondary occurrence counter when it needs
    to distinguish them for reporting.
    """
    return (
        file.replace("\\", "/"),
        line if line is not None else -1,
        stable_text(commit),
        rule_id,
        stable_text(secret_sha256),
        stable_text(match_sha256),
        byte_start if byte_start is not None else -1,
        byte_end if byte_end is not None else -1,
    )
