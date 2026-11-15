"""Canonical archive and member identity.

A scanner may report an archive member in one of three ways:

* an explicit ``container_member`` field;
* an embedded path such as ``archive.zip!member/path``;
* an embedded path using ``::`` instead of ``!``.

Nested archives may mix separators (``outer.zip::inner.tar!member``).  The
earliest separator is the boundary of the enclosing archive; later separators
are canonicalized to ``!`` inside the member identity.  The canonical member is
relative to its immediate enclosing archive.  Absolute paths, drive-qualified
paths, traversal segments, and empty identities are rejected as unsafe rather
than normalized into a different source.
"""

from __future__ import annotations

ARCHIVE_SEPARATORS = ("!", "::")


def _normalize_path(value: str) -> str:
    return value.replace("\\", "/").strip()


def canonical_member(value: str | None) -> str | None:
    """Return a safe canonical member path, or ``None`` for no member.

    ``None`` is also returned for unsafe values.  Callers must treat an explicit
    unsafe value as a mismatch; they must not fall back to a path-only match.
    """
    if not value:
        return None
    text = _normalize_path(value)
    if (
        text.startswith("/")
        or text.startswith("~")
        or _is_drive_qualified(text)
        or "\x00" in text
    ):
        return None
    # ``!/`` and ``::`` are formatting variants of the same nested boundary.
    text = text.replace("::", "!").replace("!/", "!")
    if "!" in text:
        # A nested archive boundary is part of the member identity.  Validate
        # each segment so a traversal cannot hide behind a nested archive.
        segments = text.split("!")
        parts: list[str] = []
        for segment in segments:
            clean = _clean_segment(segment)
            if clean is None:
                return None
            parts.append(clean)
        return "!".join(parts) or None
    return _clean_segment(text)


def _is_drive_qualified(value: str) -> bool:
    return len(value) >= 2 and value[0].isalpha() and value[1] == ":"


def _clean_segment(value: str) -> str | None:
    value = value.strip()
    if value.startswith("/") or value.startswith("~") or _is_drive_qualified(value):
        return None
    value = value.strip("/")
    if not value:
        return None
    pieces: list[str] = []
    for piece in value.split("/"):
        if piece in ("", "."):
            continue
        if piece == "..":
            return None
        pieces.append(piece)
    return "/".join(pieces) or None


def split_archive_path(path: str) -> tuple[str, str | None]:
    """Split a reported path at its earliest archive boundary.

    Separator priority must not decide the boundary: in
    ``outer.zip::inner.tar!secret.txt`` the first archive is ``outer.zip`` and
    the member identity is ``inner.tar!secret.txt``.  The member is canonicalized
    with ``!`` for every nested boundary.
    """
    text = _normalize_path(path)
    boundaries = [
        (text.find(separator), separator)
        for separator in ARCHIVE_SEPARATORS
        if separator in text
    ]
    if not boundaries:
        return text, None
    position, separator = min(boundaries, key=lambda value: value[0])
    archive = text[:position].rstrip("/")
    if not archive:
        return text, None
    member = canonical_member(text[position + len(separator) :])
    return archive, member


def member_from_path(path: str) -> str | None:
    return split_archive_path(path)[1]


def has_member_separator(path: str) -> bool:
    text = _normalize_path(path)
    return any(separator in text for separator in ARCHIVE_SEPARATORS)


def archive_from_path(path: str) -> str:
    return split_archive_path(path)[0]


def is_gzip_path(path: str) -> bool:
    lowered = _normalize_path(path).lower()
    if lowered.endswith(".tar.gz") or lowered.endswith(".tgz"):
        return False
    return lowered.endswith(".gz") or lowered.endswith(".gzip")
