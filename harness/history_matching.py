"""Source-accurate Leaky Repo Git-history matching.

The matcher is scanner-independent.  A normalized finding is credited only when
all of the following agree:

* the finding names a path in the owner-approved source occurrence (including a
  reviewed rename);
* the finding's commit is the introduction commit or a descendant of it;
* the source blob at the finding commit still contains the approved credential
  representation at the expected location;
* an occurrence line may move only through unchanged-line lineage, or through an
  equal-size value-preserving edit inside that existing lineage; a copy,
  deletion, rotation, or reintroduction starts no lineage; and
* the finding's safe evidence digest matches a canonical or validated typed
  representation of that credential.

Reviewed negative references are anchored at their `observed_commit`; a
`Removed` reference covers revisions at or before that snapshot, not later
replacements. Informative and typed negative references require an expected
value representation, not merely a token from the same line.

Every observed finding is retained in the result.  Unknown or unverified
findings are investigation items, never silent false positives.
"""

from __future__ import annotations

import base64
import hashlib
import re
import subprocess
import urllib.parse
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from .contracts import (
    AMBIGUOUS_MATCH,
    BLOCKED,
    DUPLICATE,
    EXECUTION_ERROR,
    EXPECTED_DETECTION,
    FALSE_POSITIVE,
    FindingEvaluation,
    INFORMATIVE_MATCH,
    MISSED_EXPECTATION,
    NormalizedFinding,
    ScoringResult,
    UNMAPPED,
    UNMATCHED_PENDING_REVIEW,
    UNVERIFIED_EVIDENCE,
)
from .errors import HarnessError
from .history_oracle import HistoryOracle


class HistoryMatchError(HarnessError):
    pass


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _add(out: dict[str, str], label: str, value: str | None) -> None:
    if value:
        out.setdefault(_sha(value), label)


def _add_digest(out: dict[str, str], label: str, digest: str | None) -> None:
    if digest:
        out.setdefault(digest, label)


def _code_prefix(value: str) -> str:
    """Return the non-comment code portion of a source line.

    This distinguishes a trailing-comment edit from a changed assignment or
    value. It is used only inside an existing lineage, never for new credit.
    """
    match = re.search(r"\s+(?:#|//)", value)
    code = value[: match.start()] if match else value
    return code.rstrip()


def _quoted(line: str) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    values.extend(("double_quoted", match.group(1)) for match in re.finditer(r'"([^"\r\n]*)"', line))
    values.extend(("single_quoted", match.group(1)) for match in re.finditer(r"'([^'\r\n]*)'", line))
    return values


def _assignments(line: str) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for match in re.finditer(r'=\s*["\']?([^\s"\',}]+)', line):
        values.append(("assignment", match.group(1)))
    for match in re.finditer(
        r'^\s*[A-Za-z_][\w.-]*\s*:\s*["\']?([^\s"\',}]+)', line
    ):
        values.append(("yaml_value", match.group(1)))
    return values


def _url_parts(line: str) -> list[tuple[str, str]]:
    """Extract validated URL userinfo components.

    The authority is split at the final ``@`` so passwords containing a literal
    ``@`` are still attributed to the credential rather than to the host.
    """
    values: list[tuple[str, str]] = []
    for match in re.finditer(
        r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<authority>[^/\s\"'<>]+)",
        line,
    ):
        authority = match.group("authority")
        if "@" not in authority:
            continue
        userinfo, _host = authority.rsplit("@", 1)
        if ":" not in userinfo:
            continue
        user, password = userinfo.split(":", 1)
        values.extend(
            [
                ("uri_password", password),
                ("uri_userinfo", userinfo),
                ("uri", match.group(0)),
            ]
        )
        try:
            decoded = urllib.parse.unquote(password)
        except ValueError:
            decoded = None
        if decoded and decoded != password:
            values.append(("uri_password_percent_decoded", decoded))
    return values


def _base64_values(line: str, *, minimum: int = 16) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for match in re.finditer(rf"[A-Za-z0-9+/=_-]{{{minimum},}}", line):
        encoded = match.group(0)
        values.append(("base64", encoded))
        try:
            padding = "=" * ((4 - len(encoded) % 4) % 4)
            decoded = base64.b64decode(encoded + padding).decode("utf-8", "replace")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded:
            values.append(("base64_decoded", decoded))
            if ":" in decoded:
                values.append(("base64_decoded_password", decoded.split(":", 1)[1]))
    return values


def _pem_values(block: str) -> list[tuple[str, str]]:
    return [
        ("pem_block", block),
        ("pem_block_without_terminal_newline", block.rstrip("\r\n")),
        ("pem_block_stripped", block.strip()),
        ("pem_block_lf", block.replace("\r\n", "\n")),
        ("pem_block_crlf", block.replace("\n", "\r\n")),
    ]


def representation_aliases(item: dict, block: str | None) -> dict[str, str]:
    """Canonical and validated typed representations of one occurrence.

    These values are derived only from the owner-approved introduction snapshot,
    never from a later scanner-named line.  That distinction prevents a modified
    credential from being assigned to the earlier occurrence.
    """
    if block is None:
        return {}
    category = str(item["category"])
    line = "\n".join(block.splitlines())
    out: dict[str, str] = {}
    _add_digest(out, "canonical", (item.get("identity") or {}).get("secret_sha256"))
    if category == "PRIVATE_KEY":
        for label, value in _pem_values(block):
            _add(out, label, value)
        return out
    if category == "DOCKER_AUTH_CREDENTIAL":
        for label, value in _base64_values(line, minimum=20):
            _add(out, f"docker_{label}", value)
        return out
    if category == "FILEZILLA_ENCODED_PASSWORD":
        for match in re.finditer(r">([A-Za-z0-9+/=]{16,})<", line):
            encoded = match.group(1)
            _add(out, "filezilla_encoded", encoded)
            try:
                decoded = base64.b64decode(
                    encoded + "=" * ((4 - len(encoded) % 4) % 4)
                ).decode("utf-8", "replace")
            except (ValueError, UnicodeDecodeError):
                continue
            _add(out, "filezilla_decoded", decoded)
            _add(out, "filezilla_decoded_stripped", decoded.strip())
        return out
    if category == "JETBRAINS_OBFUSCATED_PASSWORD":
        for match in re.finditer(r'password="([^"]+)"', line):
            _add(out, "jetbrains_encoded_attribute", match.group(1))
        return out
    if category == "DATABASE_URI_CREDENTIAL":
        for label, value in _url_parts(line):
            _add(out, label, value)
        for label, value in _quoted(line):
            _add(out, label, value)
        return out
    if category == "APPLICATION_CREDENTIAL":
        for label, value in _url_parts(line):
            _add(out, label, value)
        if ".netrc" in str(item["source"]["path"]):
            tokens = line.split()
            if tokens:
                _add(out, "netrc_password", tokens[-1])
        for label, value in _quoted(line):
            _add(out, label, value)
        return out
    if category == "DATABASE_PASSWORD":
        for match in re.finditer(r'password="([^"]+)"', line):
            _add(out, "database_password_attribute", match.group(1))
        for match in re.finditer(
            r"^([^:\s]+):([^:\s]+):([^:\s]+):([^:\s]+):(.+)$", line
        ):
            _add(out, "pgpass_password", match.group(5))
        for label, value in _quoted(line):
            _add(out, label, value)
        for label, value in _assignments(line):
            _add(out, label, value)
        return out
    if category == "SMTP_PASSWORD":
        for match in re.finditer(r'password\s+"([^"]+)"', line):
            _add(out, "smtp_password", match.group(1))
        for label, value in _quoted(line):
            _add(out, label, value)
        return out
    for label, value in _quoted(line):
        _add(out, label, value)
    for label, value in _assignments(line):
        _add(out, label, value)
    return out


def source_candidates(block: str | None) -> dict[str, str]:
    """Source-side hashes used to prove a representation at a finding commit.

    This is intentionally broader than the approved alias set.  It is only ever
    intersected with :func:`representation_aliases`, so a username, hostname, or
    unrelated token cannot become credential credit by itself.
    """
    if block is None:
        return {}
    line = "\n".join(block.splitlines())
    out: dict[str, str] = {}
    for label, value in _pem_values(block):
        _add(out, label, value)
    for label, value in _quoted(line):
        _add(out, label, value)
    for label, value in _assignments(line):
        _add(out, label, value)
    for label, value in _url_parts(line):
        _add(out, label, value)
    for match in re.finditer(r"[^\s\"'=,<>]+", line):
        token = match.group(0)
        if len(token) >= 4:
            _add(out, "token", token)
    for label, value in _base64_values(line):
        _add(out, label, value)
    for match in re.finditer(
        r"^([^:\s]+):([^:\s]+):([^:\s]+):([^:\s]+):(.+)$", line
    ):
        _add(out, "pgpass_password", match.group(5))
    for match in re.finditer(r'password="([^"]+)"', line):
        _add(out, "password_attribute", match.group(1))
    return out


def _normalized_path(value: str) -> str:
    normalized = str(value).replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if "/scan/" in normalized:
        normalized = normalized.split("/scan/", 1)[1]
    return normalized


@dataclass
class HistorySource:
    root: Path

    def __post_init__(self) -> None:
        if not (self.root / ".git").is_dir():
            raise HistoryMatchError(f"history source is not a Git checkout: {self.root}")
        try:
            graph = self._git("rev-list", "--parents", "HEAD").decode("ascii", "replace")
        except HistoryMatchError:
            raise
        self._parents = {}
        for line in graph.splitlines():
            parts = line.split()
            if parts:
                self._parents[parts[0]] = tuple(parts[1:])
        self._reachable = frozenset(self._parents)
        self._children: dict[str, list[str]] = defaultdict(list)
        for child, parents in self._parents.items():
            for parent in parents:
                self._children[parent].append(child)
        try:
            reverse = self._git("rev-list", "--topo-order", "--reverse", "HEAD").decode(
                "ascii", "replace"
            )
            self._commit_order = {
                commit: index
                for index, commit in enumerate(
                    line.strip() for line in reverse.splitlines() if line.strip()
                )
            }
        except HistoryMatchError:
            self._commit_order = {}
        for children in self._children.values():
            children.sort(key=lambda item: self._commit_order.get(item, 10**9))
        self._ancestor_cache: dict[tuple[str, str], bool] = {}
        self._path_cache: dict[str, frozenset[str]] = {}
        self._blob_cache: dict[tuple[str, str], str | None] = {}
        self._line_map_cache: dict[tuple[str, str, str], list[tuple[int, int, int, int]]] = {}
        self._line_map_between_cache: dict[tuple[str, str, str, str], list[tuple[int, int, int, int]]] = {}
        self._lineage_cache: dict[tuple[str, str, str, int, int, tuple[str, ...], tuple[tuple[str, str, str], ...]], dict[str, tuple[tuple[str, int, int], ...]]] = {}

    def _git(self, *args: str) -> bytes:
        try:
            result = subprocess.run(
                ["git", "-C", str(self.root), *args],
                capture_output=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HistoryMatchError(f"git command failed: {exc}") from exc
        if result.returncode != 0:
            raise HistoryMatchError(
                f"git {' '.join(args)} failed: "
                f"{result.stderr.decode('utf-8', 'replace').strip()[:300]}"
            )
        return result.stdout

    def head(self) -> str:
        return self._git("rev-parse", "HEAD").decode("ascii", "replace").strip()

    def commit_rank(self, commit: str) -> int:
        return self._commit_order.get(commit, 10**9)

    def is_ancestor(self, earlier: str, later: str) -> bool:
        if not earlier or not later or later not in self._reachable:
            return False
        key = (earlier, later)
        if key in self._ancestor_cache:
            return self._ancestor_cache[key]
        pending = [later]
        seen: set[str] = set()
        found = False
        while pending:
            current = pending.pop()
            if current == earlier:
                found = True
                break
            if current in seen:
                continue
            seen.add(current)
            pending.extend(self._parents.get(current, ()))
        self._ancestor_cache[key] = found
        return found

    def paths(self, commit: str) -> frozenset[str]:
        if commit not in self._path_cache:
            try:
                listing = self._git("ls-tree", "-r", "--name-only", commit)
            except HistoryMatchError:
                self._path_cache[commit] = frozenset()
            else:
                self._path_cache[commit] = frozenset(
                    line for line in listing.decode("utf-8", "replace").splitlines() if line
                )
        return self._path_cache[commit]

    def exists(self, commit: str, path: str) -> bool:
        return bool(commit and path and path in self.paths(commit))

    def blob(self, commit: str, path: str) -> str | None:
        key = (commit, path)
        if key not in self._blob_cache:
            if not self.exists(commit, path):
                self._blob_cache[key] = None
            else:
                try:
                    data = self._git("show", f"{commit}:{path}")
                except HistoryMatchError:
                    self._blob_cache[key] = None
                else:
                    self._blob_cache[key] = data.decode("utf-8", "replace")
        return self._blob_cache[key]

    def block(self, commit: str, path: str, start: int, end: int) -> str | None:
        text = self.blob(commit, path)
        if text is None:
            return None
        lines = text.splitlines(keepends=True)
        if start < 1 or end > len(lines):
            return None
        return "".join(lines[start - 1 : end])

    def _line_hunks(self, parent: str, child: str, path: str) -> list[tuple[int, int, int, int]]:
        key = (parent, child, path)
        if key in self._line_map_cache:
            return self._line_map_cache[key]
        if not self.exists(parent, path) or not self.exists(child, path):
            self._line_map_cache[key] = []
            return []
        if self.blob(parent, path) == self.blob(child, path):
            self._line_map_cache[key] = []
            return []
        try:
            output = self._git(
                "diff",
                "--unified=0",
                "--no-color",
                "--no-ext-diff",
                "--no-renames",
                parent,
                child,
                "--",
                path,
            ).decode("utf-8", "replace")
        except HistoryMatchError:
            self._line_map_cache[key] = []
            return []
        hunks: list[tuple[int, int, int, int]] = []
        for line in output.splitlines():
            match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if not match:
                continue
            old_start = int(match.group(1))
            old_count = int(match.group(2) or "1")
            new_start = int(match.group(3))
            new_count = int(match.group(4) or "1")
            hunks.append((old_start, old_count, new_start, new_count))
        self._line_map_cache[key] = hunks
        return hunks

    def _line_hunks_between(
        self, parent: str, child: str, old_path: str, new_path: str
    ) -> list[tuple[int, int, int, int]]:
        key = (parent, child, old_path, new_path)
        if key in self._line_map_between_cache:
            return self._line_map_between_cache[key]
        if not self.exists(parent, old_path) or not self.exists(child, new_path):
            self._line_map_between_cache[key] = []
            return []
        if self.blob(parent, old_path) == self.blob(child, new_path):
            self._line_map_between_cache[key] = []
            return []
        try:
            output = self._git(
                "diff",
                "--unified=0",
                "--no-color",
                "--no-ext-diff",
                parent,
                child,
                "--",
                old_path,
                new_path,
            ).decode("utf-8", "replace")
        except HistoryMatchError:
            self._line_map_between_cache[key] = []
            return []
        hunks: list[tuple[int, int, int, int]] = []
        for output_line in output.splitlines():
            match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", output_line)
            if not match:
                continue
            hunks.append(
                (
                    int(match.group(1)),
                    int(match.group(2) or "1"),
                    int(match.group(3)),
                    int(match.group(4) or "1"),
                )
            )
        self._line_map_between_cache[key] = hunks
        return hunks

    def map_line_between(
        self, parent: str, child: str, old_path: str, new_path: str, line: int
    ) -> int | None:
        if old_path == new_path:
            return self.map_line(parent, child, old_path, line)
        if not self.exists(parent, old_path) or not self.exists(child, new_path):
            return None
        if self.blob(parent, old_path) == self.blob(child, new_path):
            return line
        hunks = self._line_hunks_between(parent, child, old_path, new_path)
        for old_start, old_count, _new_start, _new_count in hunks:
            if old_count and old_start <= line < old_start + old_count:
                return None
        delta = 0
        for old_start, old_count, _new_start, new_count in hunks:
            threshold = old_start + old_count - 1 if old_count else old_start
            if line > threshold:
                delta += new_count - old_count
        mapped = line + delta
        return mapped if mapped >= 1 else None

    def _changed_line_location_between(
        self, parent: str, child: str, old_path: str, new_path: str, line: int
    ) -> int | None:
        if old_path == new_path:
            return self._changed_line_location(parent, child, old_path, line)
        for old_start, old_count, new_start, new_count in self._line_hunks_between(
            parent, child, old_path, new_path
        ):
            if old_count == 0 or not (old_start <= line < old_start + old_count):
                continue
            if old_count != new_count:
                return None
            return new_start + (line - old_start)
        return None

    def _rename_line_location(
        self,
        parent: str,
        child: str,
        old_path: str,
        new_path: str,
        line: int,
        allowed: set[str],
    ) -> int | None:
        """Find a unique content anchor for an approved rename.

        Git's rename heuristic can fail when a moved line also gains a comment.
        Within an explicitly approved rename only, the old line may be located
        by exact content or by an unchanged non-comment code prefix. Multiple
        possible destinations are ambiguous and are rejected. No line distance
        is used.
        """
        parent_text = self.blob(parent, old_path)
        child_text = self.blob(child, new_path)
        if parent_text is None or child_text is None:
            return None
        parent_lines = parent_text.splitlines()
        child_lines = child_text.splitlines()
        if line < 1 or line > len(parent_lines):
            return None
        old_line = parent_lines[line - 1]
        old_code = _code_prefix(old_line)
        matches: list[int] = []
        for index, candidate in enumerate(child_lines, 1):
            exact = candidate == old_line
            prefix = bool(old_code) and _code_prefix(candidate) == old_code
            value_ok = (
                not allowed
                or (
                    set(source_candidates(old_line)) & allowed
                    and set(source_candidates(candidate)) & allowed
                )
            )
            if exact or (prefix and value_ok):
                matches.append(index)
        return matches[0] if len(matches) == 1 else None

    def _changed_line_location(
        self, parent: str, child: str, path: str, line: int
    ) -> int | None:
        """Return a one-to-one replacement location for a changed line.

        Only equal-size replacement hunks are accepted. Multi-line rewrites,
        additions, and deletions are ambiguous and are not lineage.
        """
        for old_start, old_count, new_start, new_count in self._line_hunks(
            parent, child, path
        ):
            if old_count == 0 or not (old_start <= line < old_start + old_count):
                continue
            if old_count != new_count:
                return None
            return new_start + (line - old_start)
        return None

    def map_line(self, parent: str, child: str, path: str, line: int) -> int | None:
        """Map an unchanged source line through one parent-to-child revision.

        A line inside a diff hunk is not mapped: insertions above it shift it,
        while a modified/deleted/added line is not the same source placement.
        This deliberately avoids an unrestricted line-distance tolerance.
        """
        if not self.exists(parent, path) or not self.exists(child, path):
            return None
        if self.blob(parent, path) == self.blob(child, path):
            return line
        hunks = self._line_hunks(parent, child, path)
        for old_start, old_count, _new_start, _new_count in hunks:
            if old_count and old_start <= line < old_start + old_count:
                return None
        delta = 0
        for old_start, old_count, _new_start, new_count in hunks:
            threshold = old_start + old_count - 1 if old_count else old_start
            if line > threshold:
                delta += new_count - old_count
        mapped = line + delta
        return mapped if mapped >= 1 else None

    def lineage_for(
        self,
        item_id: str,
        anchor_commit: str,
        path: str,
        start: int,
        end: int,
        allowed_digests: tuple[str, ...] = (),
        renames: tuple[dict, ...] = (),
    ) -> dict[str, tuple[tuple[str, int, int], ...]]:
        """Return valid unchanged-line locations of one source placement.

        The result starts at the introduction snapshot and follows only
        unchanged lines through the real commit graph. Equal-size value-preserving
        edits are accepted only when the current lineage block contains an
        approved value in both parent and child; copies, deletions,
        reintroductions, rotations, and same-value lines in other placements do
        not enter the lineage.
        """
        digest_key = tuple(sorted(set(allowed_digests)))
        rename_key = tuple(
            sorted(
                (
                    str(rename["commit"]),
                    str(rename["from"]),
                    str(rename["to"]),
                )
                for rename in renames
                if all(key in rename for key in ("commit", "from", "to"))
            )
        )
        key = (item_id, anchor_commit, path, start, end, digest_key, rename_key)
        if key in self._lineage_cache:
            return self._lineage_cache[key]
        rename_at = {
            (rename_commit, old_path): new_path
            for rename_commit, old_path, new_path in rename_key
        }
        states: dict[str, set[tuple[str, int, int]]] = {
            anchor_commit: {(path, start, end)}
        }
        allowed = set(digest_key)
        for commit in sorted(
            self._reachable, key=lambda value: self._commit_order.get(value, 10**9)
        ):
            ranges = states.get(commit)
            if not ranges:
                continue
            for child in self._children.get(commit, ()):
                for current_path, current_start, current_end in ranges:
                    target_path = rename_at.get((child, current_path), current_path)
                    if not self.exists(child, target_path):
                        continue
                    if target_path == current_path:
                        new_start = self.map_line(
                            commit, child, current_path, current_start
                        )
                        new_end = self.map_line(
                            commit, child, current_path, current_end
                        )
                    else:
                        new_start = self.map_line_between(
                            commit,
                            child,
                            current_path,
                            target_path,
                            current_start,
                        )
                        new_end = self.map_line_between(
                            commit,
                            child,
                            current_path,
                            target_path,
                            current_end,
                        )
                        if new_start is None or new_end is None:
                            new_start = self._rename_line_location(
                                commit,
                                child,
                                current_path,
                                target_path,
                                current_start,
                                allowed,
                            )
                            new_end = self._rename_line_location(
                                commit,
                                child,
                                current_path,
                                target_path,
                                current_end,
                                allowed,
                            )
                    target: tuple[int, int] | None = None
                    if (
                        new_start is not None
                        and new_end is not None
                        and new_end >= new_start
                        and self.block(child, target_path, new_start, new_end)
                    ):
                        target = (new_start, new_end)
                    elif allowed:
                        if target_path == current_path:
                            changed_start = self._changed_line_location(
                                commit, child, current_path, current_start
                            )
                            changed_end = self._changed_line_location(
                                commit, child, current_path, current_end
                            )
                        else:
                            changed_start = self._changed_line_location_between(
                                commit,
                                child,
                                current_path,
                                target_path,
                                current_start,
                            )
                            changed_end = self._changed_line_location_between(
                                commit,
                                child,
                                current_path,
                                target_path,
                                current_end,
                            )
                        if (
                            changed_start is not None
                            and changed_end is not None
                            and changed_end >= changed_start
                        ):
                            parent_block = self.block(
                                commit, current_path, current_start, current_end
                            )
                            child_block = self.block(
                                child, target_path, changed_start, changed_end
                            )
                            parent_text = (parent_block or "").rstrip("\r\n")
                            child_text = (child_block or "").rstrip("\r\n")
                            parent_code = _code_prefix(parent_text)
                            child_code = _code_prefix(child_text)
                            if (
                                parent_code
                                and parent_code == child_code
                                and parent_text != child_text
                                and set(source_candidates(parent_block)) & allowed
                                and set(source_candidates(child_block)) & allowed
                            ):
                                target = (changed_start, changed_end)
                    if target is not None:
                        states.setdefault(child, set()).add(
                            (target_path, target[0], target[1])
                        )
        result = {
            commit: tuple(sorted(ranges))
            for commit, ranges in states.items()
        }
        self._lineage_cache[key] = result
        return result


def _path_candidates(item: dict, commit: str, renames: tuple[dict, ...], source: HistorySource):
    source_item = item["source"]
    paths: list[str] = [source_item["path"]]
    current = source_item.get("current_path")
    if current and current not in paths:
        paths.append(current)
    for rename in renames:
        if rename["from"] == source_item["path"] and rename["to"] not in paths:
            try:
                rename_commit = str(rename["commit"])
            except KeyError:
                continue
            if source.is_ancestor(rename_commit, commit):
                paths.append(rename["to"])
    return [path for path in paths if source.exists(commit, path)]


def _coerce_finding(finding: NormalizedFinding | dict) -> NormalizedFinding:
    if isinstance(finding, NormalizedFinding):
        return finding
    return NormalizedFinding(
        file=str(finding.get("file") or ""),
        line=finding.get("line") if isinstance(finding.get("line"), int) else None,
        rule_id=str(finding.get("rule_id") or ""),
        secret_sha256=finding.get("secret_sha256"),
        match_sha256=finding.get("match_sha256"),
        secret_redacted=bool(finding.get("secret_redacted", False)),
        finding_id=finding.get("finding_id"),
        target=finding.get("target"),
        scanner=finding.get("scanner"),
        scanner_version=finding.get("scanner_version"),
        commit=finding.get("commit"),
        metadata=dict(finding.get("metadata") or {}),
    )


def _finding_digest(finding: NormalizedFinding) -> str | None:
    if finding.secret_sha256:
        return finding.secret_sha256
    if finding.secret_text and not finding.secret_redacted:
        return _sha(finding.secret_text)
    return None


def _item_descriptor(item: dict) -> dict:
    return {
        "finding_id": item["id"],
        "disposition": item["disposition"],
        "category": item["category"],
        "path": item["source"]["path"],
        "line_start": item["source"]["line_start"],
        "line_end": item["source"]["line_end"],
        "introduced_at": item["source"]["introduced_at"],
        "current_path": item["source"].get("current_path"),
        "unique_group": (item.get("identity") or {}).get("unique_group"),
        "review_status": "OWNER_APPROVED_FINAL",
    }


def _evaluation(
    classification: str,
    *,
    observed: dict,
    path: str | None = None,
    line: int | None = None,
    item: dict | None = None,
    reason: str,
    representation: str | None = None,
    review_status: str,
    identity_confidence: str = "value",
) -> FindingEvaluation:
    return FindingEvaluation(
        classification=classification,
        expected_id=item["id"] if item else None,
        path=path,
        line=line,
        observed=observed,
        expected=_item_descriptor(item) if item else None,
        reason=reason + (f" (representation={representation})" if representation else ""),
        identity_confidence=identity_confidence,
        review_status=review_status,
    )


def score_history(
    findings: list[NormalizedFinding] | tuple[NormalizedFinding, ...] | list[dict],
    oracle: HistoryOracle,
    source: HistorySource | str | Path,
    *,
    scope: dict | None = None,
    execution_status: str = "PASS",
) -> ScoringResult:
    """Score normalized findings against the owner-approved historical oracle.

    ``scope`` is the pinned history-scope document.  It supplies rename lineage
    and is required to avoid inventing path continuity.
    """
    source = source if isinstance(source, HistorySource) else HistorySource(Path(source))
    if execution_status != "PASS":
        classification = EXECUTION_ERROR if execution_status == "ERROR" else BLOCKED
        return ScoringResult(
            scoring_status=classification,
            execution_status=execution_status,
            metrics={"expected_count": len(oracle.positives), "execution_error": True},
            evaluations=(),
            exceptions=(
                FindingEvaluation(
                    classification=classification,
                    reason=f"history execution status was {execution_status}",
                ),
            ),
            warnings=(),
            manifest_id=oracle.oracle_id,
            manifest_version=oracle.version,
            dataset_id="leaky-repo-history",
            dataset_version=str(oracle.scope.get("head")),
            policy_id="leaky-history-source-v1",
            policy_version="1",
        )
    if oracle.validation.get("status") != "PASS":
        return ScoringResult(
            scoring_status="NOT_READY",
            execution_status=execution_status,
            metrics={"expected_count": len(oracle.positives), "reason": "oracle validation is not PASS"},
            evaluations=(),
            exceptions=(
                FindingEvaluation(
                    classification=BLOCKED,
                    reason="owner-approved history oracle is not ready",
                ),
            ),
            warnings=(),
            manifest_id=oracle.oracle_id,
            manifest_version=oracle.version,
            dataset_id="leaky-repo-history",
            dataset_version=str(oracle.scope.get("head")),
            policy_id="leaky-history-source-v1",
            policy_version="1",
        )
    renames = tuple((scope or {}).get("renames") or ())
    positives = tuple(oracle.positives)
    references = tuple(oracle.references)
    allowed_by_item: dict[str, dict[str, str]] = {}
    for item in positives:
        source_item = item["source"]
        allowed_by_item[item["id"]] = representation_aliases(
            item,
            source.block(
                source_item["introduced_at"],
                source_item["path"],
                source_item["line_start"],
                source_item["line_end"],
            ),
        )
    reference_allowed: dict[str, dict[str, str]] = {}
    for item in references:
        source_item = item["source"]
        digest = (item.get("identity") or {}).get("secret_sha256")
        if item["disposition"] == "NEGATIVE" and digest:
            # An exact-value negative certifies one extracted non-secret value,
            # not every quoted field or token on the source line.
            reference_allowed[item["id"]] = {str(digest): "exact_extracted_value"}
        else:
            reference_allowed[item["id"]] = representation_aliases(
                item,
                source.block(
                    source_item["observed_commit"],
                    source_item["path"],
                    source_item["line_start"],
                    source_item["line_end"],
                ),
            )
    candidate_cache: dict[tuple[str, str, int, int], dict[str, str]] = {}
    path_candidate_cache: dict[tuple[str, str], tuple[str, ...]] = {}

    def candidates_for(commit: str, path: str, start: int, end: int) -> dict[str, str]:
        key = (commit, path, start, end)
        if key not in candidate_cache:
            candidate_cache[key] = source_candidates(source.block(commit, path, start, end))
        return candidate_cache[key]

    def paths_for(item: dict, commit: str) -> tuple[str, ...]:
        key = (item["id"], commit)
        if key not in path_candidate_cache:
            path_candidate_cache[key] = tuple(_path_candidates(item, commit, renames, source))
        return path_candidate_cache[key]

    def mapped_ranges(
        item: dict,
        commit: str,
        candidate_path: str,
        anchor_commit: str,
        allowed: dict[str, str],
    ) -> tuple[tuple[int, int], ...]:
        source_item = item["source"]
        lineage = source.lineage_for(
            item["id"],
            anchor_commit,
            source_item["path"],
            source_item["line_start"],
            source_item["line_end"],
            tuple(allowed),
            renames,
        )
        return tuple(
            (start, end)
            for path_value, start, end in lineage.get(commit, ())
            if path_value == candidate_path
        )

    claimed: dict[str, str] = {}
    observed_count = 0
    evaluations: list[FindingEvaluation] = []
    representation_counts: Counter[str] = Counter()
    category_expected: Counter[str] = Counter()
    category_matched: Counter[str] = Counter()
    category_unique: dict[str, set[str]] = defaultdict(set)
    matched_groups: set[str] = set()
    all_groups = {item["identity"]["unique_group"] for item in positives}

    ordered: list[tuple[int, int, str, int, str, NormalizedFinding]] = []
    for index, raw in enumerate(findings):
        finding = _coerce_finding(raw)
        ordered.append(
            (
                source.commit_rank((finding.commit or "").lower()),
                index,
                _normalized_path(finding.file),
                finding.line or 0,
                _finding_digest(finding) or "",
                finding,
            )
        )
    ordered.sort(key=lambda entry: entry[:5])
    for _rank, index, _path_key, _line_key, _digest_key, finding in ordered:
        observed = finding.safe_dict()
        observed["index"] = index
        observed_count += 1
        path = _normalized_path(finding.file)
        line = finding.line
        commit = (finding.commit or "").lower()
        digest = _finding_digest(finding)
        if not path or path == ".":
            evaluations.append(
                _evaluation(
                    UNMAPPED,
                    observed=observed,
                    reason="finding has no usable file identity; mandatory source review",
                    review_status="UNMATCHED_PENDING_REVIEW",
                    identity_confidence="unverified",
                )
            )
            continue
        if not commit or not re.fullmatch(r"[0-9a-f]{40}", commit):
            evaluations.append(
                _evaluation(
                    UNMATCHED_PENDING_REVIEW,
                    observed=observed,
                    path=path,
                    line=line,
                    reason="finding has no valid commit identity for historical matching",
                    review_status="UNMATCHED_PENDING_REVIEW",
                    identity_confidence="unverified",
                )
            )
            continue
        positive_candidates: list[tuple[dict, str, str]] = []
        for item in positives:
            if not source.is_ancestor(item["source"]["introduced_at"], commit):
                continue
            if line is None:
                continue
            for candidate_path in paths_for(item, commit):
                if candidate_path != path:
                    continue
                allowed = allowed_by_item[item["id"]]
                item_added = False
                for mapped_start, mapped_end in mapped_ranges(
                    item,
                    commit,
                    candidate_path,
                    item["source"]["introduced_at"],
                    allowed,
                ):
                    if not (mapped_start <= line <= mapped_end):
                        continue
                    current_block = source.block(
                        commit,
                        candidate_path,
                        mapped_start,
                        mapped_end,
                    )
                    if not current_block:
                        continue
                    common = set(
                        candidates_for(
                            commit,
                            candidate_path,
                            mapped_start,
                            mapped_end,
                        )
                    ) & set(allowed)
                    if digest and digest in common:
                        positive_candidates.append(
                            (item, allowed[digest], candidate_path)
                        )
                        item_added = True
                        break
                if item_added:
                    break
        if len(positive_candidates) == 1:
            item, representation, _candidate_path = positive_candidates[0]
            item_id = item["id"]
            category = item["category"]
            group = item["identity"]["unique_group"]
            if item_id in claimed:
                duplicate_of = claimed[item_id]
                evaluations.append(
                    _evaluation(
                        DUPLICATE,
                        observed=observed,
                        path=path,
                        line=line,
                        item=item,
                        reason=f"occurrence was already matched by finding {duplicate_of}",
                        representation=representation,
                        review_status="DUPLICATE_OF_VERIFIED_MATCH",
                    )
                )
                representation_counts["duplicate"] += 1
                continue
            claimed[item_id] = str(observed.get("finding_id") or observed_count - 1)
            matched_groups.add(group)
            category_matched[category] += 1
            category_unique[category].add(group)
            representation_counts[representation] += 1
            evaluations.append(
                _evaluation(
                    EXPECTED_DETECTION,
                    observed=observed,
                    path=path,
                    line=line,
                    item=item,
                    reason="source-occurrence identity, commit ancestry, location and value representation match",
                    representation=representation,
                    review_status="VERIFIED_SOURCE_OCCURRENCE",
                )
            )
            continue
        if len(positive_candidates) > 1:
            evaluations.append(
                _evaluation(
                    AMBIGUOUS_MATCH,
                    observed=observed,
                    path=path,
                    line=line,
                    reason="finding matches multiple owner-approved source occurrences",
                    representation=",".join(item["id"] for item, _r, _p in positive_candidates),
                    review_status="UNMATCHED_PENDING_REVIEW",
                    identity_confidence="value",
                )
            )
            continue

        reference_candidates: list[tuple[dict, str]] = []
        for item in references:
            source_item = item["source"]
            if line is None:
                continue
            anchor_commit = source_item["observed_commit"]
            change_event = source_item.get("change_event")
            if change_event == "Removed":
                # A removed reference existed up to the observed removal
                # snapshot. A later revision is not covered by this negative.
                if not (
                    commit == anchor_commit
                    or source.is_ancestor(commit, anchor_commit)
                ):
                    continue
            elif not source.is_ancestor(anchor_commit, commit):
                continue
            for candidate_path in paths_for(item, commit):
                if candidate_path != path:
                    continue
                allowed = reference_allowed.get(item["id"]) or {}
                for mapped_start, mapped_end in mapped_ranges(
                    item,
                    commit,
                    candidate_path,
                    anchor_commit,
                    allowed,
                ):
                    if not (mapped_start <= line <= mapped_end):
                        continue
                    current_block = source.block(
                        commit,
                        candidate_path,
                        mapped_start,
                        mapped_end,
                    )
                    if not current_block:
                        continue
                    candidates = candidates_for(
                        commit,
                        candidate_path,
                        mapped_start,
                        mapped_end,
                    )
                    if allowed:
                        candidates = {
                            key: value
                            for key, value in candidates.items()
                            if key in allowed
                        }
                    if digest and digest in candidates:
                        reference_candidates.append((item, candidates[digest]))
                        break
                if reference_candidates and reference_candidates[-1][0] is item:
                    break
        if len(reference_candidates) == 1:
            item, representation = reference_candidates[0]
            kind = FALSE_POSITIVE if item["disposition"] == "NEGATIVE" else INFORMATIVE_MATCH
            evaluations.append(
                _evaluation(
                    kind,
                    observed=observed,
                    path=path,
                    line=line,
                    item=item,
                    reason=(
                        "source-verified non-secret reference value"
                        if kind == FALSE_POSITIVE
                        else "source-verified informative reference value; excluded from primary recall"
                    ),
                    representation=representation,
                    review_status=(
                        "VERIFIED_FALSE_POSITIVE"
                        if kind == FALSE_POSITIVE
                        else "INFORMATIVE_MATCH"
                    ),
                    identity_confidence="value",
                )
            )
            continue
        if len(reference_candidates) > 1:
            evaluations.append(
                _evaluation(
                    AMBIGUOUS_MATCH,
                    observed=observed,
                    path=path,
                    line=line,
                    reason="finding matches multiple reviewed non-secret/informative references",
                    representation=",".join(item["id"] for item, _r in reference_candidates),
                    review_status="UNMATCHED_PENDING_REVIEW",
                )
            )
            continue

        # Location exists in the owner-approved positive inventory but the value
        # is missing or disagrees.  That is an investigation item, not a TP.
        location_refs: list[dict] = []
        for item in positives:
            if line is None or not source.is_ancestor(
                item["source"]["introduced_at"], commit
            ):
                continue
            for candidate_path in paths_for(item, commit):
                if candidate_path != path:
                    continue
                if any(
                    start <= line <= end
                    for start, end in mapped_ranges(
                        item,
                        commit,
                        candidate_path,
                        item["source"]["introduced_at"],
                        allowed_by_item[item["id"]],
                    )
                ):
                    location_refs.append(item)
                    break
        if location_refs:
            evaluations.append(
                _evaluation(
                    UNVERIFIED_EVIDENCE,
                    observed=observed,
                    path=path,
                    line=line,
                    item=location_refs[0] if len(location_refs) == 1 else None,
                    reason="approved source location but extracted value identity is missing or conflicting",
                    review_status="UNVERIFIED_EVIDENCE",
                    identity_confidence="unverified",
                )
            )
            continue
        evaluations.append(
            _evaluation(
                UNMATCHED_PENDING_REVIEW,
                observed=observed,
                path=path,
                line=line,
                reason="no owner-approved source reference at this path, commit and line; mandatory investigation",
                review_status="UNMATCHED_PENDING_REVIEW",
                identity_confidence="unverified",
            )
        )

    matched_items = {
        item_id: item
        for item_id, item in ((item["id"], item) for item in positives)
        if item_id in claimed
    }
    for item in positives:
        category_expected[item["category"]] += 1
        if item["id"] not in claimed:
            evaluations.append(
                _evaluation(
                    MISSED_EXPECTATION,
                    observed=None,
                    path=item["source"]["path"],
                    line=item["source"]["line_start"],
                    item=item,
                    reason="no scanner observation was mapped to this source occurrence",
                    review_status="MISSED",
                    identity_confidence="line",
                )
            )
    classifications = Counter(item.classification for item in evaluations)
    unique_expected = len(all_groups)
    unique_matched = len(matched_groups)
    occurrence_expected = len(positives)
    occurrence_matched = len(matched_items)
    occurrence_missed = occurrence_expected - occurrence_matched
    pending = sum(
        item.observed is not None
        and item.classification
        in (UNMATCHED_PENDING_REVIEW, UNVERIFIED_EVIDENCE, AMBIGUOUS_MATCH, UNMAPPED)
        for item in evaluations
    )
    accounted = sum(item.observed is not None for item in evaluations)
    category_metrics: dict[str, dict] = {}
    for category in sorted(category_expected):
        expected = category_expected[category]
        found = category_matched[category]
        category_metrics[category] = {
            "expected_occurrences": expected,
            "matched_occurrences": found,
            "missed_occurrences": expected - found,
            "unique_expected": len(
                {
                    item["identity"]["unique_group"]
                    for item in positives
                    if item["category"] == category
                }
            ),
            "unique_matched": len(category_unique[category]),
            "occurrence_recall_percent": round(100.0 * found / expected, 2)
            if expected
            else None,
        }
    metrics = {
        "expected_count": occurrence_expected,
        "expected_occurrences": occurrence_expected,
        "matched_count": occurrence_matched,
        "matched_occurrences": occurrence_matched,
        "missed_count": occurrence_missed,
        "missed_occurrences": occurrence_missed,
        "unique_expected": unique_expected,
        "unique_matched": unique_matched,
        "unique_missed": unique_expected - unique_matched,
        "unique_recall_percent": round(100.0 * unique_matched / unique_expected, 2)
        if unique_expected
        else None,
        "occurrence_recall_percent": round(
            100.0 * occurrence_matched / occurrence_expected, 2
        )
        if occurrence_expected
        else None,
        "verified_false_positive_count": classifications[FALSE_POSITIVE],
        "unique_verified_nonsecret_exposure_count": len(
            {
                item.expected_id
                for item in evaluations
                if item.classification == FALSE_POSITIVE and item.expected_id
            }
        ),
        "informative_match_count": classifications[INFORMATIVE_MATCH],
        "duplicate_count": classifications[DUPLICATE],
        "unmatched_pending_review_count": classifications[UNMATCHED_PENDING_REVIEW],
        "unverified_evidence_count": classifications[UNVERIFIED_EVIDENCE],
        "ambiguous_count": classifications[AMBIGUOUS_MATCH],
        "unmapped_count": classifications[UNMAPPED],
        "observed_count": observed_count,
        "accounted_observed_count": accounted,
        "finding_accounting_reconciled": accounted == observed_count,
        "finding_review_pending_count": pending,
        "precision_percent": None,
        "f1_percent": None,
        "precision_certification_status": "BLOCKED_INCOMPLETE_NEGATIVE_ORACLE",
        "negative_oracle": False,
        "reviewed_negatives_exhaustive": False,
        "category_metrics": category_metrics,
        "representation_counts": dict(sorted(representation_counts.items())),
        "matched_occurrence_ids": sorted(matched_items),
        "missed_occurrence_ids": sorted(
            item["id"] for item in positives if item["id"] not in claimed
        ),
        "matched_unique_groups": sorted(matched_groups),
        "policy": "owner-approved source occurrences; lineage-rooted; typed value identity; exact extracted-value negatives",
        "scope": dict(oracle.scope),
        "oracle_sha256": oracle.sha256,
        "source_validation": oracle.validation.get("source_validation"),
        "execution_status": "PASS",
    }
    warnings = [
        "Reviewed negative references are not an exhaustive negative oracle; precision and F1 are not certified.",
        "Informative references are reported separately and excluded from primary recall.",
        "A finding at a later commit is mapped to the introduction occurrence through unchanged-line lineage; persistence snapshots are duplicates, not new occurrences.",
        "Same-value copies, rotations, reintroductions, and different placements are not conflated with the approved occurrence.",
        "Value-preserving edits are accepted only when the existing lineage block contains the approved value in both parent and child; a reintroduced value starts a new identity.",
        "Removed negative references match only observations at or before their observed removal snapshot.",
        "Verified false-positive alerts and unique verified nonsecret exposures are counted separately; repeated alerts at one approved negative source count once as an exposure.",
        "Unmatched and unverified findings remain in the investigation ledger.",
    ]
    if metrics["representation_counts"].get("jetbrains_encoded_attribute"):
        warnings.append(
            "JetBrains obfuscated material is credited only when the scanner hashes the "
            "validated encoded source attribute; decoded-value equivalence is not claimed."
        )
    exceptions = tuple(
        item
        for item in evaluations
        if item.classification
        in (
            MISSED_EXPECTATION,
            FALSE_POSITIVE,
            INFORMATIVE_MATCH,
            DUPLICATE,
            UNMATCHED_PENDING_REVIEW,
            UNVERIFIED_EVIDENCE,
            AMBIGUOUS_MATCH,
            UNMAPPED,
        )
    )
    return ScoringResult(
        scoring_status="COMPLETED",
        execution_status="PASS",
        metrics=metrics,
        evaluations=tuple(evaluations),
        exceptions=exceptions,
        warnings=tuple(warnings),
        manifest_id=oracle.oracle_id,
        manifest_version=oracle.version,
        dataset_id="leaky-repo-history",
        dataset_version=str(oracle.scope.get("head")),
        policy_id="leaky-history-source-v1",
        policy_version="1",
    )
