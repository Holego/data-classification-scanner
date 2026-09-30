"""Allowlist matching for paths, S3 keys and database objects.

Things that match an allowlist entry are never opened, read or queried.
"""

from __future__ import annotations

import fnmatch
import re
from functools import lru_cache
from typing import Iterable


@lru_cache(maxsize=256)
def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a gitignore-like glob to a regex.

    ``*`` and ``?`` stay inside one path segment, ``**`` crosses segments, and a
    trailing ``/**`` also matches the directory itself.
    """
    suffix = ""
    if pattern.endswith("/**"):
        pattern, suffix = pattern[:-3], "(?:/.*)?"
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            if pattern.startswith("**", i):
                if pattern[i + 2 : i + 3] == "/":
                    out.append("(?:.*/)?")
                    i += 3
                else:
                    out.append(".*")
                    i += 2
            else:
                out.append("[^/]*")
                i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        elif ch == "[" and "]" in pattern[i + 1 :]:
            end = pattern.index("]", i + 1)
            body = pattern[i + 1 : end].replace("\\", "\\\\")
            if body.startswith("!"):
                body = "^" + body[1:]
            out.append(f"[{body}]")
            i = end + 1
        else:
            out.append(re.escape(ch))
            i += 1
    return re.compile("".join(out) + suffix + r"\Z", re.DOTALL)


def _normalise(path: str) -> str:
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path.rstrip("/") or "/"


class PathMatcher:
    """Matches file paths or object keys against glob patterns.

    A pattern containing ``/`` is matched against the whole (relative or
    absolute) path; a pattern without ``/`` is matched against every path
    segment, so ``.git`` or ``*.min.json`` work at any depth.
    """

    def __init__(self, patterns: Iterable[str] = ()) -> None:
        self._segment: list[re.Pattern[str]] = []
        self._full: list[re.Pattern[str]] = []
        for raw in patterns:
            pattern = _normalise(str(raw))
            target = self._full if "/" in pattern else self._segment
            target.append(glob_to_regex(pattern))

    def __bool__(self) -> bool:
        return bool(self._segment or self._full)

    def matches(self, relative: str, absolute: str | None = None) -> bool:
        """True if the path is allowlisted.

        Slash-less (segment) patterns look only at ``relative`` so that a scan
        root such as ``/tmp/x`` is not excluded by a pattern named ``tmp``;
        patterns containing ``/`` are tried against both forms.
        """
        rel = _normalise(relative)
        candidates = [rel] if absolute is None else [rel, _normalise(absolute)]
        if any(rx.match(path) for rx in self._full for path in candidates):
            return True
        if self._segment:
            return any(rx.match(seg) for seg in rel.split("/") if seg for rx in self._segment)
        return False


class NameMatcher:
    """Case-insensitive glob matching for ``schema.table`` / ``table.column`` names."""

    def __init__(self, patterns: Iterable[str] = ()) -> None:
        self._patterns = [str(p).lower() for p in patterns]

    def __bool__(self) -> bool:
        return bool(self._patterns)

    def matches(self, *names: str) -> bool:
        lowered = [n.lower() for n in names]
        return any(fnmatch.fnmatchcase(n, p) for p in self._patterns for n in lowered)
