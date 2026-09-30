"""Email address detector with top-level-domain validation."""

from __future__ import annotations

import re
from typing import ClassVar, Iterable, Iterator

from ._tlds import VALID_TLDS
from .base import BaseDetector, Match

_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9._%+\-])"
    r"[A-Za-z0-9._%+\-]{1,64}"
    r"@"
    r"(?:[A-Za-z0-9\-]{1,63}\.)+"
    r"[A-Za-z0-9\-]{2,63}"
)
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?")


def is_valid_email(candidate: str) -> bool:
    """Structural checks (RFC 5321 limits) plus a top-level-domain lookup."""
    local, _, domain = candidate.rpartition("@")
    if not local or not domain or len(candidate) > 254:
        return False
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    if not all(len(lbl) <= 63 and _LABEL.fullmatch(lbl) for lbl in labels):
        return False
    return labels[-1].lower() in VALID_TLDS


def _longest_valid_prefix(candidate: str) -> str | None:
    """The candidate itself, or the longest prefix of its domain labels that is a
    valid address - so ``jane@example.com.txt`` (an export named after its
    owner) still yields ``jane@example.com`` while ``logo@2x.png`` yields nothing."""
    local, _, domain = candidate.rpartition("@")
    labels = domain.split(".")
    while len(labels) >= 2:
        attempt = f"{local}@{'.'.join(labels)}"
        if is_valid_email(attempt):
            return attempt
        labels.pop()
    return None


def mask_email(value: str) -> str:
    """``jane.doe@example.com`` -> ``j***@example.com``."""
    local, _, domain = value.rpartition("@")
    if not local:
        return "*" * len(value)
    return f"{local[0]}{'*' * min(max(len(local) - 1, 2), 6)}@{domain}"


class EmailDetector(BaseDetector):
    name: ClassVar[str] = "email"
    description: ClassVar[str] = "Email addresses with a delegated top-level domain"
    priority: ClassVar[int] = 40

    def __init__(self, ignore_domains: Iterable[str] = ()) -> None:
        self._ignore = {d.lower().lstrip("@") for d in ignore_domains}

    def detect(self, text: str) -> Iterator[Match]:
        if "@" not in text:
            return
        for m in _CANDIDATE.finditer(text):
            value = _longest_valid_prefix(m.group(0))
            if value is None:
                continue
            if self._ignore and value.rpartition("@")[2].lower() in self._ignore:
                continue
            yield Match(self.name, value, m.start(), m.start() + len(value))

    def mask(self, value: str, subtype: str | None = None) -> str:
        return mask_email(value)
