"""Detector interface and the match record detectors produce."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar, Iterator


@dataclass(frozen=True)
class Match:
    """A raw detection inside a piece of text.

    ``value`` is the unmasked string and must never leave the process: it is
    excluded from ``repr`` so it cannot leak through logs or tracebacks, and the
    engine converts it to a masked string before anything is reported.
    """

    detector: str
    value: str = field(repr=False)
    start: int = 0
    end: int = 0
    subtype: str | None = None


class BaseDetector(ABC):
    """Finds one kind of sensitive data in text and knows how to mask it."""

    #: Stable identifier used in configuration, reports and classification.
    name: ClassVar[str]
    description: ClassVar[str] = ""
    #: When two detectors match overlapping text the lower number wins.
    priority: ClassVar[int] = 100

    @abstractmethod
    def detect(self, text: str) -> Iterator[Match]:
        """Yield every validated match found in ``text``."""

    @abstractmethod
    def mask(self, value: str, subtype: str | None = None) -> str:
        """Return a representation of ``value`` that is safe to report."""


class RegexDetector(BaseDetector):
    """Base class for detectors built around one compiled regular expression.

    Subclasses provide ``pattern`` and may override ``validate`` to reject
    candidates that merely look right (checksums, structural rules, ...).
    """

    pattern: ClassVar[re.Pattern[str]]

    def validate(self, value: str, text: str, match: re.Match[str]) -> bool:
        return True

    def subtype_of(self, value: str) -> str | None:
        return None

    def detect(self, text: str) -> Iterator[Match]:
        for m in self.pattern.finditer(text):
            value = m.group(0)
            if self.validate(value, text, m):
                yield Match(self.name, value, m.start(), m.end(), self.subtype_of(value))


def mask_keep_last(value: str, keep: int = 4, mask_char: str = "*") -> str:
    """Mask every letter and digit except the last ``keep``; keep separators.

    ``123-45-6789`` -> ``***-**-6789``
    """
    total = sum(ch.isalnum() for ch in value)
    to_hide = max(total - keep, 0)
    out: list[str] = []
    seen = 0
    for ch in value:
        if ch.isalnum():
            out.append(mask_char if seen < to_hide else ch)
            seen += 1
        else:
            out.append(ch)
    return "".join(out)
