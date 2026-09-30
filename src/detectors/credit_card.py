"""Payment card number detector.

A candidate is only reported when it (1) has the length and prefix of a known
card scheme and (2) passes the Luhn checksum. Cards may be written as a plain
digit run or in groups separated by single spaces or dashes.
"""

from __future__ import annotations

import re
from typing import ClassVar, Iterator

from .base import BaseDetector, Match
from .luhn import luhn_check

# Scheme name -> full-match pattern over the digits only.
_SCHEMES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("visa", re.compile(r"4\d{15}(?:\d{3})?")),
    (
        "mastercard",
        re.compile(r"(?:5[1-5]\d{2}|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)\d{12}"),
    ),
    ("amex", re.compile(r"3[47]\d{13}")),
    ("discover", re.compile(r"(?:6011|65\d{2}|64[4-9]\d)\d{12}")),
    ("diners", re.compile(r"3(?:0[0-5]|[689]\d)\d{11}")),
    ("jcb", re.compile(r"35(?:2[89]|[3-8]\d)\d{12}(?:\d{1,3})?")),
    ("unionpay", re.compile(r"62\d{14,17}")),
    ("maestro", re.compile(r"(?:5018|5020|5038|5893|6304|6759|676[1-3])\d{8,15}")),
    ("mir", re.compile(r"220[0-4]\d{12}(?:\d{1,3})?")),
)

# Maximal runs of digits joined by at most one space or dash.
_RUN = re.compile(r"\d(?:[ -]?\d)*")
_GROUP = re.compile(r"\d+")

_MIN_DIGITS = 13
_MAX_DIGITS = 19


def identify_scheme(digits: str) -> str | None:
    """Return the card scheme whose length/prefix rules match ``digits``."""
    for name, pattern in _SCHEMES:
        if pattern.fullmatch(digits):
            return name
    return None


def _is_ascii_alnum(ch: str) -> bool:
    return ch.isascii() and ch.isalnum()


def _plausible_grouping(groups: list[tuple[str, int, int]]) -> bool:
    """Cards are printed in blocks of >= 4 digits (the last may hold 3)."""
    if len(groups) == 1:
        return True
    return all(len(g[0]) >= 4 for g in groups[:-1]) and len(groups[-1][0]) >= 3


def mask_card_number(value: str) -> str:
    """``4111 1111 1111 1111`` -> ``**** **** **** 1111`` (last four kept)."""
    digits = "".join(ch for ch in value if ch.isdigit())
    masked = "*" * max(len(digits) - 4, 0) + digits[-4:]
    if len(digits) == 15:  # American Express prints 4-6-5
        sizes = (4, 6, 5)
    elif len(digits) == 14:  # Diners Club prints 4-6-4
        sizes = (4, 6, 4)
    else:  # groups of four stars, then the last four digits as their own group
        hidden = len(digits) - 4
        sizes = tuple([4] * (hidden // 4) + ([hidden % 4] if hidden % 4 else []) + [4])
    parts: list[str] = []
    pos = 0
    for size in sizes:
        parts.append(masked[pos : pos + size])
        pos += size
    return " ".join(part for part in parts if part)


class CreditCardDetector(BaseDetector):
    name: ClassVar[str] = "credit_card"
    description: ClassVar[str] = "Payment card numbers (scheme prefix + Luhn checksum)"
    priority: ClassVar[int] = 10

    def detect(self, text: str) -> Iterator[Match]:
        for run in _RUN.finditer(text):
            start, end = run.span()
            if end - start < _MIN_DIGITS:
                continue
            groups = [
                (g.group(), start + g.start(), start + g.end())
                for g in _GROUP.finditer(run.group())
            ]
            # A digit run glued to letters/digits (order12345..., 4111...abc) is
            # part of a longer identifier, not a card number.
            if start > 0 and _is_ascii_alnum(text[start - 1]):
                groups = groups[1:]
            if end < len(text) and _is_ascii_alnum(text[end]):
                groups = groups[:-1]
            yield from self._scan_groups(text, groups)

    def _scan_groups(
        self, text: str, groups: list[tuple[str, int, int]]
    ) -> Iterator[Match]:
        i = 0
        while i < len(groups):
            digits = ""
            found: tuple[int, str, str] | None = None
            for j in range(i, len(groups)):
                digits += groups[j][0]
                if len(digits) > _MAX_DIGITS:
                    break
                if len(digits) < _MIN_DIGITS or not _plausible_grouping(groups[i : j + 1]):
                    continue
                scheme = identify_scheme(digits)
                if scheme and luhn_check(digits):
                    found = (j, scheme, digits)
                    break
            if found is None:
                i += 1
                continue
            j, scheme, _ = found
            span_start, span_end = groups[i][1], groups[j][2]
            yield Match(self.name, text[span_start:span_end], span_start, span_end, scheme)
            i = j + 1

    def mask(self, value: str, subtype: str | None = None) -> str:
        return mask_card_number(value)
