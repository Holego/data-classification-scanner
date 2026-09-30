"""Phone number detector.

Deliberately conservative: bare digit strings are never reported. A number must
either carry an international ``+`` prefix, follow the North American
``(212) 555-0123`` / ``212-555-0123`` layout, or the Russian ``8 (912) 345-67-89``
layout, and the digit count must be plausible (E.164 allows 8-15 digits).
"""

from __future__ import annotations

import re
from typing import ClassVar

from .base import RegexDetector, mask_keep_last

_PHONE = re.compile(
    r"""
    (?<![\w+])
    (?:
        \+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}     # +CC ...
      | (?:\+?1[\s.-]?)?\(?[2-9]\d{2}\)?[\s.-]\d{3}[\s.-]\d{4}   # NANP
      | 8[\s-]?\(\d{3}\)[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}         # RU trunk 8
    )
    (?![\w-])
    """,
    re.VERBOSE,
)


class PhoneDetector(RegexDetector):
    name: ClassVar[str] = "phone"
    description: ClassVar[str] = "Phone numbers (E.164-style, North American, Russian)"
    priority: ClassVar[int] = 70
    pattern: ClassVar[re.Pattern[str]] = _PHONE

    def validate(self, value: str, text: str, match: re.Match[str]) -> bool:
        digits = [ch for ch in value if ch.isdigit()]
        if not 8 <= len(digits) <= 15:
            return False
        # Repeated single digit (0000000000) is a placeholder, not a number.
        return len(set(digits)) > 2

    def mask(self, value: str, subtype: str | None = None) -> str:
        return mask_keep_last(value, keep=4)
