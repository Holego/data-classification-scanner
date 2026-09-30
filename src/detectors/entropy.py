"""Shannon entropy helper used to spot randomly generated secrets."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(text: str) -> float:
    """Entropy of ``text`` in bits per character (0.0 for an empty string)."""
    if not text:
        return 0.0
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in Counter(text).values())
