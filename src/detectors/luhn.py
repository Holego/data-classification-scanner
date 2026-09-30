"""Luhn (mod 10) checksum.

Payment card numbers carry a Luhn check digit, so roughly 9 out of 10 random
digit strings of card length fail it. Requiring it removes the bulk of false
positives (order numbers, timestamps, IDs) that a bare 16-digit regex produces.
"""

from __future__ import annotations

_SEPARATORS = " -"


def luhn_check(number: str) -> bool:
    """Return True if ``number`` passes the Luhn checksum.

    Spaces and dashes are ignored. Anything else that is not a digit, or fewer
    than two digits, is rejected.
    """
    digits = number.translate({ord(c): None for c in _SEPARATORS})
    if len(digits) < 2 or not digits.isascii() or not digits.isdigit():
        return False

    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = ord(char) - 48
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0
