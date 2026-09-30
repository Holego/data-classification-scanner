"""Shared fixtures and helpers.

Secret-looking test values are assembled at runtime instead of being written as
literals, so repository secret scanners do not mistake fixtures for leaks.
"""

from __future__ import annotations

import random
import string

import pytest

from dcscanner.classifiers import RiskClassifier
from dcscanner.detectors import build_engine

ALL_DETECTORS = {
    "credit_card": {"enabled": True},
    "email": {"enabled": True},
    "national_id": {"enabled": True},
    "phone": {"enabled": True},
    "ip_address": {"enabled": True},
    "api_key": {"enabled": True},
}


def luhn_check_digit(partial: str) -> str:
    total = 0
    for index, char in enumerate(reversed(partial)):
        digit = int(char)
        if index % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return str((10 - total % 10) % 10)


def make_luhn(prefix: str, length: int, seed: int = 7) -> str:
    """A Luhn-valid number of ``length`` digits starting with ``prefix``."""
    rng = random.Random(seed)
    body = prefix + "".join(rng.choice(string.digits) for _ in range(length - len(prefix) - 1))
    return body + luhn_check_digit(body)


def random_token(length: int, seed: int = 1, alphabet: str = string.ascii_letters + string.digits) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(alphabet) for _ in range(length))


@pytest.fixture
def engine():
    return build_engine(ALL_DETECTORS)


@pytest.fixture
def classifier():
    return RiskClassifier()
