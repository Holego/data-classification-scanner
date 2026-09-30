"""API key / token detector.

Two complementary strategies:

* well-known provider formats (AWS, GitHub, Slack, Stripe, Google, JWT, PEM
  private key headers) matched by prefix and length - high confidence;
* a generic high-entropy string heuristic for everything else - tunable, and
  intentionally strict about what looks like a random token (no hex digests,
  UUIDs, plain words or single-class strings).
"""

from __future__ import annotations

import re
from typing import ClassVar, Iterator

from .base import BaseDetector, Match
from .entropy import shannon_entropy

_PROVIDER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])")),
    ("github_token", re.compile(r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9])")),
    (
        "github_fine_grained_token",
        re.compile(r"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{22,255}(?![A-Za-z0-9_])"),
    ),
    ("slack_token", re.compile(r"(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9-]{10,}")),
    ("stripe_key", re.compile(r"(?<![A-Za-z0-9])[sr]k_live_[A-Za-z0-9]{16,}")),
    ("google_api_key", re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])")),
    (
        "jwt",
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
        ),
    ),
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")),
)

_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_\-]{20,}={0,2}(?![A-Za-z0-9+/_\-])")
_HEX_ONLY = re.compile(r"[0-9a-fA-F]+")
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

GENERIC = "high_entropy_string"


def _is_camel_case(token: str) -> bool:
    """CamelCase words put a lowercase letter after almost every capital;
    random tokens do so only about 40% of the time."""
    uppers = [i for i, c in enumerate(token) if c.isupper()]
    if len(uppers) < 2:
        return False
    followed = sum(1 for i in uppers if i + 1 < len(token) and token[i + 1].islower())
    return followed / len(uppers) >= 0.8


class ApiKeyDetector(BaseDetector):
    name: ClassVar[str] = "api_key"
    description: ClassVar[str] = "API keys, tokens and private-key headers (provider formats + entropy)"
    priority: ClassVar[int] = 30

    def __init__(
        self,
        entropy_threshold: float = 4.0,
        min_length: int = 20,
        max_length: int = 200,
        detect_generic: bool = True,
    ) -> None:
        self.entropy_threshold = entropy_threshold
        self.min_length = min_length
        self.max_length = max_length
        self.detect_generic = detect_generic

    def detect(self, text: str) -> Iterator[Match]:
        taken: list[tuple[int, int]] = []
        for subtype, pattern in _PROVIDER_PATTERNS:
            for m in pattern.finditer(text):
                taken.append(m.span())
                yield Match(self.name, m.group(0), m.start(), m.end(), subtype)

        if not self.detect_generic or len(text) < self.min_length:
            return
        for m in _CANDIDATE.finditer(text):
            if any(m.start() < end and start < m.end() for start, end in taken):
                continue
            if self._looks_like_secret(m.group(0)):
                yield Match(self.name, m.group(0), m.start(), m.end(), GENERIC)

    def _looks_like_secret(self, token: str) -> bool:
        if not self.min_length <= len(token) <= self.max_length:
            return False
        if _HEX_ONLY.fullmatch(token) or _UUID.fullmatch(token):
            return False  # hashes, commit ids and UUIDs are identifiers, not secrets
        has_digit = any(c.isdigit() for c in token)
        has_lower = any(c.islower() for c in token)
        has_upper = any(c.isupper() for c in token)
        if not has_digit or not (has_lower or has_upper):
            return False
        if token.count("-") + token.count("_") > len(token) // 3:
            return False  # slug-like: my-long-descriptive-name-2024
        if _is_camel_case(token):
            return False  # identifiers such as getUserAccountDetails2
        return shannon_entropy(token) >= self.entropy_threshold

    def mask(self, value: str, subtype: str | None = None) -> str:
        if subtype == "private_key":
            return "-----BEGIN PRIVATE KEY----- [redacted]"
        keep = 2 if subtype == GENERIC else 4
        return value[:keep] + "*" * 8
