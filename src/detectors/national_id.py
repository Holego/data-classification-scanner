"""Configurable national identifier detector (SSN and look-alikes).

Each identifier type is an :class:`IdPattern`: a regular expression, an optional
structural/checksum validator and optional context keywords ("SSN", "INN", ...)
that must appear near the match. A handful of country profiles ship built in;
any other country can be added from the YAML config with a custom regex.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, ClassVar, Iterable, Iterator, Mapping

from .base import BaseDetector, Match, mask_keep_last
from .luhn import luhn_check

Validator = Callable[[str], bool]


@dataclass(frozen=True)
class IdPattern:
    name: str
    regex: re.Pattern[str]
    validator: Validator | None = None
    keep_last: int = 4
    context_keywords: tuple[str, ...] = ()
    context_window: int = 40

    @classmethod
    def from_config(cls, raw: Mapping[str, object]) -> IdPattern:
        try:
            name = str(raw["name"])
            pattern = str(raw["regex"])
        except KeyError as exc:
            raise ValueError(f"national_id custom pattern is missing {exc.args[0]!r}") from None
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"national_id pattern {name!r}: invalid regex ({exc})") from None
        validator_name = raw.get("validator")
        validator = None
        if validator_name:
            validator = VALIDATORS.get(str(validator_name))
            if validator is None:
                known = ", ".join(sorted(VALIDATORS))
                raise ValueError(
                    f"national_id pattern {name!r}: unknown validator {validator_name!r} "
                    f"(known: {known})"
                )
        keywords = raw.get("context_keywords") or ()
        if isinstance(keywords, str):
            keywords = (keywords,)
        return cls(
            name=name,
            regex=compiled,
            validator=validator,
            keep_last=int(raw.get("keep_last", 4)),  # type: ignore[arg-type]
            context_keywords=tuple(str(k).lower() for k in keywords),  # type: ignore[union-attr]
            context_window=int(raw.get("context_window", 40)),  # type: ignore[arg-type]
        )


# --------------------------------------------------------------------------
# Validators. Each receives the matched text (separators included).
# --------------------------------------------------------------------------


def _digits(value: str) -> str:
    return "".join(ch for ch in value if ch.isdigit())


def validate_us_ssn(value: str) -> bool:
    """Reject numbers the SSA never issues (area 000/666/9xx, group 00, serial 0000)."""
    digits = _digits(value)
    if len(digits) != 9:
        return False
    area, group, serial = int(digits[:3]), int(digits[3:5]), int(digits[5:])
    return not (area == 0 or area == 666 or area >= 900 or group == 0 or serial == 0)


def validate_ca_sin(value: str) -> bool:
    digits = _digits(value)
    return len(digits) == 9 and digits[0] not in "08" and luhn_check(digits)


def validate_ru_inn(value: str) -> bool:
    digits = [int(c) for c in _digits(value)]
    if len(digits) == 10:
        weights = (2, 4, 10, 3, 5, 9, 4, 6, 8)
        return sum(w * d for w, d in zip(weights, digits)) % 11 % 10 == digits[9]
    if len(digits) == 12:
        w11 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        w12 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        c11 = sum(w * d for w, d in zip(w11, digits)) % 11 % 10
        c12 = sum(w * d for w, d in zip(w12, digits)) % 11 % 10
        return c11 == digits[10] and c12 == digits[11]
    return False


def validate_ru_snils(value: str) -> bool:
    digits = _digits(value)
    if len(digits) != 11 or int(digits[:9]) <= 1001998:
        return False
    total = sum(int(d) * w for d, w in zip(digits[:9], range(9, 0, -1)))
    if total < 100:
        check = total
    elif total in (100, 101):
        check = 0
    else:
        check = total % 101
        if check in (100, 101):
            check = 0
    return check == int(digits[9:])


def validate_pl_pesel(value: str) -> bool:
    digits = _digits(value)
    if len(digits) != 11:
        return False
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    check = (10 - sum(w * int(d) for w, d in zip(weights, digits[:10])) % 10) % 10
    return check == int(digits[10])


def validate_br_cpf(value: str) -> bool:
    digits = _digits(value)
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    for length in (9, 10):
        total = sum(int(d) * w for d, w in zip(digits[:length], range(length + 1, 1, -1)))
        check = (total * 10 % 11) % 10
        if check != int(digits[length]):
            return False
    return True


VALIDATORS: dict[str, Validator] = {
    "us_ssn": validate_us_ssn,
    "ca_sin": validate_ca_sin,
    "ru_inn": validate_ru_inn,
    "ru_snils": validate_ru_snils,
    "pl_pesel": validate_pl_pesel,
    "br_cpf": validate_br_cpf,
    "luhn": luhn_check,
}


# --------------------------------------------------------------------------
# Built-in country profiles.
# --------------------------------------------------------------------------


def _p(name: str, regex: str, validator: str | None = None, **kwargs: object) -> IdPattern:
    return IdPattern(
        name=name,
        regex=re.compile(regex),
        validator=VALIDATORS[validator] if validator else None,
        **kwargs,  # type: ignore[arg-type]
    )


PROFILES: dict[str, tuple[IdPattern, ...]] = {
    # United States: XXX-XX-XXXX
    "us_ssn": (_p("us_ssn", r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])", "us_ssn"),),
    # Canada: XXX-XXX-XXX or XXX XXX XXX, Luhn-checked
    "ca_sin": (_p("ca_sin", r"(?<![\d-])\d{3}([ -])\d{3}\1\d{3}(?![\d-])", "ca_sin"),),
    # United Kingdom National Insurance number: AB 12 34 56 C
    "uk_nino": (
        _p(
            "uk_nino",
            r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]"
            r"(?: ?\d{2}){3} ?[A-D]\b",
            keep_last=3,
        ),
    ),
    # Russia INN (10/12 digits) - bare digit strings need a nearby keyword
    "ru_inn": (
        _p(
            "ru_inn",
            r"(?<!\d)(?:\d{12}|\d{10})(?!\d)",
            "ru_inn",
            keep_last=2,
            context_keywords=("инн", "inn", "tax id"),
        ),
    ),
    # Russia SNILS: formatted form stands alone, bare 11 digits need context
    "ru_snils": (
        _p("ru_snils", r"(?<!\d)\d{3}-\d{3}-\d{3}[ -]\d{2}(?!\d)", "ru_snils", keep_last=2),
        _p(
            "ru_snils",
            r"(?<!\d)\d{11}(?!\d)",
            "ru_snils",
            keep_last=2,
            context_keywords=("снилс", "snils"),
        ),
    ),
    # Poland PESEL: 11 digits with checksum, needs context
    "pl_pesel": (
        _p(
            "pl_pesel",
            r"(?<!\d)\d{11}(?!\d)",
            "pl_pesel",
            keep_last=2,
            context_keywords=("pesel",),
        ),
    ),
    # Brazil CPF: XXX.XXX.XXX-XX, or bare 11 digits with context
    "br_cpf": (
        _p("br_cpf", r"(?<![\d.])\d{3}\.\d{3}\.\d{3}-\d{2}(?!\d)", "br_cpf", keep_last=2),
        _p(
            "br_cpf",
            r"(?<!\d)\d{11}(?!\d)",
            "br_cpf",
            keep_last=2,
            context_keywords=("cpf",),
        ),
    ),
}


def mask_national_id(value: str, keep_last: int = 4) -> str:
    """``123-45-6789`` -> ``***-**-6789``."""
    return mask_keep_last(value, keep=keep_last)


class NationalIdDetector(BaseDetector):
    name: ClassVar[str] = "national_id"
    description: ClassVar[str] = "National identifiers (SSN and country-specific IDs)"
    priority: ClassVar[int] = 20

    def __init__(
        self,
        profiles: Iterable[str] = ("us_ssn",),
        custom_patterns: Iterable[IdPattern] = (),
    ) -> None:
        patterns: list[IdPattern] = []
        for profile in profiles:
            if profile not in PROFILES:
                known = ", ".join(sorted(PROFILES))
                raise ValueError(f"unknown national_id profile {profile!r} (known: {known})")
            patterns.extend(PROFILES[profile])
        patterns.extend(custom_patterns)
        self._patterns = tuple(patterns)
        self._keep_last = {p.name: p.keep_last for p in patterns}

    @property
    def pattern_names(self) -> list[str]:
        return sorted({p.name for p in self._patterns})

    def detect(self, text: str) -> Iterator[Match]:
        for pattern in self._patterns:
            for m in pattern.regex.finditer(text):
                value = m.group(0)
                if pattern.validator and not pattern.validator(value):
                    continue
                if pattern.context_keywords and not _has_context(text, m.start(), m.end(), pattern):
                    continue
                yield Match(self.name, value, m.start(), m.end(), pattern.name)

    def mask(self, value: str, subtype: str | None = None) -> str:
        return mask_national_id(value, self._keep_last.get(subtype or "", 4))


def _has_context(text: str, start: int, end: int, pattern: IdPattern) -> bool:
    """True if a context keyword appears within the window on either side."""
    window = pattern.context_window
    around = (text[max(0, start - window) : start] + " " + text[end : end + window]).lower()
    return any(keyword in around for keyword in pattern.context_keywords)
