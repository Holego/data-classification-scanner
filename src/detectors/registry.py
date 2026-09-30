"""Builds detector instances from the ``detectors`` section of the config."""

from __future__ import annotations

from typing import Any, Callable, Mapping

from .api_key import ApiKeyDetector
from .base import BaseDetector
from .credit_card import CreditCardDetector
from .email import EmailDetector
from .engine import DetectionEngine
from .ip_address import IPAddressDetector
from .national_id import IdPattern, NationalIdDetector
from .phone import PhoneDetector

Factory = Callable[[Mapping[str, Any]], BaseDetector]


def _national_id(options: Mapping[str, Any]) -> BaseDetector:
    profiles = options.get("profiles", ["us_ssn"])
    custom = [IdPattern.from_config(raw) for raw in options.get("custom_patterns", []) or []]
    return NationalIdDetector(profiles=profiles or [], custom_patterns=custom)


def _api_key(options: Mapping[str, Any]) -> BaseDetector:
    return ApiKeyDetector(
        entropy_threshold=float(options.get("entropy_threshold", 4.0)),
        min_length=int(options.get("min_length", 20)),
        detect_generic=bool(options.get("detect_generic", True)),
    )


FACTORIES: dict[str, Factory] = {
    "credit_card": lambda opts: CreditCardDetector(),
    "email": lambda opts: EmailDetector(ignore_domains=opts.get("ignore_domains", []) or []),
    "national_id": _national_id,
    "phone": lambda opts: PhoneDetector(),
    "ip_address": lambda opts: IPAddressDetector(ignore_private=bool(opts.get("ignore_private", False))),
    "api_key": _api_key,
}

#: Detectors switched on when the config does not mention them. Phone numbers and
#: IP addresses are opt-in because they are noisy in logs and free text.
DEFAULT_ENABLED: dict[str, bool] = {
    "credit_card": True,
    "email": True,
    "national_id": True,
    "api_key": True,
    "phone": False,
    "ip_address": False,
}


def build_detectors(settings: Mapping[str, Mapping[str, Any]] | None = None) -> list[BaseDetector]:
    """Instantiate the enabled detectors.

    ``settings`` maps detector name -> options (``enabled`` plus detector
    specific keys). Unknown names raise ``ValueError``.
    """
    settings = settings or {}
    unknown = set(settings) - set(FACTORIES)
    if unknown:
        raise ValueError(
            f"unknown detector(s): {', '.join(sorted(unknown))} "
            f"(available: {', '.join(sorted(FACTORIES))})"
        )
    detectors: list[BaseDetector] = []
    for name, factory in FACTORIES.items():
        options = settings.get(name) or {}
        if options.get("enabled", DEFAULT_ENABLED[name]):
            detectors.append(factory(options))
    return detectors


def build_engine(settings: Mapping[str, Mapping[str, Any]] | None = None) -> DetectionEngine:
    return DetectionEngine(build_detectors(settings))


def build_redaction_engine() -> DetectionEngine:
    """Engine used to scrub log output: every detector that is safe to run
    on arbitrary text, independent of what the current scan has enabled."""
    return build_engine(
        {name: {"enabled": True} for name in ("credit_card", "email", "national_id", "api_key", "phone")}
    )
