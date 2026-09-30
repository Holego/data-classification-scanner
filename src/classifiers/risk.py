"""Maps detected data types to a risk level and a data category."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from ..models import RiskLevel


@dataclass(frozen=True)
class Classification:
    risk: RiskLevel
    category: str


DEFAULT_CLASSIFICATION: dict[str, Classification] = {
    "credit_card": Classification(RiskLevel.HIGH, "PCI"),
    "national_id": Classification(RiskLevel.HIGH, "PII"),
    "api_key": Classification(RiskLevel.HIGH, "Credentials"),
    "email": Classification(RiskLevel.MEDIUM, "PII"),
    "phone": Classification(RiskLevel.MEDIUM, "PII"),
    "ip_address": Classification(RiskLevel.LOW, "Network"),
}

_FALLBACK = Classification(RiskLevel.MEDIUM, "Unclassified")


class RiskClassifier:
    """Assigns risk levels to findings.

    ``overrides`` maps either a data type (``email``) or a ``data_type.subtype``
    pair (``national_id.uk_nino``) to a risk level; the more specific key wins.
    """

    def __init__(self, overrides: Mapping[str, RiskLevel | str] | None = None) -> None:
        self._overrides = {key: RiskLevel.parse(level) for key, level in (overrides or {}).items()}

    def classify(self, data_type: str, subtype: str | None = None) -> Classification:
        base = DEFAULT_CLASSIFICATION.get(data_type, _FALLBACK)
        for key in (f"{data_type}.{subtype}" if subtype else None, data_type):
            if key and key in self._overrides:
                return Classification(self._overrides[key], base.category)
        return base
