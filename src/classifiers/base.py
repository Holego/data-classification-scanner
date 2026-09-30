"""Classifier interface."""

from __future__ import annotations

from typing import Protocol

from .risk import Classification


class Classifier(Protocol):
    def classify(self, data_type: str, subtype: str | None = None) -> Classification: ...
