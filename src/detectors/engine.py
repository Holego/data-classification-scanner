"""Runs a set of detectors over text and resolves overlapping matches."""

from __future__ import annotations

import bisect
from typing import Sequence

from .base import BaseDetector, Match


class DetectionEngine:
    def __init__(self, detectors: Sequence[BaseDetector]) -> None:
        names = [d.name for d in detectors]
        if len(set(names)) != len(names):
            raise ValueError(f"duplicate detector names: {sorted(names)}")
        self._detectors = tuple(sorted(detectors, key=lambda d: d.priority))
        self._by_name = {d.name: d for d in self._detectors}

    @property
    def detector_names(self) -> list[str]:
        return [d.name for d in self._detectors]

    def find(self, text: str) -> list[Match]:
        """All matches in ``text``, ordered by position.

        When detectors overlap (a card number that also looks like a phone
        number) the detector with the lowest ``priority`` value keeps the span.
        """
        if not text:
            return []
        candidates: list[Match] = []
        for detector in self._detectors:
            candidates.extend(detector.detect(text))
        if len(candidates) < 2:
            return candidates

        accepted: list[Match] = []
        starts: list[int] = []
        # Candidates arrive in detector-priority order, so higher-priority
        # detectors claim their spans first.
        for match in candidates:
            pos = bisect.bisect_left(starts, match.start)
            if pos > 0 and accepted[pos - 1].end > match.start:
                continue
            if pos < len(accepted) and accepted[pos].start < match.end:
                continue
            accepted.insert(pos, match)
            starts.insert(pos, match.start)
        return accepted

    def mask(self, match: Match) -> str:
        return self._by_name[match.detector].mask(match.value, match.subtype)

    def redact(self, text: str) -> str:
        """Replace every detected value in ``text`` with its masked form."""
        matches = self.find(text)
        if not matches:
            return text
        out: list[str] = []
        cursor = 0
        for match in matches:
            out.append(text[cursor : match.start])
            out.append(self.mask(match))
            cursor = match.end
        out.append(text[cursor:])
        return "".join(out)
