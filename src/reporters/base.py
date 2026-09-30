"""Reporter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar

from ..models import ScanResult


class BaseReporter(ABC):
    """Renders a :class:`ScanResult`. Reporters only ever see masked findings."""

    #: Short identifier used by ``--output`` (``console``, ``json``, ``csv``).
    format: ClassVar[str]

    @abstractmethod
    def report(self, result: ScanResult) -> Path | None:
        """Render the result; return the file written, if any."""
