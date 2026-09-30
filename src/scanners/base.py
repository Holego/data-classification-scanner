"""Scanner interface shared by every data source."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar, Iterator

from ..classifiers import Classifier
from ..detectors import DetectionEngine, build_redaction_engine
from ..models import Finding, Location, ScanStats, ScanTarget


class BaseScanner(ABC):
    """A data source that can be enumerated (``plan``) and read (``scan``).

    Concrete scanners decide how to walk their source and which unit each
    worker handles (a file, an S3 object, a table); they hand text to
    :meth:`inspect`, which is the single place where raw matches are turned
    into masked, classified findings.
    """

    source_type: ClassVar[str]

    def __init__(
        self,
        engine: DetectionEngine,
        classifier: Classifier,
        threads: int = 1,
    ) -> None:
        self.engine = engine
        self.classifier = classifier
        self.threads = max(1, threads)
        self.stats = ScanStats()

    @abstractmethod
    def plan(self) -> Iterator[ScanTarget]:
        """Enumerate what :meth:`scan` would read, without reading any content."""

    @abstractmethod
    def scan(self) -> Iterator[Finding]:
        """Read the source and yield findings. ``self.stats`` is updated as it runs."""

    def safe_name(self, name: str) -> str:
        """Mask sensitive values that appear inside a path, key or table name."""
        return build_redaction_engine().redact(name)

    def inspect(
        self,
        text: str,
        source: str,
        *,
        line: int | None = None,
        column_name: str | None = None,
        row: int | None = None,
        row_id: str | None = None,
    ) -> list[Finding]:
        """Run detection and classification on ``text`` and build findings."""
        findings: list[Finding] = []
        for match in self.engine.find(text):
            classification = self.classifier.classify(match.detector, match.subtype)
            findings.append(
                Finding(
                    source_type=self.source_type,
                    source=source,
                    data_type=match.detector,
                    subtype=match.subtype,
                    category=classification.category,
                    risk=classification.risk,
                    location=Location(
                        line=line,
                        offset=match.start + 1,
                        column_name=column_name,
                        row=row,
                        row_id=row_id,
                    ),
                    masked_value=self.engine.mask(match),
                )
            )
        return findings
