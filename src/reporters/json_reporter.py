"""JSON report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

from .. import __version__
from ..models import ScanResult
from .base import BaseReporter


def build_report(result: ScanResult) -> dict[str, Any]:
    """The JSON document written by :class:`JsonReporter`."""
    report: dict[str, Any] = {
        "scan": {
            "tool": "data-classification-scanner",
            "version": __version__,
            "started_at": result.started_at.isoformat(),
            "finished_at": result.finished_at.isoformat(),
            "duration_seconds": round(result.duration_seconds, 3),
            "dry_run": result.dry_run,
            "sources": result.sources,
        },
        "summary": result.summary(),
        "errors": result.stats.errors,
        "failed_sources": result.failed_sources,
        "findings": [f.to_dict() for f in result.findings],
    }
    if result.dry_run:
        report["targets"] = [t.to_dict() for t in result.targets]
    return report


class JsonReporter(BaseReporter):
    format: ClassVar[str] = "json"

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def report(self, result: ScanResult) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as handle:
            json.dump(build_report(result), handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        return self.path
