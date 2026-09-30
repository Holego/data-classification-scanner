"""CSV report."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, ClassVar

from ..models import Finding, ScanResult
from .base import BaseReporter

COLUMNS = (
    "source_type",
    "source",
    "data_type",
    "subtype",
    "category",
    "risk",
    "line",
    "offset",
    "column_name",
    "row",
    "row_id",
    "masked_value",
)

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_cell(value: Any) -> Any:
    """Neutralise spreadsheet formula injection.

    Sources such as file names or S3 keys are attacker-influenced, and masked
    values can start with ``+`` or ``-``. Excel and LibreOffice would evaluate
    those cells as formulas, so text starting with a trigger character gets a
    leading apostrophe.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return "" if value is None else value


def finding_row(finding: Finding) -> list[Any]:
    loc = finding.location
    values = [
        finding.source_type,
        finding.source,
        finding.data_type,
        finding.subtype,
        finding.category,
        finding.risk.value,
        loc.line,
        loc.offset,
        loc.column_name,
        loc.row,
        loc.row_id,
        finding.masked_value,
    ]
    return [sanitize_cell(v) for v in values]


class CsvReporter(BaseReporter):
    format: ClassVar[str] = "csv"

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def report(self, result: ScanResult) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(COLUMNS)
            for finding in result.findings:
                writer.writerow(finding_row(finding))
        return self.path
