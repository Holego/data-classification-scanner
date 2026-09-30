"""Core data structures shared by scanners, classifiers and reporters.

Nothing in this module carries a raw sensitive value: a ``Finding`` only
holds the masked representation produced by the detector that found it.
"""

from __future__ import annotations

import enum
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class RiskLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def rank(self) -> int:
        return _RISK_RANK[self]

    def at_least(self, other: RiskLevel) -> bool:
        return self.rank >= other.rank

    @classmethod
    def parse(cls, value: str | RiskLevel) -> RiskLevel:
        if isinstance(value, RiskLevel):
            return value
        try:
            return cls(str(value).strip().upper())
        except ValueError:
            valid = ", ".join(level.value for level in cls)
            raise ValueError(f"unknown risk level {value!r} (expected one of: {valid})") from None


_RISK_RANK = {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3}


@dataclass(frozen=True)
class Location:
    """Where inside a source a value was found.

    ``line`` is 1-based. ``offset`` is the 1-based character offset inside the
    scanned unit (a line, a CSV field or a database cell). ``column_name`` is a
    CSV header or a database column, ``row`` the 1-based scan-order ordinal of a
    database row and ``row_id`` its primary key when that is a plain integer or
    UUID.
    """

    line: int | None = None
    offset: int | None = None
    column_name: str | None = None
    row: int | None = None
    row_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "line": self.line,
            "offset": self.offset,
            "column_name": self.column_name,
            "row": self.row,
            "row_id": self.row_id,
        }

    def describe(self, compact: bool = False) -> str:
        """Human-readable position; ``compact`` is the console table form."""
        if compact:
            parts: list[str] = []
            if self.row is not None:
                parts.append(f"row {self.row}" + (f" id={self.row_id}" if self.row_id else ""))
            if self.line is not None:
                parts.append(f"{self.line}:{self.offset}" if self.offset else str(self.line))
            elif self.offset is not None and self.row is None:
                parts.append(f":{self.offset}")
            if self.column_name is not None:
                parts.append(f"[{self.column_name}]")
            return " ".join(parts) or "-"
        parts = []
        if self.row is not None:
            parts.append(f"row {self.row}" + (f" (id={self.row_id})" if self.row_id else ""))
        if self.line is not None:
            parts.append(f"line {self.line}")
        if self.column_name is not None:
            parts.append(f"column '{self.column_name}'")
        if self.offset is not None:
            parts.append(f"offset {self.offset}")
        return ", ".join(parts) or "-"


@dataclass(frozen=True)
class Finding:
    """A single classified detection. Contains the masked value only."""

    source_type: str
    source: str
    data_type: str
    subtype: str | None
    category: str
    risk: RiskLevel
    location: Location
    masked_value: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_type": self.source_type,
            "source": self.source,
            "data_type": self.data_type,
            "subtype": self.subtype,
            "category": self.category,
            "risk": self.risk.value,
            "location": self.location.to_dict(),
            "masked_value": self.masked_value,
        }

    def sort_key(self) -> tuple[Any, ...]:
        loc = self.location
        return (
            self.source_type,
            self.source,
            loc.row or 0,
            loc.line or 0,
            loc.offset or 0,
            self.data_type,
        )


@dataclass(frozen=True)
class ScanTarget:
    """One unit a scanner would read (file, object, table). Used by --dry-run."""

    source_type: str
    name: str
    size_bytes: int | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_type": self.source_type,
            "name": self.name,
            "size_bytes": self.size_bytes,
            "detail": self.detail,
        }


@dataclass
class ScanStats:
    files_scanned: int = 0
    lines_scanned: int = 0
    objects_scanned: int = 0
    tables_scanned: int = 0
    rows_scanned: int = 0
    bytes_scanned: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)

    _COUNTERS = (
        "files_scanned",
        "lines_scanned",
        "objects_scanned",
        "tables_scanned",
        "rows_scanned",
        "bytes_scanned",
        "skipped",
    )

    def merge(self, other: ScanStats) -> None:
        for name in self._COUNTERS:
            setattr(self, name, getattr(self, name) + getattr(other, name))
        self.errors.extend(other.errors)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {name: getattr(self, name) for name in self._COUNTERS}
        data["errors"] = len(self.errors)
        return data


@dataclass
class TargetResult:
    """What a worker returns after scanning one file, object or table."""

    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)


@dataclass
class ScanResult:
    findings: list[Finding]
    stats: ScanStats
    sources: list[str]
    started_at: datetime
    finished_at: datetime
    dry_run: bool = False
    targets: list[ScanTarget] = field(default_factory=list)
    failed_sources: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    def count_by_type(self) -> Counter[str]:
        return Counter(f.data_type for f in self.findings)

    def count_by_risk(self) -> Counter[str]:
        return Counter(f.risk.value for f in self.findings)

    def count_by_source_type(self) -> Counter[str]:
        return Counter(f.source_type for f in self.findings)

    def highest_risk(self) -> RiskLevel | None:
        if not self.findings:
            return None
        return max((f.risk for f in self.findings), key=lambda r: r.rank)

    def summary(self) -> dict[str, Any]:
        by_type = self.count_by_type()
        by_risk = self.count_by_risk()
        return {
            "total_findings": len(self.findings),
            "by_risk": {lvl.value: by_risk.get(lvl.value, 0) for lvl in reversed(list(RiskLevel))},
            "by_type": dict(sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0]))),
            "by_source_type": dict(sorted(self.count_by_source_type().items())),
            "sources_with_findings": len({(f.source_type, f.source) for f in self.findings}),
            "scanned": self.stats.to_dict(),
        }
