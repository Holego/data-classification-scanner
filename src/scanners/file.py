"""Local filesystem scanner."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Iterator

from ..allowlist import PathMatcher
from ..classifiers import Classifier
from ..config import FileSourceConfig
from ..detectors import DetectionEngine
from ..models import Finding, ScanStats, ScanTarget, TargetResult
from ._concurrency import bounded_map
from .base import BaseScanner
from .text import BinaryContentError, decode_lines, read_chunks, scan_text_source

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Candidate:
    path: Path
    relative: str
    size: int


class FileScanner(BaseScanner):
    """Recursively scans text-like files (extension allowlist) in parallel."""

    source_type: ClassVar[str] = "file"

    def __init__(
        self,
        engine: DetectionEngine,
        classifier: Classifier,
        config: FileSourceConfig,
        allowlist: PathMatcher | None = None,
        threads: int = 1,
    ) -> None:
        super().__init__(engine, classifier, threads)
        self.config = config
        self.allowlist = allowlist or PathMatcher()
        self._max_bytes = int(config.max_file_size_mb * 1024 * 1024)

    # -- enumeration -----------------------------------------------------

    def _roots(self) -> Iterator[Path]:
        if not self.config.paths:
            raise ValueError("file source has no paths to scan")
        for raw in self.config.paths:
            root = Path(raw)
            if not root.exists():
                raise FileNotFoundError(f"scan path does not exist: {raw}")
            yield root

    def _candidates(self) -> Iterator[_Candidate]:
        for root in self._roots():
            if root.is_file():
                yield from self._consider(root, root.name)
                continue
            for dirpath, dirnames, filenames in os.walk(root, followlinks=self.config.follow_symlinks):
                base = Path(dirpath)
                rel_dir = base.relative_to(root).as_posix()
                dirnames[:] = sorted(
                    d for d in dirnames if not self._allowlisted(base / d, _join(rel_dir, d))
                )
                for name in sorted(filenames):
                    yield from self._consider(base / name, _join(rel_dir, name))

    def _allowlisted(self, path: Path, relative: str) -> bool:
        return bool(self.allowlist) and self.allowlist.matches(relative, str(path.absolute()))

    def _consider(self, path: Path, relative: str) -> Iterator[_Candidate]:
        if path.suffix.lower() not in self.config.extensions:
            return
        if self._allowlisted(path, relative):
            self.stats.skipped += 1
            log.debug("allowlisted: %s", self.safe_name(str(path)))
            return
        if path.is_symlink() and not self.config.follow_symlinks:
            self.stats.skipped += 1
            return
        try:
            size = path.stat().st_size
        except OSError as exc:
            self.stats.errors.append(f"{self.safe_name(str(path))}: {exc.strerror or type(exc).__name__}")
            return
        if size > self._max_bytes:
            self.stats.skipped += 1
            log.info("skipped (larger than %s MB): %s", self.config.max_file_size_mb, self.safe_name(str(path)))
            return
        yield _Candidate(path, relative, size)

    def plan(self) -> Iterator[ScanTarget]:
        for candidate in self._candidates():
            yield ScanTarget(self.source_type, self.safe_name(str(candidate.path)), candidate.size)

    # -- scanning --------------------------------------------------------

    def scan(self) -> Iterator[Finding]:
        for result in bounded_map(self._scan_file, self._candidates(), self.threads):
            self.stats.merge(result.stats)
            yield from result.findings

    def _scan_file(self, candidate: _Candidate) -> TargetResult:
        path = candidate.path
        source = self.safe_name(str(path))
        result = TargetResult(stats=ScanStats())
        try:
            def open_lines() -> Iterator[str]:
                with open(path, "rb") as handle:
                    yield from decode_lines(read_chunks(handle))

            findings, lines = scan_text_source(
                self, source, open_lines, is_csv=path.suffix.lower() == ".csv"
            )
        except BinaryContentError:
            result.stats.skipped += 1
            log.debug("skipped binary file: %s", source)
            return result
        except OSError as exc:
            result.stats.errors.append(f"{source}: {exc.strerror or type(exc).__name__}")
            log.warning("cannot read %s: %s", source, exc.strerror or type(exc).__name__)
            return result

        result.findings = findings
        result.stats.files_scanned = 1
        result.stats.lines_scanned = lines
        result.stats.bytes_scanned = candidate.size
        log.debug("scanned %s: %d line(s), %d finding(s)", source, lines, len(findings))
        return result


def _join(directory: str, name: str) -> str:
    return name if directory in ("", ".") else f"{directory}/{name}"
