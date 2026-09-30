"""Orchestrates detectors, classifier and scanners for one scan."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Sequence

from .allowlist import NameMatcher, PathMatcher
from .classifiers import RiskClassifier
from .config import AppConfig
from .detectors import DetectionEngine, build_engine
from .logging_utils import redact_text
from .models import Finding, ScanResult, ScanStats, ScanTarget
from .scanners import BaseScanner, DatabaseAdapter, FileScanner, PostgresScanner, S3Scanner

log = logging.getLogger(__name__)


class ScanRunner:
    def __init__(
        self,
        config: AppConfig,
        *,
        db_adapter: DatabaseAdapter | None = None,
        s3_client: Any | None = None,
    ) -> None:
        self.config = config
        self.engine: DetectionEngine = build_engine(config.detectors)
        self.classifier = RiskClassifier(config.risk_levels)
        self._db_adapter = db_adapter
        self._s3_client = s3_client
        if not self.engine.detector_names:
            raise ValueError("no detectors are enabled")

    def build_scanner(self, source: str) -> BaseScanner:
        cfg = self.config
        allow = cfg.allowlist
        if source == "file" and cfg.file:
            return FileScanner(
                self.engine,
                self.classifier,
                cfg.file,
                PathMatcher(allow.paths),
                cfg.threads,
                executor=cfg.executor,
            )
        if source == "postgres" and cfg.postgres:
            return PostgresScanner(
                self.engine,
                self.classifier,
                cfg.postgres,
                table_allowlist=NameMatcher(allow.tables),
                column_allowlist=NameMatcher(allow.columns),
                threads=cfg.threads,
                adapter=self._db_adapter,
            )
        if source == "s3" and cfg.s3:
            return S3Scanner(
                self.engine,
                self.classifier,
                cfg.s3,
                key_allowlist=PathMatcher(allow.s3_keys),
                threads=cfg.threads,
                client=self._s3_client,
            )
        raise ValueError(f"source {source!r} is not configured")

    def run(self, sources: Sequence[str], dry_run: bool = False) -> ScanResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        targets: list[ScanTarget] = []
        stats = ScanStats()
        failed: list[str] = []

        for source in sources:
            scanner = self.build_scanner(source)
            log.info("%s %s source", "planning" if dry_run else "scanning", source)
            try:
                if dry_run:
                    targets.extend(scanner.plan())
                else:
                    findings.extend(scanner.scan())
            except Exception as exc:  # a broken source must not hide the others
                message = redact_text(f"{source}: {type(exc).__name__}: {_first_line(exc)}")
                failed.append(message)
                log.error("source failed: %s", message)
            finally:
                stats.merge(scanner.stats)

        findings.sort(key=Finding.sort_key)
        return ScanResult(
            findings=findings,
            stats=stats,
            sources=list(sources),
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            dry_run=dry_run,
            targets=targets,
            failed_sources=failed,
        )


def _first_line(exc: BaseException) -> str:
    text = str(exc).strip()
    return (text.splitlines()[0] if text else "")[:300]
