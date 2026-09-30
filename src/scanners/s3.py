"""AWS S3 scanner: streams objects under a bucket/prefix, in parallel."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, ClassVar, Iterator

from botocore.exceptions import BotoCoreError, ClientError

from ..allowlist import PathMatcher
from ..classifiers import Classifier
from ..config import S3SourceConfig
from ..detectors import DetectionEngine
from ..models import Finding, ScanStats, ScanTarget, TargetResult
from ._concurrency import bounded_map
from .base import BaseScanner
from .text import CHUNK_SIZE, BinaryContentError, decode_lines, scan_text_source

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class _S3Object:
    key: str
    size: int


class S3Scanner(BaseScanner):
    """Scans text-like objects below ``bucket/prefix``.

    Credentials are never handled here: the boto3 client is created with the
    default credentials chain (environment, shared config/SSO profiles, IAM
    roles), so nothing secret is read from the YAML config or logged.
    """

    source_type: ClassVar[str] = "s3"

    def __init__(
        self,
        engine: DetectionEngine,
        classifier: Classifier,
        config: S3SourceConfig,
        key_allowlist: PathMatcher | None = None,
        threads: int = 1,
        client: Any | None = None,
    ) -> None:
        super().__init__(engine, classifier, threads)
        self.config = config
        self.key_allowlist = key_allowlist or PathMatcher()
        self._client = client
        self._max_bytes = int(config.max_object_size_mb * 1024 * 1024)

    def _get_client(self) -> Any:
        if self._client is None:
            import boto3
            from botocore.config import Config

            session = boto3.session.Session(region_name=self.config.region)
            self._client = session.client(
                "s3",
                endpoint_url=self.config.endpoint_url,
                config=Config(
                    retries={"max_attempts": 5, "mode": "standard"},
                    max_pool_connections=max(10, self.threads),
                    user_agent_extra="data-classification-scanner",
                ),
            )
        return self._client

    # -- enumeration -----------------------------------------------------

    def _objects(self) -> Iterator[_S3Object]:
        if not self.config.bucket:
            raise ValueError("s3 source needs a bucket name")
        paginator = self._get_client().get_paginator("list_objects_v2")
        pages = paginator.paginate(
            Bucket=self.config.bucket,
            Prefix=self.config.prefix,
            PaginationConfig={"PageSize": self.config.page_size},
        )
        for page in pages:
            for obj in page.get("Contents", []):
                key, size = obj["Key"], obj["Size"]
                if key.endswith("/") or size == 0:
                    continue  # folder placeholder / empty object
                if PurePosixPath(key).suffix.lower() not in self.config.extensions:
                    continue
                if self.key_allowlist and self.key_allowlist.matches(key):
                    self.stats.skipped += 1
                    log.debug("allowlisted key: %s", self.safe_name(key))
                    continue
                if size > self._max_bytes:
                    self.stats.skipped += 1
                    log.info(
                        "skipped (larger than %s MB): %s",
                        self.config.max_object_size_mb,
                        self.safe_name(key),
                    )
                    continue
                yield _S3Object(key, size)

    def _uri(self, key: str) -> str:
        return self.safe_name(f"s3://{self.config.bucket}/{key}")

    def plan(self) -> Iterator[ScanTarget]:
        for obj in self._objects():
            yield ScanTarget(self.source_type, self._uri(obj.key), obj.size)

    # -- scanning --------------------------------------------------------

    def scan(self) -> Iterator[Finding]:
        for result in bounded_map(self._scan_object, self._objects(), self.threads):
            self.stats.merge(result.stats)
            yield from result.findings

    def _scan_object(self, obj: _S3Object) -> TargetResult:
        source = self._uri(obj.key)
        result = TargetResult(stats=ScanStats())
        client = self._get_client()

        def open_lines() -> Iterator[str]:
            body = client.get_object(Bucket=self.config.bucket, Key=obj.key)["Body"]
            try:
                yield from decode_lines(body.iter_chunks(CHUNK_SIZE))
            finally:
                body.close()

        try:
            findings, lines = scan_text_source(
                self, source, open_lines, is_csv=obj.key.lower().endswith(".csv")
            )
        except BinaryContentError:
            result.stats.skipped += 1
            return result
        except (ClientError, BotoCoreError) as exc:
            code = exc.response.get("Error", {}).get("Code") if isinstance(exc, ClientError) else None
            reason = code or type(exc).__name__
            result.stats.errors.append(f"{source}: {reason}")
            log.warning("cannot read %s: %s", source, reason)
            return result

        result.findings = findings
        result.stats.objects_scanned = 1
        result.stats.lines_scanned = lines
        result.stats.bytes_scanned = obj.size
        log.debug("scanned %s: %d line(s), %d finding(s)", source, lines, len(findings))
        return result
