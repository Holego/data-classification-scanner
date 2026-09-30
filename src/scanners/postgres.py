"""PostgreSQL scanner: reads table columns in batches over server-side cursors."""

from __future__ import annotations

import logging
import os
import re
import uuid
from abc import ABC, abstractmethod
from typing import Any, ClassVar, Iterator, Sequence

from ..allowlist import NameMatcher
from ..classifiers import Classifier
from ..config import PostgresSourceConfig, TableSpec
from ..detectors import DetectionEngine
from ..models import Finding, ScanStats, ScanTarget, TargetResult
from ._concurrency import bounded_map
from .base import BaseScanner

log = logging.getLogger(__name__)

_UUID_TEXT = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
_LIBPQ_HINT_VARS = ("PGHOST", "PGDATABASE", "PGSERVICE", "PGUSER", "PGPASSFILE")


def quote_ident(name: str) -> str:
    """Quote an SQL identifier (valid for PostgreSQL and SQLite)."""
    if not name or "\x00" in name:
        raise ValueError(f"invalid SQL identifier: {name!r}")
    return '"' + name.replace('"', '""') + '"'


class DatabaseAdapter(ABC):
    """The small set of database operations the scanner needs.

    Keeping them behind an interface lets the scanner run unchanged against
    PostgreSQL in production and against SQLite in unit tests.
    """

    @abstractmethod
    def connect(self) -> Any: ...

    @abstractmethod
    def list_text_columns(self, conn: Any, schema: str, table: str) -> list[str]: ...

    @abstractmethod
    def primary_key(self, conn: Any, schema: str, table: str) -> str | None: ...

    @abstractmethod
    def qualified_name(self, schema: str, table: str) -> str: ...

    @abstractmethod
    def stream(self, conn: Any, sql: str, batch_size: int) -> Iterator[list[Sequence[Any]]]: ...

    def close(self, conn: Any) -> None:
        conn.close()


class PsycopgAdapter(DatabaseAdapter):
    """PostgreSQL via psycopg 3. Connection settings come from libpq
    environment variables (PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD,
    PGSSLMODE, ...) or ~/.pgpass; nothing is read from the YAML config."""

    def connect(self) -> Any:
        import psycopg

        if not any(name in os.environ for name in _LIBPQ_HINT_VARS):
            raise RuntimeError(
                "PostgreSQL connection is configured through environment variables: set "
                "PGHOST, PGPORT, PGDATABASE, PGUSER and PGPASSWORD (see .env.example)"
            )
        conn = psycopg.connect(connect_timeout=10, application_name="data-classification-scanner")
        conn.read_only = True  # the scanner never writes
        return conn

    def list_text_columns(self, conn: Any, schema: str, table: str) -> list[str]:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT column_name FROM information_schema.columns
                WHERE table_schema = %s AND table_name = %s
                  AND (data_type IN ('text', 'character varying', 'character', 'json', 'jsonb', 'xml')
                       OR udt_name = 'citext')
                ORDER BY ordinal_position
                """,
                (schema, table),
            )
            return [row[0] for row in cur.fetchall()]

    def primary_key(self, conn: Any, schema: str, table: str) -> str | None:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT a.attname
                FROM pg_index i
                JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
                WHERE i.indrelid = %s::regclass AND i.indisprimary
                """,
                (self.qualified_name(schema, table),),
            )
            rows = cur.fetchall()
        return rows[0][0] if len(rows) == 1 else None

    def qualified_name(self, schema: str, table: str) -> str:
        return f"{quote_ident(schema)}.{quote_ident(table)}"

    def stream(self, conn: Any, sql: str, batch_size: int) -> Iterator[list[Sequence[Any]]]:
        # A named cursor is a server-side cursor: rows are fetched batch by
        # batch instead of loading the whole table into memory.
        with conn.cursor(name=f"dcscan_{uuid.uuid4().hex[:12]}") as cur:
            cur.execute(sql)
            while True:
                rows = cur.fetchmany(batch_size)
                if not rows:
                    return
                yield rows


class PostgresScanner(BaseScanner):
    source_type: ClassVar[str] = "postgres"

    def __init__(
        self,
        engine: DetectionEngine,
        classifier: Classifier,
        config: PostgresSourceConfig,
        table_allowlist: NameMatcher | None = None,
        column_allowlist: NameMatcher | None = None,
        threads: int = 1,
        adapter: DatabaseAdapter | None = None,
    ) -> None:
        super().__init__(engine, classifier, threads)
        self.config = config
        self.table_allowlist = table_allowlist or NameMatcher()
        self.column_allowlist = column_allowlist or NameMatcher()
        self.adapter = adapter or PsycopgAdapter()

    # -- enumeration -----------------------------------------------------

    def _tables(self) -> Iterator[tuple[str, TableSpec]]:
        if not self.config.tables:
            raise ValueError("postgres source has no tables to scan")
        for spec in self.config.tables:
            schema = spec.schema or self.config.schema
            if self.table_allowlist.matches(f"{schema}.{spec.name}", spec.name):
                self.stats.skipped += 1
                log.debug("allowlisted table: %s.%s", schema, spec.name)
                continue
            yield schema, spec

    def plan(self) -> Iterator[ScanTarget]:
        for schema, spec in self._tables():
            columns = ", ".join(spec.columns) if spec.columns else "all text-like columns (auto-discovered)"
            yield ScanTarget(self.source_type, f"{schema}.{spec.name}", None, f"columns: {columns}")

    # -- scanning --------------------------------------------------------

    def scan(self) -> Iterator[Finding]:
        tables = list(self._tables())
        # Fail fast on bad credentials/connectivity instead of once per table.
        self.adapter.close(self.adapter.connect())
        for result in bounded_map(lambda item: self._scan_table(*item), tables, self.threads):
            self.stats.merge(result.stats)
            yield from result.findings

    def _scan_table(self, schema: str, spec: TableSpec) -> TargetResult:
        table = spec.name
        result = TargetResult(stats=ScanStats())
        label = f"{schema}.{table}"
        conn = None
        try:
            conn = self.adapter.connect()
            columns = list(spec.columns) or self.adapter.list_text_columns(conn, schema, table)
            if not columns:
                raise LookupError("no text-like columns found (does the table exist?)")
            columns = [c for c in columns if not self._column_allowlisted(schema, table, c)]
            if not columns:
                result.stats.skipped += 1
                return result

            key = spec.id_column or self.adapter.primary_key(conn, schema, table)
            select = ([quote_ident(key)] if key else []) + [
                f"CAST({quote_ident(c)} AS TEXT)" for c in columns
            ]
            sql = f"SELECT {', '.join(select)} FROM {self.adapter.qualified_name(schema, table)}"

            rows = 0
            for batch in self.adapter.stream(conn, sql, self.config.batch_size):
                for record in batch:
                    rows += 1
                    row_id = _format_row_id(record[0]) if key else None
                    values = record[1:] if key else record
                    for column, value in zip(columns, values):
                        if value:
                            result.findings.extend(
                                self.inspect(
                                    str(value),
                                    f"{label}.{column}",
                                    column_name=column,
                                    row=rows,
                                    row_id=row_id,
                                )
                            )
            result.stats.tables_scanned = 1
            result.stats.rows_scanned = rows
            log.debug("scanned %s: %d row(s), %d finding(s)", label, rows, len(result.findings))
        except Exception as exc:  # one broken table must not abort the others
            message = self.safe_name(f"{label}: {type(exc).__name__}: {_first_line(exc)}")
            result.stats.errors.append(message)
            log.warning("table scan failed: %s", message)
        finally:
            if conn is not None:
                try:
                    self.adapter.close(conn)
                except Exception:  # pragma: no cover - best effort
                    pass
        return result

    def _column_allowlisted(self, schema: str, table: str, column: str) -> bool:
        return bool(self.column_allowlist) and self.column_allowlist.matches(
            f"{schema}.{table}.{column}", f"{table}.{column}", column
        )


def _format_row_id(value: Any) -> str | None:
    """Row ids are reported only when they are plain integers or UUIDs, so a
    text primary key (an email, a name) can never leak into a report."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, uuid.UUID)):
        return str(value)
    if isinstance(value, str) and _UUID_TEXT.fullmatch(value):
        return value
    return None


def _first_line(exc: BaseException) -> str:
    text = str(exc).strip()
    return (text.splitlines()[0] if text else "")[:300]
