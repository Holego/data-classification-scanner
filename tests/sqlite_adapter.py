"""SQLite stand-in for the PostgreSQL adapter, used by scanner unit tests."""

from __future__ import annotations

import sqlite3
from typing import Any, Iterator, Sequence

from dcscanner.scanners import DatabaseAdapter, quote_ident

_TEXT_TYPES = ("TEXT", "VARCHAR", "CHAR", "CLOB", "JSON")


class SQLiteAdapter(DatabaseAdapter):
    def __init__(self, path: str) -> None:
        self.path = path
        self.connections = 0

    def connect(self) -> sqlite3.Connection:
        self.connections += 1
        return sqlite3.connect(self.path)

    def _table_info(self, conn: Any, table: str) -> list[tuple]:
        return conn.execute(f"PRAGMA table_info({quote_ident(table)})").fetchall()

    def list_text_columns(self, conn: Any, schema: str, table: str) -> list[str]:
        return [r[1] for r in self._table_info(conn, table) if str(r[2]).upper().startswith(_TEXT_TYPES)]

    def primary_key(self, conn: Any, schema: str, table: str) -> str | None:
        keys = [r[1] for r in self._table_info(conn, table) if r[5]]
        return keys[0] if len(keys) == 1 else None

    def qualified_name(self, schema: str, table: str) -> str:
        return quote_ident(table)

    def stream(self, conn: Any, sql: str, batch_size: int) -> Iterator[list[Sequence[Any]]]:
        cursor = conn.execute(sql)
        while True:
            rows = cursor.fetchmany(batch_size)
            if not rows:
                return
            yield rows


class NoConnectAdapter(SQLiteAdapter):
    """Fails the test if the scanner touches the database (used for --dry-run)."""

    def connect(self) -> Any:
        raise AssertionError("dry run must not open a database connection")
