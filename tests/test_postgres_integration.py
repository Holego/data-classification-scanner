"""Runs the scanner against a live PostgreSQL.

Skipped unless PGHOST/PGDATABASE (and normally PGUSER/PGPASSWORD) are set, e.g.
after `docker compose up -d postgres` with the values from .env.example.
"""

import os
import uuid

import pytest

psycopg = pytest.importorskip("psycopg")

from dcscanner.config import PostgresSourceConfig, TableSpec  # noqa: E402
from dcscanner.scanners import PostgresScanner, PsycopgAdapter  # noqa: E402

pytestmark = pytest.mark.integration

if not (os.environ.get("PGHOST") and os.environ.get("PGDATABASE")):
    pytest.skip("no PostgreSQL configured in the environment", allow_module_level=True)


@pytest.fixture
def tables():
    suffix = uuid.uuid4().hex[:8]
    users, notes = f"dcs_users_{suffix}", f"dcs_notes_{suffix}"
    with psycopg.connect(connect_timeout=5) as conn:
        conn.execute(f"CREATE TABLE {users} (id serial PRIMARY KEY, email text, card varchar(30), age int)")
        conn.execute(
            f"CREATE TABLE {notes} (ticket_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), body text, meta jsonb)"
        )
        rows = [(f"user{i}@example.com", "4111 1111 1111 1111" if i % 2 else "n/a", 20 + i) for i in range(1, 8)]
        with conn.cursor() as cur:
            cur.executemany(f"INSERT INTO {users} (email, card, age) VALUES (%s, %s, %s)", rows)
            cur.execute(
                f"INSERT INTO {notes} (body, meta) VALUES (%s, %s::jsonb)",
                ("ssn 123-45-6789", '{"contact": "x@example.org"}'),
            )
    yield users, notes
    with psycopg.connect(connect_timeout=5) as conn:
        conn.execute(f"DROP TABLE IF EXISTS {users}, {notes}")


def make(engine, classifier, tables, **kwargs):
    config = PostgresSourceConfig(tables=tables, batch_size=3)
    return PostgresScanner(engine, classifier, config, adapter=PsycopgAdapter(), **kwargs)


def test_batched_scan_with_primary_key_row_ids(engine, classifier, tables):
    users, _ = tables
    sc = make(engine, classifier, [TableSpec(users, columns=["email", "card"])])
    findings = sorted(sc.scan(), key=lambda f: f.sort_key())
    assert sc.stats.rows_scanned == 7 and sc.stats.tables_scanned == 1
    assert sum(f.data_type == "email" for f in findings) == 7
    assert sum(f.data_type == "credit_card" for f in findings) == 4
    assert {f.location.row_id for f in findings} == {str(i) for i in range(1, 8)}
    assert all(f.masked_value != "4111 1111 1111 1111" for f in findings)


def test_text_and_jsonb_columns_are_auto_discovered_and_uuid_keys_reported(engine, classifier, tables):
    _, notes = tables
    sc = make(engine, classifier, [TableSpec(notes)])
    findings = list(sc.scan())
    assert {(f.location.column_name, f.data_type) for f in findings} == {("body", "national_id"), ("meta", "email")}
    uuid.UUID(findings[0].location.row_id)  # a valid UUID, not a text key


def test_connection_is_read_only(engine, classifier, tables):
    users, _ = tables
    adapter = PsycopgAdapter()
    conn = adapter.connect()
    try:
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            conn.execute(f"DELETE FROM {users}")
    finally:
        conn.close()


def test_missing_table_is_an_error_not_a_crash(engine, classifier, tables):
    users, _ = tables
    sc = make(engine, classifier, [TableSpec("does_not_exist_zzz"), TableSpec(users, columns=["email"])])
    findings = list(sc.scan())
    assert len(findings) == 7
    assert len(sc.stats.errors) == 1 and "does_not_exist_zzz" in sc.stats.errors[0]


def test_parallel_tables(engine, classifier, tables):
    users, notes = tables
    sc = make(engine, classifier, [TableSpec(users, columns=["email"]), TableSpec(notes)], threads=2)
    assert len(list(sc.scan())) == 7 + 2
    assert sc.stats.tables_scanned == 2
