"""PostgresScanner behaviour, exercised against SQLite through the adapter interface."""

import sqlite3

import pytest

from dcscanner.allowlist import NameMatcher
from dcscanner.config import PostgresSourceConfig, TableSpec
from dcscanner.scanners import BaseScanner, PostgresScanner, quote_ident

from conftest import make_luhn
from sqlite_adapter import NoConnectAdapter, SQLiteAdapter

CARD = "4111 1111 1111 1111"


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "test.db")
    conn = sqlite3.connect(path)
    conn.executescript(
        f"""
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, card TEXT, age INTEGER);
        INSERT INTO users VALUES (1, 'Ann', 'ann@example.com', '{CARD}', 31);
        INSERT INTO users VALUES (2, 'Bob', NULL, '', 42);
        INSERT INTO users VALUES (3, 'Cy', 'cy@example.org', 'not a card', 25);
        INSERT INTO users VALUES (4, 'Di', 'di@example.net', '{make_luhn("5", 16)}', 19);

        CREATE TABLE notes (body TEXT, meta JSON);
        INSERT INTO notes VALUES ('call me, ssn 123-45-6789', '{{"mail": "x@example.com"}}');

        CREATE TABLE audit_log (actor TEXT);
        INSERT INTO audit_log VALUES ('root@example.com');
        """
    )
    conn.commit()
    conn.close()
    return SQLiteAdapter(path)


def scanner(engine, classifier, adapter, tables, threads=1, **kwargs):
    config = PostgresSourceConfig(tables=tables, batch_size=kwargs.pop("batch_size", 2))
    return PostgresScanner(engine, classifier, config, adapter=adapter, threads=threads, **kwargs)


def run(sc):
    return sorted(sc.scan(), key=lambda f: f.sort_key())


def test_is_a_base_scanner():
    assert issubclass(PostgresScanner, BaseScanner)
    assert PostgresScanner.source_type == "postgres"


def test_scans_named_columns_with_row_and_column_coordinates(engine, classifier, db):
    sc = scanner(engine, classifier, db, [TableSpec("users", columns=["email", "card"])])
    findings = run(sc)
    got = [(f.source, f.data_type, f.location.row, f.location.row_id, f.location.column_name) for f in findings]
    assert got == [  # ordered by source, then row
        ("public.users.card", "credit_card", 1, "1", "card"),
        ("public.users.card", "credit_card", 4, "4", "card"),
        ("public.users.email", "email", 1, "1", "email"),
        ("public.users.email", "email", 3, "3", "email"),
        ("public.users.email", "email", 4, "4", "email"),
    ]
    assert sc.stats.tables_scanned == 1 and sc.stats.rows_scanned == 4


def test_findings_hold_masked_values_only(engine, classifier, db):
    findings = run(scanner(engine, classifier, db, [TableSpec("users", columns=["email", "card"])]))
    assert "**** **** **** 1111" in {f.masked_value for f in findings}
    assert "4111" not in repr(findings) and "ann@" not in repr(findings)


def test_rows_are_processed_in_batches(engine, classifier, db):
    calls = []
    original = db.stream

    def spy(conn, sql, batch_size):
        for batch in original(conn, sql, batch_size):
            calls.append(len(batch))
            yield batch

    db.stream = spy
    run(scanner(engine, classifier, db, [TableSpec("users", columns=["email"])], batch_size=3))
    assert calls == [3, 1]


def test_auto_discovers_text_columns_when_none_are_listed(engine, classifier, db):
    findings = run(scanner(engine, classifier, db, [TableSpec("notes")]))
    assert {(f.location.column_name, f.data_type) for f in findings} == {
        ("body", "national_id"),
        ("meta", "email"),
    }
    assert all(f.location.row_id is None for f in findings)  # no primary key


def test_non_text_columns_are_scanned_when_named_explicitly(engine, classifier, db):
    findings = run(scanner(engine, classifier, db, [TableSpec("users", columns=["age"])]))
    assert findings == []  # scanned (cast to text) but nothing sensitive in ages


def test_id_column_can_be_configured(engine, classifier, db):
    findings = run(scanner(engine, classifier, db, [TableSpec("users", columns=["email"], id_column="age")]))
    assert [f.location.row_id for f in findings] == ["31", "25", "19"]


def test_text_primary_keys_are_never_reported(engine, classifier, db):
    findings = run(scanner(engine, classifier, db, [TableSpec("users", columns=["email"], id_column="name")]))
    assert all(f.location.row_id is None for f in findings)


def test_table_and_column_allowlists(engine, classifier, db):
    tables = [TableSpec("users", columns=["email", "card"]), TableSpec("audit_log", columns=["actor"])]
    sc = scanner(
        engine,
        classifier,
        db,
        tables,
        table_allowlist=NameMatcher(["public.audit_*"]),
        column_allowlist=NameMatcher(["users.card"]),
    )
    findings = run(sc)
    assert {f.source for f in findings} == {"public.users.email"}
    assert sc.stats.tables_scanned == 1 and sc.stats.skipped == 1


def test_schema_override_per_table(engine, classifier, db):
    sc = scanner(engine, classifier, db, [TableSpec("users", schema="app", columns=["email"])])
    assert {f.source for f in run(sc)} == {"app.users.email"}


def test_missing_table_is_reported_and_others_still_scan(engine, classifier, db):
    sc = scanner(engine, classifier, db, [TableSpec("ghost"), TableSpec("users", columns=["email"])])
    findings = run(sc)
    assert len(findings) == 3
    assert len(sc.stats.errors) == 1 and "public.ghost" in sc.stats.errors[0]


def test_failure_midway_keeps_earlier_findings_and_reports_the_error(engine, classifier, db):
    class DropsConnection(SQLiteAdapter):
        def stream(self, conn, sql, batch_size):
            for index, batch in enumerate(super().stream(conn, sql, batch_size)):
                if index == 1:
                    raise RuntimeError("server closed the connection unexpectedly")
                yield batch

    sc = scanner(engine, classifier, DropsConnection(db.path), [TableSpec("users", columns=["email"])], batch_size=2)
    findings = run(sc)
    assert len(findings) == 1  # rows 1-2 were read before the failure
    assert sc.stats.tables_scanned == 0
    assert len(sc.stats.errors) == 1 and "server closed" in sc.stats.errors[0]


def test_sql_injection_through_identifiers_is_neutralised(engine, classifier, db):
    evil = 'users"; DROP TABLE users; --'
    sc = scanner(engine, classifier, db, [TableSpec(evil, columns=["email"])])
    assert run(sc) == []
    assert len(sc.stats.errors) == 1
    conn = sqlite3.connect(db.path)
    assert conn.execute("SELECT count(*) FROM users").fetchone() == (4,)  # still there


def test_quote_ident():
    assert quote_ident("users") == '"users"'
    assert quote_ident('we"ird') == '"we""ird"'
    for bad in ("", "a\x00b"):
        with pytest.raises(ValueError):
            quote_ident(bad)


def test_parallel_tables_use_their_own_connections(engine, classifier, db):
    tables = [TableSpec("users", columns=["email"]), TableSpec("notes"), TableSpec("audit_log")]
    sc = scanner(engine, classifier, db, tables, threads=3)
    findings = run(sc)
    assert sc.stats.tables_scanned == 3
    assert len(findings) == 3 + 2 + 1
    assert db.connections >= 1 + 3  # one probe connection + one per table


def test_unreachable_database_fails_the_source(engine, classifier, tmp_path):
    class Broken(SQLiteAdapter):
        def connect(self):
            raise ConnectionError("connection refused")

    sc = scanner(engine, classifier, Broken(str(tmp_path / "x.db")), [TableSpec("users", columns=["email"])])
    with pytest.raises(ConnectionError):
        list(sc.scan())


def test_plan_never_touches_the_database(engine, classifier, db, tmp_path):
    adapter = NoConnectAdapter(db.path)
    sc = scanner(
        engine,
        classifier,
        adapter,
        [TableSpec("users", columns=["email", "card"]), TableSpec("audit_log"), TableSpec("notes")],
        table_allowlist=NameMatcher(["audit_log"]),
    )
    targets = list(sc.plan())
    assert [t.name for t in targets] == ["public.users", "public.notes"]
    assert targets[0].detail == "columns: email, card"
    assert "auto-discovered" in targets[1].detail


def test_no_tables_configured(engine, classifier, db):
    with pytest.raises(ValueError, match="no tables"):
        list(scanner(engine, classifier, db, []).scan())
