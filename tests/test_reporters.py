import csv
import io
import json
from datetime import datetime, timedelta, timezone

import pytest
from rich.console import Console

from dcscanner.models import Finding, Location, RiskLevel, ScanResult, ScanStats, ScanTarget
from dcscanner.reporters import BaseReporter, ConsoleReporter, CsvReporter, JsonReporter, build_report
from dcscanner.reporters.csv_reporter import COLUMNS, sanitize_cell


def finding(**overrides):
    base = dict(
        source_type="file",
        source="data/customers.csv",
        data_type="credit_card",
        subtype="visa",
        category="PCI",
        risk=RiskLevel.HIGH,
        location=Location(line=12, offset=7, column_name="card"),
        masked_value="**** **** **** 1111",
    )
    base.update(overrides)
    return Finding(**base)


@pytest.fixture
def result():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    stats = ScanStats(files_scanned=2, lines_scanned=120, tables_scanned=1, rows_scanned=50, bytes_scanned=2048)
    return ScanResult(
        findings=[
            finding(),
            finding(data_type="email", subtype=None, category="PII", risk=RiskLevel.MEDIUM,
                    masked_value="a**@example.com", location=Location(line=3, offset=1)),
            finding(source_type="postgres", source="public.users.email", data_type="email", subtype=None,
                    category="PII", risk=RiskLevel.MEDIUM, masked_value="b**@example.org",
                    location=Location(row=5, row_id="5", column_name="email", offset=1)),
            finding(data_type="ip_address", subtype="ipv4", category="Network", risk=RiskLevel.LOW,
                    masked_value="10.0.*.*", location=Location(line=9, offset=2)),
        ],
        stats=stats,
        sources=["file", "postgres"],
        started_at=start,
        finished_at=start + timedelta(seconds=1.5),
    )


def render(result, **kwargs):
    buffer = io.StringIO()
    ConsoleReporter(Console(file=buffer, width=120, force_terminal=False), **kwargs).report(result)
    return buffer.getvalue()


def test_reporters_share_an_interface():
    for cls in (ConsoleReporter, JsonReporter, CsvReporter):
        assert issubclass(cls, BaseReporter)
    assert {ConsoleReporter.format, JsonReporter.format, CsvReporter.format} == {"console", "json", "csv"}


# --- JSON -------------------------------------------------------------------


def test_json_report_structure(result, tmp_path):
    path = JsonReporter(tmp_path / "out" / "r.json").report(result)
    doc = json.loads(path.read_text())
    assert set(doc) == {"scan", "summary", "errors", "failed_sources", "findings"}
    assert doc["scan"]["sources"] == ["file", "postgres"] and doc["scan"]["duration_seconds"] == 1.5
    assert doc["summary"]["total_findings"] == 4
    assert doc["summary"]["by_risk"] == {"HIGH": 1, "MEDIUM": 2, "LOW": 1}
    assert doc["summary"]["by_type"] == {"email": 2, "credit_card": 1, "ip_address": 1}
    assert doc["summary"]["by_source_type"] == {"file": 3, "postgres": 1}
    assert doc["summary"]["scanned"]["files_scanned"] == 2 and doc["summary"]["scanned"]["rows_scanned"] == 50
    first = doc["findings"][0]
    assert first == {
        "source_type": "file",
        "source": "data/customers.csv",
        "data_type": "credit_card",
        "subtype": "visa",
        "category": "PCI",
        "risk": "HIGH",
        "location": {"line": 12, "offset": 7, "column_name": "card", "row": None, "row_id": None},
        "masked_value": "**** **** **** 1111",
    }


def test_json_dry_run_includes_targets(result):
    result.dry_run = True
    result.targets = [ScanTarget("file", "a.txt", 10)]
    assert build_report(result)["targets"] == [
        {"source_type": "file", "name": "a.txt", "size_bytes": 10, "detail": None}
    ]
    result.dry_run = False
    assert "targets" not in build_report(result)


# --- CSV --------------------------------------------------------------------


def test_csv_report(result, tmp_path):
    path = CsvReporter(tmp_path / "r.csv").report(result)
    rows = list(csv.reader(path.open(newline="")))
    assert tuple(rows[0]) == COLUMNS
    assert len(rows) == 5
    assert rows[1] == ["file", "data/customers.csv", "credit_card", "visa", "PCI", "HIGH", "12", "7", "card", "", "", "**** **** **** 1111"]
    assert rows[3][:2] == ["postgres", "public.users.email"] and rows[3][9:11] == ["5", "5"]


@pytest.mark.parametrize("value", ["=cmd|' /C calc'!A0", "+1 (212) 555-0123", "-2+3", "@SUM(A1)", "\t=1"])
def test_csv_formula_injection_is_neutralised(value):
    assert sanitize_cell(value) == "'" + value


def test_csv_keeps_ordinary_values(result):
    assert sanitize_cell("plain") == "plain" and sanitize_cell(5) == 5 and sanitize_cell(None) == ""


def test_csv_neutralises_hostile_source_names(tmp_path):
    hostile = ScanResult(
        findings=[finding(source="=HYPERLINK(\"http://evil\")", masked_value="+* (***) ***-0123")],
        stats=ScanStats(), sources=["file"],
        started_at=datetime.now(timezone.utc), finished_at=datetime.now(timezone.utc),
    )
    rows = list(csv.reader(CsvReporter(tmp_path / "h.csv").report(hostile).open(newline="")))
    assert rows[1][1].startswith("'=") and rows[1][-1].startswith("'+")


# --- console ----------------------------------------------------------------


def test_console_report_shows_findings_and_statistics(result):
    text = render(result)
    for expected in ("HIGH", "MEDIUM", "LOW", "credit_card (visa)", "data/customers.csv", "12:7 [card]",
                     "row 5 id=5 [email]", "**** **** **** 1111", "public.users.email"):
        assert expected in text
    assert "Scan summary" in text
    assert "2 files" in text and "1 table" in text and "120 lines" in text and "50 rows" in text
    assert "4 total" in text and "HIGH 1" in text and "MEDIUM 2" in text and "LOW 1" in text
    assert text.index("HIGH") < text.index("MEDIUM") < text.index("LOW")  # most severe first


def test_console_truncates_long_tables(result):
    text = render(result, max_rows=2)
    assert "2 more finding(s) not shown" in text
    assert "not shown" not in render(result, max_rows=0)  # 0 means "show everything"


def test_console_colours_by_risk(result):
    buffer = io.StringIO()
    ConsoleReporter(Console(file=buffer, width=120, force_terminal=True, color_system="truecolor")).report(result)
    output = buffer.getvalue()
    assert "\x1b[" in output
    # red background for HIGH, yellow for MEDIUM, cyan for LOW
    assert "41m" in output or "48;2;" in output or "48;5;" in output


def test_console_without_findings():
    empty = ScanResult([], ScanStats(files_scanned=1), ["file"], datetime.now(timezone.utc), datetime.now(timezone.utc))
    text = render(empty)
    assert "No sensitive data found" in text and "0 total" in text


def test_console_lists_errors_and_failed_sources(result):
    result.stats.errors = [f"file{i}.txt: Permission denied" for i in range(12)]
    result.failed_sources = ["postgres: RuntimeError: cannot connect"]
    text = render(result)
    assert "FAILED postgres: RuntimeError: cannot connect" in text
    assert "file0.txt: Permission denied" in text and "and 2 more error(s)" in text


def test_console_dry_run(result):
    result.dry_run = True
    result.findings = []
    result.targets = [ScanTarget("file", "a.txt", 2048), ScanTarget("postgres", "public.users", None, "columns: email")]
    text = render(result)
    assert "Dry run" in text and "a.txt" in text and "2.0 KB" in text and "columns: email" in text
    assert "2 target(s)" in text and "nothing was read" in text
