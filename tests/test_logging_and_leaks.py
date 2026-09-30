"""Sensitive values and credentials must never reach logs or reports."""

import json
import logging

import pytest

from dcscanner.config import AppConfig, FileSourceConfig
from dcscanner.logging_utils import RedactingFormatter, configure_logging, redact_text
from dcscanner.reporters import CsvReporter, JsonReporter
from dcscanner.runner import ScanRunner

from conftest import make_luhn

CARD = "4111 1111 1111 1111"
EMAIL = "jane.roe@example.com"
SSN = "123-45-6789"


def test_redact_text_masks_detected_values():
    text = f"payment failed for {EMAIL} card {CARD} ssn {SSN}"
    redacted = redact_text(text)
    assert redacted == "payment failed for j******@example.com card **** **** **** 1111 ssn ***-**-6789"


def test_credentials_from_the_environment_are_scrubbed(monkeypatch):
    monkeypatch.setenv("PGPASSWORD", "s3cr3t-Passw0rd")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "abc123SECRETkey")
    text = "connect failed: password=s3cr3t-Passw0rd key=abc123SECRETkey"
    assert redact_text(text) == "connect failed: password=[REDACTED] key=[REDACTED]"


def test_short_secrets_are_not_used_for_literal_replacement(monkeypatch):
    monkeypatch.setenv("PGPASSWORD", "abc")
    assert redact_text("abc stays") == "abc stays"


def test_formatter_redacts_messages_arguments_and_tracebacks():
    formatter = RedactingFormatter("%(message)s")
    try:
        raise ValueError(f"bad row for {EMAIL}")
    except ValueError:
        import sys

        record = logging.LogRecord("t", logging.ERROR, __file__, 1, "card %s failed", (CARD,), sys.exc_info())
    output = formatter.format(record)
    assert "**** **** **** 1111" in output
    assert "j******@example.com" in output
    assert "4111" not in output and "jane.roe" not in output


def test_configure_logging_is_idempotent_and_redacts(capsys):
    configure_logging("INFO")
    configure_logging("INFO")
    root = logging.getLogger()
    ours = [h for h in root.handlers if h.get_name() == "dcscanner-stderr"]
    assert len(ours) == 1
    logging.getLogger("dcscanner.test").warning("leaked %s", CARD)
    err = capsys.readouterr().err
    assert "**** **** **** 1111" in err and "4111" not in err
    root.removeHandler(ours[0])


@pytest.fixture
def leaky_tree(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    (root / "a.csv").write_text(f"card,mail,ssn\n{CARD},{EMAIL},{SSN}\n")
    (root / "b.log").write_text(f"charge {CARD.replace(' ', '')} for {EMAIL}\nssn={SSN}\n")
    (root / f"{EMAIL}.txt").write_text(CARD)
    token = "gh" + "p_" + make_luhn("1", 36)
    (root / "c.txt").write_text(f"token {token}\n")
    return root, token


def test_scan_never_puts_raw_values_in_logs_or_reports(leaky_tree, tmp_path, caplog):
    root, token = leaky_tree
    config = AppConfig(file=FileSourceConfig(paths=[str(root)]), threads=4)
    config.detectors = {"phone": {"enabled": True}}

    with caplog.at_level(logging.DEBUG):
        result = ScanRunner(config).run(["file"])

    assert len(result.findings) >= 8
    json_path = JsonReporter(tmp_path / "r.json").report(result)
    csv_path = CsvReporter(tmp_path / "r.csv").report(result)
    surfaces = {
        "json": json_path.read_text(),
        "csv": csv_path.read_text(),
        "repr": repr(result),
        "logs": "\n".join(record.getMessage() for record in caplog.records),
    }
    raw_values = [CARD, CARD.replace(" ", ""), EMAIL, "jane.roe", SSN, token, token[4:]]
    for name, text in surfaces.items():
        for raw in raw_values:
            assert raw not in text, f"{raw!r} leaked into {name}"
    assert json.loads(surfaces["json"])["summary"]["total_findings"] == len(result.findings)


def test_file_named_after_a_person_is_masked_in_every_finding(leaky_tree):
    root, _ = leaky_tree
    result = ScanRunner(AppConfig(file=FileSourceConfig(paths=[str(root)]))).run(["file"])
    sources = {f.source for f in result.findings}
    assert any(s.endswith("j******@example.com.txt") for s in sources)
    assert not any("jane.roe" in s for s in sources)
