import csv
import json

import boto3
import pytest
from click.testing import CliRunner
from moto import mock_aws

from dcscanner.cli import cli

CARD = "4111 1111 1111 1111"
EMAIL = "jane.roe@example.com"
SSN = "123-45-6789"
RAW_VALUES = (CARD, "4111111111111111", EMAIL, "jane.roe", SSN)


@pytest.fixture
def runner(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for name in ("PGHOST", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGSERVICE", "AWS_ENDPOINT_URL"):
        monkeypatch.delenv(name, raising=False)
    # wide terminal so rich does not fold long paths across lines
    env = {"COLUMNS": "250"}
    if "mix_stderr" in CliRunner.__init__.__code__.co_varnames:  # click < 8.2
        return CliRunner(mix_stderr=False, env=env)
    return CliRunner(env=env)


@pytest.fixture
def data(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    (root / "customers.csv").write_text(f"id,card,email\n1,{CARD},{EMAIL}\n")
    (root / "notes.txt").write_text(f"ssn {SSN}\nnothing here\n")
    return root


def invoke(runner, *args):
    return runner.invoke(cli, list(args), catch_exceptions=False)


def test_file_scan_prints_masked_findings_and_summary(runner, data):
    result = invoke(runner, "scan", "--source", "file", "--path", str(data))
    assert result.exit_code == 0
    out = result.stdout
    assert "**** **** **** 1111" in out and "j******@example.com" in out and "***-**-6789" in out
    assert "Scan summary" in out and "2 files" in out and "3 total" in out
    for raw in RAW_VALUES:
        assert raw not in result.output


def test_json_and_csv_outputs_written_to_report_dir(runner, data, tmp_path):
    out_dir = tmp_path / "out"
    result = invoke(runner, "scan", "--source", "file", "--path", str(data), "-o", "json", "-o", "csv",
                    "--report-dir", str(out_dir), "--report-name", "run1")
    assert result.exit_code == 0
    report = json.loads((out_dir / "run1.json").read_text())
    assert report["summary"]["total_findings"] == 3
    rows = list(csv.DictReader((out_dir / "run1.csv").open()))
    assert {r["data_type"] for r in rows} == {"credit_card", "email", "national_id"}
    assert "Scan summary" not in result.stdout  # console not requested
    assert "run1.json" in result.stderr
    for raw in RAW_VALUES:
        assert raw not in (out_dir / "run1.json").read_text()
        assert raw not in (out_dir / "run1.csv").read_text()


def test_default_report_name_is_timestamped(runner, data, tmp_path):
    invoke(runner, "scan", "--source", "file", "--path", str(data), "-o", "json", "--report-dir", str(tmp_path / "r"))
    (report,) = (tmp_path / "r").glob("scan-report-*.json")
    assert report.exists()


def test_fail_on_threshold_sets_exit_code(runner, data):
    assert invoke(runner, "scan", "--source", "file", "--path", str(data), "--fail-on", "high").exit_code == 3
    only_email = invoke(runner, "scan", "--source", "file", "--path", str(data), "--detectors", "email", "--fail-on", "high")
    assert only_email.exit_code == 0
    assert invoke(runner, "scan", "--source", "file", "--path", str(data), "--detectors", "email", "--fail-on", "medium").exit_code == 3


def test_detectors_flag_limits_what_is_reported(runner, data):
    result = invoke(runner, "scan", "--source", "file", "--path", str(data), "--detectors", "credit_card", "-o", "json",
                    "--report-dir", "r", "--report-name", "x")
    doc = json.loads(open("r/x.json").read())
    assert {f["data_type"] for f in doc["findings"]} == {"credit_card"}
    assert result.exit_code == 0


def test_unknown_detector_is_a_usage_error(runner, data):
    result = runner.invoke(cli, ["scan", "--source", "file", "--path", str(data), "--detectors", "passport"])
    assert result.exit_code == 2 and "unknown detector" in result.output


def test_dry_run_reads_nothing(runner, data):
    result = invoke(runner, "scan", "--source", "file", "--path", str(data), "--dry-run")
    assert result.exit_code == 0
    assert "Dry run" in result.stdout and "customers.csv" in result.stdout and "nothing was read" in result.stdout
    assert "**** " not in result.stdout


def test_dry_run_json_lists_targets(runner, data, tmp_path):
    invoke(runner, "scan", "--source", "file", "--path", str(data), "--dry-run", "-o", "json", "--report-dir", "r", "--report-name", "d")
    doc = json.loads(open("r/d.json").read())
    assert doc["scan"]["dry_run"] is True and doc["findings"] == []
    assert sorted(t["name"].rsplit("/", 1)[1] for t in doc["targets"]) == ["customers.csv", "notes.txt"]


def test_scan_with_config_file_and_all(runner, data, tmp_path):
    config = tmp_path / "scan.yaml"
    config.write_text(
        f"""
scan: {{threads: 2}}
sources:
  file: {{paths: ["{data}"]}}
  postgres: {{enabled: false, tables: [users]}}
allowlist: {{paths: ["notes.txt"]}}
output: {{formats: [json], directory: cfg-reports, name: fromcfg}}
"""
    )
    result = invoke(runner, "scan", "--all", "--config", str(config))
    assert result.exit_code == 0
    doc = json.loads(open("cfg-reports/fromcfg.json").read())
    assert doc["scan"]["sources"] == ["file"]
    assert doc["summary"]["total_findings"] == 2  # notes.txt was allowlisted


def test_process_executor_flag(runner, data):
    result = invoke(runner, "scan", "--source", "file", "--path", str(data), "--executor", "process", "--threads", "2")
    assert result.exit_code == 0 and "3 total" in result.stdout
    for raw in RAW_VALUES:
        assert raw not in result.output


def test_cli_flags_override_the_config(runner, data, tmp_path):
    config = tmp_path / "scan.yaml"
    config.write_text("sources: {file: {paths: ['/definitely/not/here']}}\n")
    result = invoke(runner, "scan", "--source", "file", "--path", str(data), "--config", str(config), "--threads", "3")
    assert result.exit_code == 0 and "3 total" in result.stdout


@pytest.mark.parametrize(
    "args, message",
    [
        (["scan"], "nothing to scan"),
        (["scan", "--all"], "--all needs a config"),
        (["scan", "--all", "--source", "file"], "either --all or --source"),
        (["scan", "--source", "file"], "needs --path"),
        (["scan", "--source", "postgres"], "needs --table"),
        (["scan", "--source", "postgres", "--columns", "a"], "--columns requires --table"),
        (["scan", "--source", "s3"], "needs --bucket"),
        (["scan", "--source", "file", "--path", ".", "--bucket", "b"], "--bucket/--prefix given but the s3 source"),
        (["scan", "--source", "s3", "--bucket", "b", "--table", "t"], "--table"),
        (["scan", "--source", "ftp"], "Invalid value"),
        (["scan", "--source", "file", "--path", ".", "--threads", "0"], "Invalid value"),
    ],
)
def test_usage_errors(runner, args, message):
    result = runner.invoke(cli, args)
    assert result.exit_code == 2
    assert message in result.output


def test_credentials_in_config_are_refused(runner, tmp_path):
    config = tmp_path / "bad.yaml"
    config.write_text("sources:\n  postgres:\n    password: hunter2\n    tables: [users]\n")
    result = runner.invoke(cli, ["scan", "--source", "postgres", "--config", str(config)])
    assert result.exit_code == 2
    assert "credentials must not be stored" in result.output
    assert "hunter2" not in result.output


def test_missing_path_exits_with_error_status(runner, tmp_path):
    result = runner.invoke(cli, ["scan", "--source", "file", "--path", str(tmp_path / "nope")])
    assert result.exit_code == 1
    assert "FAILED" in result.stdout and "does not exist" in result.stdout


def test_postgres_without_environment_explains_how_to_configure(runner):
    result = runner.invoke(cli, ["scan", "--source", "postgres", "--table", "users", "--columns", "email"])
    assert result.exit_code == 1
    assert "PGPASSWORD" in result.stdout and "environment variables" in result.stdout


def test_postgres_table_argument_forms(runner, monkeypatch):
    seen = {}

    from dcscanner import runner as runner_module

    original = runner_module.ScanRunner.run

    def spy(self, sources, dry_run=False):
        seen["tables"] = [(t.schema, t.name, t.columns) for t in self.config.postgres.tables]
        seen["schema"] = self.config.postgres.schema
        return original(self, sources, dry_run=True)

    monkeypatch.setattr(runner_module.ScanRunner, "run", spy)
    result = runner.invoke(cli, ["scan", "--source", "postgres", "--table", "users", "--table", "audit.events",
                                 "--columns", "email, card_number", "--schema", "app"])
    assert result.exit_code == 0
    assert seen["tables"] == [(None, "users", ["email", "card_number"]), ("audit", "events", ["email", "card_number"])]
    assert seen["schema"] == "app"
    assert "public" not in result.stdout and "app.users" in result.stdout


def test_dotenv_file_supplies_environment(runner, monkeypatch):
    for name in ("PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD"):
        monkeypatch.setenv(name, "x")  # registers the variable so teardown removes what .env loads
        monkeypatch.delenv(name)
    open(".env", "w").write("PGHOST=127.0.0.1\nPGPORT=1\nPGDATABASE=x\nPGUSER=y\nPGPASSWORD=zzzzzz-secret\n")
    result = runner.invoke(cli, ["scan", "--source", "postgres", "--table", "users", "-o", "console"])
    # it got as far as trying to connect (nothing listens on port 1) and did not leak the password
    assert result.exit_code == 1
    assert "PGPASSWORD" not in result.stdout
    assert "zzzzzz-secret" not in result.output


def test_s3_scan_through_the_cli(runner, monkeypatch):
    for name, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                        "AWS_DEFAULT_REGION": "us-east-1"}.items():
        monkeypatch.setenv(name, value)
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="cli-bucket")
        client.put_object(Bucket="cli-bucket", Key="uploads/a.csv", Body=f"card\n{CARD}\n".encode())
        client.put_object(Bucket="cli-bucket", Key="elsewhere/b.csv", Body=f"card\n{CARD}\n".encode())
        result = invoke(runner, "scan", "--source", "s3", "--bucket", "cli-bucket", "--prefix", "uploads/")
    assert result.exit_code == 0
    assert "s3://cli-bucket/uploads/a.csv" in result.stdout and "elsewhere" not in result.stdout
    assert "1 S3 object" in result.stdout and "4111" not in result.output


def test_detectors_command_and_version(runner):
    listing = invoke(runner, "detectors")
    for name in ("credit_card", "email", "national_id", "phone", "ip_address", "api_key"):
        assert name in listing.stdout
    assert "us_ssn" in listing.stdout
    assert "0.1.0" in invoke(runner, "--version").stdout


def test_module_entry_point():
    import subprocess
    import sys

    completed = subprocess.run([sys.executable, "-m", "dcscanner", "--version"], capture_output=True, text=True)
    assert completed.returncode == 0 and "0.1.0" in completed.stdout
