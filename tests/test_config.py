from pathlib import Path

import pytest
import yaml

from dcscanner.config import AppConfig, ConfigError, load_config, parse_config
from dcscanner.models import RiskLevel

EXAMPLE = Path(__file__).parent.parent / "config" / "scan_config.example.yaml"


def test_shipped_example_config_is_valid():
    cfg = load_config(EXAMPLE)
    assert cfg.threads == 8
    assert cfg.enabled_sources() == ["file", "postgres"]
    assert cfg.postgres.tables[0].columns == ["email", "phone", "ssn", "card_number"]
    assert cfg.postgres.tables[2].columns == []  # auto-discovery
    assert "audit_log" in cfg.allowlist.tables
    assert cfg.output.formats == ["console", "json"]


def test_defaults_when_no_file():
    cfg = load_config(None)
    assert isinstance(cfg, AppConfig)
    assert cfg.enabled_sources() == []
    assert cfg.threads == 4


def test_empty_file_gives_defaults(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("")
    assert load_config(path).threads == 4


def test_parses_sources_and_options():
    cfg = parse_config(
        {
            "scan": {"threads": 2},
            "classification": {"risk_levels": {"email": "high", "national_id.uk_nino": "LOW"}},
            "sources": {
                "file": {"paths": ["./a", "./b"], "extensions": ["log", ".CSV"], "max_file_size_mb": 1.5},
                "postgres": {
                    "schema": "app",
                    "batch_size": 50,
                    "tables": ["plain", {"name": "users", "schema": "other", "columns": "email, ssn", "id_column": "uid"}],
                },
                "s3": {"bucket": "b", "prefix": "p/", "enabled": False, "endpoint_url": "http://localhost:5000"},
            },
        }
    )
    assert cfg.threads == 2
    assert cfg.risk_levels == {"email": RiskLevel.HIGH, "national_id.uk_nino": RiskLevel.LOW}
    assert cfg.file.paths == ["./a", "./b"] and cfg.file.extensions == (".log", ".csv")
    assert cfg.postgres.schema == "app" and cfg.postgres.batch_size == 50
    assert cfg.postgres.tables[0].name == "plain"
    users = cfg.postgres.tables[1]
    assert (users.schema, users.columns, users.id_column) == ("other", ["email", "ssn"], "uid")
    assert cfg.s3.bucket == "b" and cfg.s3.endpoint_url == "http://localhost:5000"
    assert cfg.enabled_sources() == ["file", "postgres"]  # s3 is disabled


@pytest.mark.parametrize(
    "source",
    [
        {"postgres": {"password": "x"}},
        {"postgres": {"tables": [{"name": "t", "Password": "x"}]}},
        {"postgres": {"dsn": "postgresql://u:p@h/db"}},
        {"postgres": {"connection_string": "..."}},
        {"s3": {"bucket": "b", "aws_secret_access_key": "x"}},
        {"s3": {"bucket": "b", "access_key_id": "x"}},
        {"s3": {"bucket": "b", "session_token": "x"}},
    ],
)
def test_credentials_in_the_config_are_rejected(source):
    with pytest.raises(ConfigError, match="credentials must not be stored"):
        parse_config({"sources": source})


@pytest.mark.parametrize(
    "raw, message",
    [
        ({"bogus": 1}, "unknown key"),
        ({"scan": {"threads": 0}}, "scan.threads"),
        ({"scan": {"threads": "many"}}, "scan.threads"),
        ({"sources": {"ftp": {}}}, "unknown key"),
        ({"sources": {"file": {"paths": "a", "typo": 1}}}, "unknown key"),
        ({"sources": {"file": {"max_file_size_mb": -1}}}, "positive number"),
        ({"sources": {"file": {"enabled": "yes"}}}, "true or false"),
        ({"sources": {"postgres": {"tables": [{"columns": ["a"]}]}}}, "name is required"),
        ({"sources": {"postgres": {"batch_size": 0}}}, "batch_size"),
        ({"classification": {"risk_levels": {"email": "critical"}}}, "unknown risk level"),
        ({"detectors": {"passport": {}}}, "unknown detector"),
        ({"detectors": {"national_id": {"profiles": ["mars"]}}}, "unknown national_id profile"),
        ({"output": {"formats": ["xml"]}}, "unsupported"),
        ({"logging": {"level": "LOUD"}}, "logging.level"),
        (["not", "a", "mapping"], "must be a mapping"),
    ],
)
def test_invalid_config(raw, message):
    with pytest.raises(ConfigError, match=message):
        parse_config(raw)


def test_load_errors(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("a: [unclosed")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(bad)


def test_round_trip_through_yaml_file(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump({"sources": {"file": {"paths": ["x"]}}, "allowlist": {"paths": ["*.tmp"]}}))
    cfg = load_config(path)
    assert cfg.file.paths == ["x"] and cfg.allowlist.paths == ["*.tmp"]
