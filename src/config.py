"""YAML configuration: loading, validation and defaults."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from .models import RiskLevel

DEFAULT_EXTENSIONS = (".txt", ".csv", ".json", ".log", ".sql")
SOURCE_TYPES = ("file", "postgres", "s3")
OUTPUT_FORMATS = ("console", "json", "csv")

# Keys that would put a credential into the config file. Credentials belong in
# the environment (PG*/AWS_*) or the AWS credentials chain, never on disk here.
_FORBIDDEN_SOURCE_KEYS = {
    "password", "passwd", "pwd", "secret", "secret_key", "secret_access_key",
    "aws_secret_access_key", "access_key", "access_key_id", "aws_access_key_id",
    "session_token", "aws_session_token", "token", "dsn", "connection_string", "url",
}


class ConfigError(ValueError):
    """The configuration file is invalid."""


@dataclass
class FileSourceConfig:
    enabled: bool = True
    paths: list[str] = field(default_factory=list)
    extensions: tuple[str, ...] = DEFAULT_EXTENSIONS
    max_file_size_mb: float = 100.0
    follow_symlinks: bool = False


@dataclass
class TableSpec:
    name: str
    schema: str | None = None
    columns: list[str] = field(default_factory=list)
    id_column: str | None = None


@dataclass
class PostgresSourceConfig:
    enabled: bool = True
    schema: str = "public"
    batch_size: int = 1000
    tables: list[TableSpec] = field(default_factory=list)


@dataclass
class S3SourceConfig:
    enabled: bool = True
    bucket: str = ""
    prefix: str = ""
    extensions: tuple[str, ...] = DEFAULT_EXTENSIONS
    max_object_size_mb: float = 100.0
    region: str | None = None
    endpoint_url: str | None = None
    page_size: int = 1000


@dataclass
class AllowlistConfig:
    paths: list[str] = field(default_factory=list)
    tables: list[str] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    s3_keys: list[str] = field(default_factory=list)


@dataclass
class OutputConfig:
    formats: list[str] = field(default_factory=lambda: ["console"])
    directory: str = "reports"
    name: str | None = None
    max_rows: int = 200


@dataclass
class AppConfig:
    threads: int = 4
    detectors: dict[str, dict[str, Any]] = field(default_factory=dict)
    risk_levels: dict[str, RiskLevel] = field(default_factory=dict)
    file: FileSourceConfig | None = None
    postgres: PostgresSourceConfig | None = None
    s3: S3SourceConfig | None = None
    allowlist: AllowlistConfig = field(default_factory=AllowlistConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    log_level: str = "WARNING"

    def enabled_sources(self) -> list[str]:
        """Sources configured with ``enabled: true`` (used by ``--all``)."""
        return [name for name in SOURCE_TYPES if (src := getattr(self, name)) and src.enabled]


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_config(path: str | Path | None) -> AppConfig:
    """Load and validate a YAML config; ``None`` returns the defaults."""
    if path is None:
        return AppConfig()
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc.strerror}") from None
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from None
    if raw is None:
        return AppConfig()
    return parse_config(raw)


def parse_config(raw: Any) -> AppConfig:
    root = _mapping(raw, "config", allowed={
        "version", "scan", "detectors", "classification", "sources", "allowlist", "output", "logging",
    })
    cfg = AppConfig()

    scan = _mapping(root.get("scan"), "scan", allowed={"threads"})
    cfg.threads = _int(scan.get("threads", cfg.threads), "scan.threads", minimum=1)

    detectors = _mapping(root.get("detectors"), "detectors")
    for name, options in detectors.items():
        cfg.detectors[str(name)] = dict(_mapping(options, f"detectors.{name}"))
    _validate_detectors(cfg.detectors)

    classification = _mapping(root.get("classification"), "classification", allowed={"risk_levels"})
    for key, level in _mapping(classification.get("risk_levels"), "classification.risk_levels").items():
        try:
            cfg.risk_levels[str(key)] = RiskLevel.parse(level)
        except ValueError as exc:
            raise ConfigError(f"classification.risk_levels.{key}: {exc}") from None

    sources = _mapping(root.get("sources"), "sources", allowed=set(SOURCE_TYPES))
    _reject_credentials(sources)
    if "file" in sources:
        cfg.file = _parse_file(_mapping(sources["file"], "sources.file"))
    if "postgres" in sources:
        cfg.postgres = _parse_postgres(_mapping(sources["postgres"], "sources.postgres"))
    if "s3" in sources:
        cfg.s3 = _parse_s3(_mapping(sources["s3"], "sources.s3"))

    allow = _mapping(root.get("allowlist"), "allowlist", allowed={"paths", "tables", "columns", "s3_keys"})
    cfg.allowlist = AllowlistConfig(
        paths=_str_list(allow.get("paths"), "allowlist.paths"),
        tables=_str_list(allow.get("tables"), "allowlist.tables"),
        columns=_str_list(allow.get("columns"), "allowlist.columns"),
        s3_keys=_str_list(allow.get("s3_keys"), "allowlist.s3_keys"),
    )

    out = _mapping(root.get("output"), "output", allowed={"formats", "directory", "name", "max_rows"})
    formats = _str_list(out.get("formats"), "output.formats") or list(cfg.output.formats)
    bad = [f for f in formats if f not in OUTPUT_FORMATS]
    if bad:
        raise ConfigError(f"output.formats: unsupported {bad} (choose from {list(OUTPUT_FORMATS)})")
    cfg.output = OutputConfig(
        formats=formats,
        directory=str(out.get("directory", cfg.output.directory)),
        name=None if out.get("name") is None else str(out["name"]),
        max_rows=_int(out.get("max_rows", cfg.output.max_rows), "output.max_rows", minimum=0),
    )

    logging_cfg = _mapping(root.get("logging"), "logging", allowed={"level"})
    level = str(logging_cfg.get("level", cfg.log_level)).upper()
    if level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
        raise ConfigError("logging.level must be one of DEBUG, INFO, WARNING, ERROR")
    cfg.log_level = level
    return cfg


def _validate_detectors(settings: Mapping[str, Mapping[str, Any]]) -> None:
    # Imported here to keep config parsing free of detector imports at module load.
    from .detectors import build_detectors

    try:
        build_detectors(settings)
    except ValueError as exc:
        raise ConfigError(f"detectors: {exc}") from None


def _parse_file(data: Mapping[str, Any]) -> FileSourceConfig:
    _check_keys(data, "sources.file", {"enabled", "paths", "extensions", "max_file_size_mb", "follow_symlinks"})
    default = FileSourceConfig()
    return FileSourceConfig(
        enabled=_bool(data.get("enabled", True), "sources.file.enabled"),
        paths=_str_list(data.get("paths"), "sources.file.paths"),
        extensions=_extensions(data.get("extensions"), "sources.file.extensions", default.extensions),
        max_file_size_mb=_number(data.get("max_file_size_mb", default.max_file_size_mb), "sources.file.max_file_size_mb"),
        follow_symlinks=_bool(data.get("follow_symlinks", False), "sources.file.follow_symlinks"),
    )


def _parse_postgres(data: Mapping[str, Any]) -> PostgresSourceConfig:
    _check_keys(data, "sources.postgres", {"enabled", "schema", "batch_size", "tables"})
    tables: list[TableSpec] = []
    for index, entry in enumerate(data.get("tables") or []):
        where = f"sources.postgres.tables[{index}]"
        if isinstance(entry, str):
            entry = {"name": entry}
        table = _mapping(entry, where, allowed={"name", "schema", "columns", "id_column"})
        if not table.get("name"):
            raise ConfigError(f"{where}.name is required")
        tables.append(
            TableSpec(
                name=str(table["name"]),
                schema=None if table.get("schema") is None else str(table["schema"]),
                columns=_column_list(table.get("columns"), f"{where}.columns"),
                id_column=None if table.get("id_column") is None else str(table["id_column"]),
            )
        )
    return PostgresSourceConfig(
        enabled=_bool(data.get("enabled", True), "sources.postgres.enabled"),
        schema=str(data.get("schema", "public")),
        batch_size=_int(data.get("batch_size", 1000), "sources.postgres.batch_size", minimum=1),
        tables=tables,
    )


def _parse_s3(data: Mapping[str, Any]) -> S3SourceConfig:
    _check_keys(
        data, "sources.s3",
        {"enabled", "bucket", "prefix", "extensions", "max_object_size_mb", "region", "endpoint_url", "page_size"},
    )
    default = S3SourceConfig()
    return S3SourceConfig(
        enabled=_bool(data.get("enabled", True), "sources.s3.enabled"),
        bucket=str(data.get("bucket") or ""),
        prefix=str(data.get("prefix") or ""),
        extensions=_extensions(data.get("extensions"), "sources.s3.extensions", default.extensions),
        max_object_size_mb=_number(data.get("max_object_size_mb", default.max_object_size_mb), "sources.s3.max_object_size_mb"),
        region=None if data.get("region") is None else str(data["region"]),
        endpoint_url=None if data.get("endpoint_url") is None else str(data["endpoint_url"]),
        page_size=_int(data.get("page_size", 1000), "sources.s3.page_size", minimum=1),
    )


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _reject_credentials(node: Any, where: str = "sources") -> None:
    if isinstance(node, Mapping):
        for key, value in node.items():
            if str(key).lower() in _FORBIDDEN_SOURCE_KEYS:
                raise ConfigError(
                    f"{where}.{key}: credentials must not be stored in the config file. "
                    "Provide them through environment variables (PGHOST/PGUSER/PGPASSWORD, "
                    "AWS_PROFILE or the standard AWS credentials chain)."
                )
            _reject_credentials(value, f"{where}.{key}")
    elif isinstance(node, list):
        for index, item in enumerate(node):
            _reject_credentials(item, f"{where}[{index}]")


def _mapping(value: Any, where: str, allowed: set[str] | None = None) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ConfigError(f"{where} must be a mapping")
    if allowed is not None:
        _check_keys(value, where, allowed)
    return value


def _check_keys(data: Mapping[str, Any], where: str, allowed: set[str]) -> None:
    unknown = sorted(str(k) for k in data if k not in allowed)
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {unknown} (allowed: {sorted(allowed)})")


def _int(value: Any, where: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ConfigError(f"{where} must be an integer >= {minimum}")
    return value


def _number(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ConfigError(f"{where} must be a positive number")
    return float(value)


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{where} must be true or false")
    return value


def _str_list(value: Any, where: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list) or not all(isinstance(v, (str, int)) for v in value):
        raise ConfigError(f"{where} must be a list of strings")
    return [str(v) for v in value]


def _column_list(value: Any, where: str) -> list[str]:
    if isinstance(value, str):
        return [c.strip() for c in value.split(",") if c.strip()]
    return _str_list(value, where)


def _extensions(value: Any, where: str, default: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return default
    items = _str_list(value, where)
    return tuple(("." + e.lstrip(".")).lower() for e in items)
