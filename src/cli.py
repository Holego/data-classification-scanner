"""Command line interface: ``scanner scan ...``."""

from __future__ import annotations

import dataclasses
import sys
from datetime import datetime
from pathlib import Path
from typing import Sequence

import click
from dotenv import load_dotenv
from rich.console import Console

from . import __version__
from .config import (
    EXECUTORS,
    OUTPUT_FORMATS,
    SOURCE_TYPES,
    AppConfig,
    ConfigError,
    FileSourceConfig,
    PostgresSourceConfig,
    S3SourceConfig,
    TableSpec,
    load_config,
)
from .detectors import PROFILES
from .detectors.registry import DEFAULT_ENABLED, FACTORIES
from .logging_utils import configure_logging
from .models import RiskLevel, ScanResult
from .reporters import ConsoleReporter, CsvReporter, JsonReporter
from .runner import ScanRunner

EXIT_ERRORS = 1
EXIT_FINDINGS = 3


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="scanner")
def cli() -> None:
    """Data discovery and classification scanner.

    Finds PII, payment card data and secrets in files, PostgreSQL tables and
    S3 objects. Reports contain masked values only.
    """


@cli.command("detectors")
def list_detectors() -> None:
    """List available detectors and national ID profiles."""
    console = Console()
    for name in FACTORIES:
        state = "on by default" if DEFAULT_ENABLED[name] else "opt-in"
        console.print(f"[bold]{name}[/bold] ({state})")
    console.print(f"\nnational_id profiles: {', '.join(sorted(PROFILES))}")


@cli.command("scan")
@click.option("--source", "sources", multiple=True, type=click.Choice(SOURCE_TYPES),
              help="Source to scan (repeatable).")
@click.option("--all", "scan_all", is_flag=True,
              help="Scan every source enabled in the config file.")
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="YAML configuration file.")
@click.option("--path", "paths", multiple=True, type=click.Path(path_type=Path),
              help="File or directory to scan (repeatable).")
@click.option("--table", "tables", multiple=True, help="PostgreSQL table, optionally schema.table (repeatable).")
@click.option("--columns", help="Comma-separated columns of the --table (default: all text-like columns).")
@click.option("--schema", help="Default PostgreSQL schema.")
@click.option("--bucket", help="S3 bucket name.")
@click.option("--prefix", help="S3 key prefix (folder) to limit the scan.")
@click.option("--detectors", "detector_names",
              help="Comma-separated detectors to run instead of the configured set.")
@click.option("--output", "-o", "formats", multiple=True, type=click.Choice(OUTPUT_FORMATS),
              help="Output format (repeatable). Default: console.")
@click.option("--report-dir", type=click.Path(file_okay=False, path_type=Path),
              help="Directory for json/csv reports (default: ./reports).")
@click.option("--report-name", help="Base file name for json/csv reports.")
@click.option("--threads", type=click.IntRange(min=1), help="Worker threads (or processes, see --executor).")
@click.option("--executor", type=click.Choice(EXECUTORS),
              help="thread (default) or process: use processes for CPU-bound scans of local files.")
@click.option("--dry-run", is_flag=True, help="List what would be scanned without reading any content.")
@click.option("--fail-on", type=click.Choice([lvl.value.lower() for lvl in RiskLevel]),
              help="Exit with status 3 if a finding of at least this risk exists.")
@click.option("--max-rows", type=click.IntRange(min=0), help="Rows in the console table (0 = all).")
@click.option("--verbose", "-v", count=True, help="-v for INFO, -vv for DEBUG logs (stderr).")
def scan(
    sources: tuple[str, ...],
    scan_all: bool,
    config_path: Path | None,
    paths: tuple[Path, ...],
    tables: tuple[str, ...],
    columns: str | None,
    schema: str | None,
    bucket: str | None,
    prefix: str | None,
    detector_names: str | None,
    formats: tuple[str, ...],
    report_dir: Path | None,
    report_name: str | None,
    threads: int | None,
    executor: str | None,
    dry_run: bool,
    fail_on: str | None,
    max_rows: int | None,
    verbose: int,
) -> None:
    """Scan data sources for sensitive information.

    \b
    scanner scan --source file --path ./data
    scanner scan --source postgres --table users --columns email,card_number
    scanner scan --source s3 --bucket my-bucket --prefix uploads/
    scanner scan --all --config config/scan_config.yaml
    """
    load_dotenv(Path.cwd() / ".env")  # real environment variables take precedence
    try:
        config = load_config(config_path)
        selected = resolve_sources(
            config, sources, scan_all, paths, tables, columns, schema, bucket, prefix
        )
        config = apply_overrides(config, threads, detector_names, max_rows, executor)
    except ConfigError as exc:
        raise click.UsageError(str(exc)) from None

    configure_logging(["WARNING", "INFO", "DEBUG"][min(verbose, 2)] if verbose else config.log_level)

    try:
        runner = ScanRunner(config)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from None

    err_console = Console(stderr=True)
    if err_console.is_terminal:
        with err_console.status("Scanning..."):
            result = runner.run(selected, dry_run=dry_run)
    else:
        result = runner.run(selected, dry_run=dry_run)

    output_formats = list(formats) or config.output.formats
    written = emit_reports(
        result,
        output_formats,
        report_dir or Path(config.output.directory),
        report_name or config.output.name,
        config.output.max_rows,
    )
    for path in written:
        click.echo(f"Report written: {path}", err=True)

    sys.exit(exit_code(result, fail_on))


# ---------------------------------------------------------------------------
# Helpers (kept module-level so they can be tested without invoking the CLI)
# ---------------------------------------------------------------------------


def resolve_sources(
    config: AppConfig,
    sources: Sequence[str],
    scan_all: bool,
    paths: Sequence[Path],
    tables: Sequence[str],
    columns: str | None,
    schema: str | None,
    bucket: str | None,
    prefix: str | None,
) -> list[str]:
    """Decide which sources run and fold CLI arguments into ``config`` (in place)."""
    if scan_all and sources:
        raise ConfigError("use either --all or --source, not both")
    if not scan_all and not sources:
        raise ConfigError("nothing to scan: pass --source file|postgres|s3 or --all")

    if scan_all:
        selected = config.enabled_sources()
        if not selected:
            raise ConfigError("--all needs a config file with at least one enabled source (--config)")
    else:
        selected = list(dict.fromkeys(sources))

    _reject_unrelated(selected, paths, tables, columns, schema, bucket, prefix)

    if "file" in selected:
        config.file = config.file or FileSourceConfig()
        if paths:
            config.file = dataclasses.replace(config.file, paths=[str(p) for p in paths])
        if not config.file.paths:
            raise ConfigError("file source needs --path (or sources.file.paths in the config)")

    if "postgres" in selected:
        config.postgres = config.postgres or PostgresSourceConfig()
        if schema:
            config.postgres = dataclasses.replace(config.postgres, schema=schema)
        if columns and not tables:
            raise ConfigError("--columns requires --table")
        if tables:
            specs = [_table_spec(t, columns) for t in tables]
            config.postgres = dataclasses.replace(config.postgres, tables=specs)
        if not config.postgres.tables:
            raise ConfigError("postgres source needs --table (or sources.postgres.tables in the config)")

    if "s3" in selected:
        config.s3 = config.s3 or S3SourceConfig()
        updates = {}
        if bucket:
            updates["bucket"] = bucket
        if prefix is not None:
            updates["prefix"] = prefix
        config.s3 = dataclasses.replace(config.s3, **updates)
        if not config.s3.bucket:
            raise ConfigError("s3 source needs --bucket (or sources.s3.bucket in the config)")
    return selected


def _reject_unrelated(selected, paths, tables, columns, schema, bucket, prefix) -> None:
    checks = (
        ("file", "--path", bool(paths)),
        ("postgres", "--table/--columns/--schema", bool(tables or columns or schema)),
        ("s3", "--bucket/--prefix", bool(bucket or prefix)),
    )
    for source, flag, given in checks:
        if given and source not in selected:
            raise ConfigError(f"{flag} given but the {source} source is not selected")


def _table_spec(value: str, columns: str | None) -> TableSpec:
    schema, _, name = value.rpartition(".")
    return TableSpec(
        name=name,
        schema=schema or None,
        columns=[c.strip() for c in (columns or "").split(",") if c.strip()],
    )


def apply_overrides(
    config: AppConfig,
    threads: int | None,
    detector_names: str | None,
    max_rows: int | None,
    executor: str | None = None,
) -> AppConfig:
    if threads:
        config.threads = threads
    if executor:
        config.executor = executor
    if max_rows is not None:
        config.output = dataclasses.replace(config.output, max_rows=max_rows)
    if detector_names:
        wanted = [n.strip() for n in detector_names.split(",") if n.strip()]
        unknown = sorted(set(wanted) - set(FACTORIES))
        if unknown:
            raise ConfigError(f"unknown detector(s): {', '.join(unknown)} (available: {', '.join(FACTORIES)})")
        for name in FACTORIES:
            options = dict(config.detectors.get(name, {}))
            options["enabled"] = name in wanted
            config.detectors[name] = options
    return config


def emit_reports(
    result: ScanResult,
    formats: Sequence[str],
    directory: Path,
    name: str | None,
    max_rows: int,
) -> list[Path]:
    base = name or f"scan-report-{datetime.now():%Y%m%d-%H%M%S}"
    written: list[Path] = []
    for fmt in dict.fromkeys(formats):
        if fmt == "console":
            ConsoleReporter(Console(), max_rows=max_rows).report(result)
        elif fmt == "json":
            written.append(JsonReporter(directory / f"{base}.json").report(result))
        elif fmt == "csv":
            written.append(CsvReporter(directory / f"{base}.csv").report(result))
    return written


def exit_code(result: ScanResult, fail_on: str | None) -> int:
    if fail_on and not result.dry_run:
        threshold = RiskLevel.parse(fail_on)
        if any(f.risk.at_least(threshold) for f in result.findings):
            return EXIT_FINDINGS
    if result.failed_sources or result.stats.errors:
        return EXIT_ERRORS
    return 0


def main() -> None:
    cli(prog_name="scanner")


if __name__ == "__main__":
    main()
