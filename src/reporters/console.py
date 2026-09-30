"""Colourised console report built with rich."""

from __future__ import annotations

from typing import ClassVar

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..models import Finding, RiskLevel, ScanResult
from .base import BaseReporter

RISK_STYLE = {
    RiskLevel.HIGH: "bold white on red",
    RiskLevel.MEDIUM: "bold black on yellow",
    RiskLevel.LOW: "bold black on cyan",
}


def _human_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"  # pragma: no cover


class ConsoleReporter(BaseReporter):
    format: ClassVar[str] = "console"

    def __init__(self, console: Console | None = None, max_rows: int = 200) -> None:
        self.console = console or Console()
        self.max_rows = max_rows

    def report(self, result: ScanResult) -> None:
        if result.dry_run:
            self._dry_run(result)
            return
        self._findings_table(result)
        self._summary(result)

    # -- sections --------------------------------------------------------

    def _findings_table(self, result: ScanResult) -> None:
        if not result.findings:
            self.console.print("[green]No sensitive data found.[/green]")
            return
        ordered = sorted(result.findings, key=lambda f: (-f.risk.rank, f.sort_key()))
        shown = ordered if self.max_rows <= 0 else ordered[: self.max_rows]

        table = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
        table.add_column("Risk", no_wrap=True)
        table.add_column("Type", no_wrap=True)
        table.add_column("Source", overflow="fold", min_width=24)
        table.add_column("Line:Col / Row", overflow="fold")
        table.add_column("Value (masked)", no_wrap=True)
        for finding in shown:
            table.add_row(
                Text(f" {finding.risk.value} ", style=RISK_STYLE[finding.risk]),
                _type_label(finding),
                Text(finding.source),
                Text(finding.location.describe(compact=True)),
                Text(finding.masked_value),
            )
        self.console.print(table)
        hidden = len(ordered) - len(shown)
        if hidden > 0:
            self.console.print(
                f"[dim]... {hidden} more finding(s) not shown "
                f"(use --max-rows 0 or --output json/csv for the full list)[/dim]"
            )

    def _summary(self, result: ScanResult) -> None:
        stats = result.stats
        c = self.console
        c.rule("Scan summary")
        c.print(f"Sources:   {', '.join(result.sources) or '-'}")
        c.print(f"Duration:  {result.duration_seconds:.2f}s")

        scanned = [
            ("files", stats.files_scanned),
            ("lines", stats.lines_scanned),
            ("S3 objects", stats.objects_scanned),
            ("tables", stats.tables_scanned),
            ("rows", stats.rows_scanned),
        ]
        parts = [f"{value:,} {label}" for label, value in scanned if value]
        if stats.bytes_scanned:
            parts.append(_human_bytes(stats.bytes_scanned))
        c.print(f"Scanned:   {', '.join(parts) or 'nothing'}")
        if stats.skipped:
            c.print(f"Skipped:   {stats.skipped:,} (allowlisted, binary or over the size limit)")

        by_risk = result.count_by_risk()
        risk_line = Text("Findings:  ")
        risk_line.append(f"{len(result.findings):,} total")
        for level in (RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW):
            if by_risk.get(level.value):
                risk_line.append("  ")
                risk_line.append(f" {level.value} {by_risk[level.value]:,} ", style=RISK_STYLE[level])
        c.print(risk_line)

        if result.findings:
            table = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
            table.add_column("Data type")
            table.add_column("Findings", justify="right")
            for data_type, count in result.summary()["by_type"].items():
                table.add_row(data_type, f"{count:,}")
            c.print(table)

        for message in result.failed_sources:
            c.print(f"[bold red]FAILED[/bold red] {message}", highlight=False)
        for message in stats.errors[:10]:
            c.print(f"[red]error[/red] {message}", highlight=False)
        if len(stats.errors) > 10:
            c.print(f"[red]... and {len(stats.errors) - 10} more error(s)[/red]")

    def _dry_run(self, result: ScanResult) -> None:
        table = Table(box=box.SIMPLE_HEAD, header_style="bold", title="Dry run: would scan")
        table.add_column("Source")
        table.add_column("Target", overflow="fold")
        table.add_column("Size", justify="right")
        table.add_column("Detail", overflow="fold")
        for target in result.targets:
            size = "" if target.size_bytes is None else _human_bytes(target.size_bytes)
            table.add_row(target.source_type, Text(target.name), size, Text(target.detail or ""))
        self.console.print(table)
        total = sum(t.size_bytes or 0 for t in result.targets)
        self.console.print(
            f"{len(result.targets):,} target(s), {_human_bytes(total)} - nothing was read."
        )
        for message in result.failed_sources:
            self.console.print(f"[bold red]FAILED[/bold red] {message}", highlight=False)


def _type_label(finding: Finding) -> Text:
    text = Text(finding.data_type)
    if finding.subtype:
        text.append(f" ({finding.subtype})", style="dim")
    return text
