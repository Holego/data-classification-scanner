"""Streaming text decoding and line/CSV scanning shared by file and S3 scanners."""

from __future__ import annotations

import codecs
import csv
import itertools
from typing import Callable, Iterable, Iterator

from ..models import Finding
from .base import BaseScanner

CHUNK_SIZE = 1 << 16
_SNIFF_BYTES = 8192

csv.field_size_limit(1 << 28)


class BinaryContentError(Exception):
    """The stream looks binary and is not scanned as text."""


def sniff_encoding(head: bytes) -> str:
    """Pick a text encoding from the first bytes, or raise for binary data."""
    if head.startswith(codecs.BOM_UTF8):
        return "utf-8-sig"
    if head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return "utf-16"
    if b"\x00" in head[:_SNIFF_BYTES]:
        raise BinaryContentError
    return "utf-8"


def decode_lines(chunks: Iterable[bytes]) -> Iterator[str]:
    """Decode a byte stream into lines (newline kept), never buffering it whole.

    Invalid byte sequences are replaced rather than raising, so one bad byte
    does not hide the rest of a file.
    """
    decoder: codecs.IncrementalDecoder | None = None
    pending = ""
    for chunk in chunks:
        if not chunk:
            continue
        if decoder is None:
            decoder = codecs.getincrementaldecoder(sniff_encoding(chunk))(errors="replace")
        pending += decoder.decode(chunk)
        if "\n" not in pending:
            continue
        *complete, pending = pending.split("\n")
        for line in complete:
            yield line + "\n"
    if decoder is not None:
        pending += decoder.decode(b"", final=True)
    if pending:
        yield pending


def read_chunks(fileobj, size: int = CHUNK_SIZE) -> Iterator[bytes]:
    return iter(lambda: fileobj.read(size), b"")


def scan_lines(
    scanner: BaseScanner, source: str, lines: Iterable[str]
) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    count = 0
    for count, line in enumerate(lines, start=1):
        if line.strip():
            findings.extend(scanner.inspect(line, source, line=count))
    return findings, count


def _sniff_delimiter(sample: str) -> str:
    try:
        return csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
    except csv.Error:
        return ","


def scan_csv(
    scanner: BaseScanner, source: str, lines: Iterable[str]
) -> tuple[list[Finding], int]:
    """Scan CSV records cell by cell so findings carry the column header.

    The first record is treated as a header unless one of its cells already
    contains sensitive data (a header-less export), in which case columns are
    named ``col_N``.
    """
    iterator = iter(lines)
    head = list(itertools.islice(iterator, 20))
    reader = csv.reader(itertools.chain(head, iterator), delimiter=_sniff_delimiter("".join(head)))

    findings: list[Finding] = []
    names: list[str] = []
    previous_end = 0
    records = 0
    for record in reader:
        line = previous_end + 1
        previous_end = reader.line_num
        if not record:
            continue
        records += 1
        if records == 1:
            first = [
                f
                for i, cell in enumerate(record)
                for f in scanner.inspect(cell, source, line=line, column_name=f"col_{i + 1}")
            ]
            if first:
                findings.extend(first)
            else:
                names = [cell.strip() or f"col_{i + 1}" for i, cell in enumerate(record)]
            continue
        for index, cell in enumerate(record):
            if not cell.strip():
                continue
            name = names[index] if index < len(names) else f"col_{index + 1}"
            findings.extend(scanner.inspect(cell, source, line=line, column_name=name))
    return findings, previous_end


def scan_text_source(
    scanner: BaseScanner,
    source: str,
    open_lines: Callable[[], Iterable[str]],
    *,
    is_csv: bool,
) -> tuple[list[Finding], int]:
    """Scan a text source; CSV parsing failures fall back to plain lines."""
    if is_csv:
        try:
            return scan_csv(scanner, source, open_lines())
        except csv.Error:
            pass
    return scan_lines(scanner, source, open_lines())
