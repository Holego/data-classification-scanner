import os
import threading

import pytest

from dcscanner.allowlist import PathMatcher
from dcscanner.config import FileSourceConfig
from dcscanner.scanners import BaseScanner, FileScanner

from conftest import make_luhn

CARD = "4111 1111 1111 1111"


def scan(engine, classifier, root, threads=1, allowlist=(), **config):
    cfg = FileSourceConfig(paths=[str(root)], **config)
    scanner = FileScanner(engine, classifier, cfg, PathMatcher(allowlist), threads)
    return scanner, sorted(scanner.scan(), key=lambda f: f.sort_key())


def test_is_a_base_scanner():
    assert issubclass(FileScanner, BaseScanner)
    assert FileScanner.source_type == "file"


def test_walks_recursively_and_honours_extensions(engine, classifier, tmp_path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    for rel in ("top.txt", "a/one.log", "a/b/two.json", "a/b/three.sql", "a/b/four.csv"):
        (tmp_path / rel).write_text(f"card {CARD}\n")
    for rel in ("ignored.py", "ignored.md", "noext"):
        (tmp_path / rel).write_text(f"card {CARD}\n")

    scanner, findings = scan(engine, classifier, tmp_path)
    assert scanner.stats.files_scanned == 5
    assert {os.path.basename(f.source) for f in findings} == {"top.txt", "one.log", "two.json", "three.sql", "four.csv"}


def test_custom_extension_list(engine, classifier, tmp_path):
    (tmp_path / "a.txt").write_text(CARD)
    (tmp_path / "b.md").write_text(CARD)
    _, findings = scan(engine, classifier, tmp_path, extensions=(".md",))
    assert [os.path.basename(f.source) for f in findings] == ["b.md"]


def test_line_and_offset_coordinates(engine, classifier, tmp_path):
    (tmp_path / "notes.txt").write_text(f"first line\nsecond {CARD} here\n\nfourth a@example.com\n")
    scanner, findings = scan(engine, classifier, tmp_path)
    card, email = findings
    assert (card.location.line, card.location.offset) == (2, 8)
    assert (email.location.line, email.location.offset) == (4, 8)
    assert scanner.stats.lines_scanned == 4


def test_findings_carry_masked_values_only(engine, classifier, tmp_path):
    (tmp_path / "x.txt").write_text(f"{CARD}\njohn.smith@example.com\n123-45-6789\n")
    _, findings = scan(engine, classifier, tmp_path)
    assert {f.masked_value for f in findings} == {"**** **** **** 1111", "j******@example.com", "***-**-6789"}
    blob = repr(findings)
    for raw in ("4111", "john.smith", "6789"[:0] + "123-45"):
        assert raw not in blob


def test_csv_findings_name_the_column(engine, classifier, tmp_path):
    (tmp_path / "people.csv").write_text(
        f'id,name,card_number,contact\n1,Ann,{CARD},"ann@example.com"\n2,Bob,,bob@example.org\n'
    )
    _, findings = scan(engine, classifier, tmp_path)
    got = [(f.data_type, f.location.line, f.location.column_name) for f in findings]
    assert got == [
        ("credit_card", 2, "card_number"),
        ("email", 2, "contact"),
        ("email", 3, "contact"),
    ]


def test_csv_without_header_names_columns_by_position(engine, classifier, tmp_path):
    (tmp_path / "raw.csv").write_text(f"{CARD},ann@example.com\n")
    _, findings = scan(engine, classifier, tmp_path)
    assert [(f.data_type, f.location.column_name) for f in findings] == [("credit_card", "col_1"), ("email", "col_2")]


def test_csv_with_semicolons_and_multiline_fields(engine, classifier, tmp_path):
    (tmp_path / "eu.csv").write_text('id;note;email\n1;"line one\nline two";a@example.com\n2;x;b@example.org\n')
    _, findings = scan(engine, classifier, tmp_path)
    assert [(f.location.line, f.location.column_name) for f in findings] == [(2, "email"), (4, "email")]


def test_allowlisted_paths_are_never_opened(engine, classifier, tmp_path, monkeypatch):
    for rel in ("keep.txt", "skip/deep.txt", "node_modules/pkg/x.txt", "data.min.json"):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(CARD)

    opened = []
    real_open = open

    def spy(path, *args, **kwargs):
        opened.append(os.path.basename(str(path)))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", spy)
    scanner, findings = scan(engine, classifier, tmp_path, allowlist=["skip/**", "node_modules", "*.min.json"])
    monkeypatch.undo()

    assert [os.path.basename(f.source) for f in findings] == ["keep.txt"]
    assert opened == ["keep.txt"]
    assert scanner.stats.skipped >= 1  # pruned directories are not enumerated


def test_binary_files_are_skipped(engine, classifier, tmp_path):
    (tmp_path / "blob.txt").write_bytes(b"\x00\x01\x02" + CARD.encode() + b"\x00")
    (tmp_path / "text.txt").write_text(CARD)
    scanner, findings = scan(engine, classifier, tmp_path)
    assert [os.path.basename(f.source) for f in findings] == ["text.txt"]
    assert scanner.stats.files_scanned == 1 and scanner.stats.skipped == 1


def test_files_over_the_size_limit_are_skipped(engine, classifier, tmp_path):
    (tmp_path / "big.txt").write_text(CARD + "\n" + "x" * 2_000_000)
    (tmp_path / "small.txt").write_text(CARD)
    scanner, findings = scan(engine, classifier, tmp_path, max_file_size_mb=1)
    assert [os.path.basename(f.source) for f in findings] == ["small.txt"]
    assert scanner.stats.skipped == 1


def test_utf16_and_bom_files_are_decoded(engine, classifier, tmp_path):
    (tmp_path / "win.txt").write_bytes(("﻿" + f"card {CARD}\r\n").encode("utf-16-le"))
    (tmp_path / "bom.txt").write_bytes(b"\xef\xbb\xbf" + "mail a@example.com\n".encode())
    _, findings = scan(engine, classifier, tmp_path)
    assert {f.data_type for f in findings} == {"credit_card", "email"}


def test_invalid_utf8_does_not_hide_the_rest(engine, classifier, tmp_path):
    (tmp_path / "mixed.txt").write_bytes(b"\xfa\xfb garbage \xc3\x28\n" + f"card {CARD}\n".encode())
    _, findings = scan(engine, classifier, tmp_path)
    assert [f.data_type for f in findings] == ["credit_card"]


def test_crlf_and_missing_final_newline(engine, classifier, tmp_path):
    (tmp_path / "w.txt").write_bytes(f"a\r\n{CARD}\r\nlast a@example.com".encode())
    scanner, findings = scan(engine, classifier, tmp_path)
    assert [(f.data_type, f.location.line) for f in findings] == [("credit_card", 2), ("email", 3)]
    assert scanner.stats.lines_scanned == 3


def test_single_file_as_root(engine, classifier, tmp_path):
    target = tmp_path / "one.log"
    target.write_text(CARD)
    _, findings = scan(engine, classifier, target)
    assert len(findings) == 1


def test_missing_root_fails_loudly(engine, classifier, tmp_path):
    scanner = FileScanner(engine, classifier, FileSourceConfig(paths=[str(tmp_path / "nope")]))
    with pytest.raises(FileNotFoundError, match="does not exist"):
        list(scanner.scan())


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_symlinks_are_not_followed_by_default(engine, classifier, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text(CARD)
    root = tmp_path / "root"
    root.mkdir()
    (root / "real.txt").write_text("nothing")
    os.symlink(outside / "secret.txt", root / "link.txt")
    os.symlink(outside, root / "linkdir")

    _, findings = scan(engine, classifier, root)
    assert findings == []
    _, followed = scan(engine, classifier, root, follow_symlinks=True)
    assert followed


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_unreadable_entries_are_reported_not_fatal(engine, classifier, tmp_path):
    (tmp_path / "ok.txt").write_text(CARD)
    os.symlink(tmp_path / "does-not-exist", tmp_path / "dangling.txt")
    scanner, findings = scan(engine, classifier, tmp_path, follow_symlinks=True)
    assert len(findings) == 1
    assert len(scanner.stats.errors) == 1 and "dangling.txt" in scanner.stats.errors[0]


def test_parallel_scan_matches_sequential_scan(engine, classifier, tmp_path):
    for i in range(40):
        (tmp_path / f"f{i:02d}.txt").write_text(f"n{i} {make_luhn('4', 16, seed=i)}\nmail{i}@example.com\n")

    seq_scanner, sequential = scan(engine, classifier, tmp_path, threads=1)
    par_scanner, parallel = scan(engine, classifier, tmp_path, threads=8)
    assert sequential == parallel
    assert len(parallel) == 80
    assert par_scanner.stats.files_scanned == 40 == seq_scanner.stats.files_scanned
    assert par_scanner.stats.lines_scanned == seq_scanner.stats.lines_scanned == 80


def test_work_is_spread_across_threads(engine, classifier, tmp_path):
    for i in range(20):
        (tmp_path / f"f{i}.txt").write_text("x\n" * 10)
    seen = set()
    original = FileScanner._scan_file

    def spy(self, candidate):
        seen.add(threading.current_thread().name)
        return original(self, candidate)

    FileScanner._scan_file = spy
    try:
        scan(engine, classifier, tmp_path, threads=4)
    finally:
        FileScanner._scan_file = original
    assert all(name.startswith("dcscan") for name in seen)


def test_plan_lists_targets_without_reading_content(engine, classifier, tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_text(CARD)
    (tmp_path / "b.py").write_text(CARD)
    scanner = FileScanner(engine, classifier, FileSourceConfig(paths=[str(tmp_path)]))
    monkeypatch.setattr("builtins.open", lambda *a, **k: (_ for _ in ()).throw(AssertionError("read!")))
    targets = list(scanner.plan())
    monkeypatch.undo()
    assert [os.path.basename(t.name) for t in targets] == ["a.txt"]
    assert targets[0].size_bytes == len(CARD)


def test_sensitive_data_in_file_names_is_masked_in_the_source(engine, classifier, tmp_path):
    (tmp_path / "export_jane.roe@example.com.txt").write_text(CARD)
    _, findings = scan(engine, classifier, tmp_path)
    assert "jane.roe" not in findings[0].source
    assert findings[0].source.endswith("/e******@example.com.txt")


def test_process_executor_gives_the_same_results_as_threads(engine, classifier, tmp_path):
    for i in range(12):
        (tmp_path / f"f{i:02d}.csv").write_text(f"id,card,mail\n{i},{make_luhn('4', 16, seed=i)},u{i}@example.com\n")
    (tmp_path / "bin.txt").write_bytes(b"\x00\x01\x02")

    def run_with(executor, threads):
        cfg = FileSourceConfig(paths=[str(tmp_path)])
        sc = FileScanner(engine, classifier, cfg, PathMatcher(), threads, executor=executor)
        return sc, sorted(sc.scan(), key=lambda f: f.sort_key())

    thread_scanner, by_threads = run_with("thread", 2)
    process_scanner, by_processes = run_with("process", 2)
    assert by_processes == by_threads and len(by_processes) == 24
    assert process_scanner.stats.files_scanned == thread_scanner.stats.files_scanned == 12
    assert process_scanner.stats.skipped == thread_scanner.stats.skipped == 1
    assert process_scanner.stats.lines_scanned == thread_scanner.stats.lines_scanned == 24
