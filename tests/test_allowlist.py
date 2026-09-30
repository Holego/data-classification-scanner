import pytest

from dcscanner.allowlist import NameMatcher, PathMatcher, glob_to_regex


@pytest.mark.parametrize(
    "pattern, path, expected",
    [
        ("*.log", "app.log", True),
        ("*.log", "logs/app.log", True),  # slash-less patterns match any segment
        ("*.log", "logs/app.txt", False),
        (".git", "repo/.git/config", True),
        ("node_modules", "a/b/node_modules/x.js", True),
        ("**/node_modules/**", "a/node_modules/x.js", True),
        ("**/node_modules/**", "node_modules", True),
        ("**/node_modules/**", "a/node_modules", True),
        ("**/node_modules/**", "a/src/x.js", False),
        ("clean/**", "clean/readme.txt", True),
        ("clean/**", "dirty/clean/readme.txt", False),
        ("exports/*.csv", "exports/a.csv", True),
        ("exports/*.csv", "exports/deep/a.csv", False),
        ("exports/**/*.csv", "exports/deep/er/a.csv", True),
        ("data/?.txt", "data/a.txt", True),
        ("data/?.txt", "data/ab.txt", False),
        ("data/[ab].txt", "data/b.txt", True),
        ("data/[!ab].txt", "data/b.txt", False),
        ("./data/x.txt", "data/x.txt", True),
    ],
)
def test_path_matcher(pattern, path, expected):
    assert PathMatcher([pattern]).matches(path) is expected


def test_absolute_patterns_match_the_absolute_path_only():
    matcher = PathMatcher(["/srv/private/**"])
    assert matcher.matches("private/x.txt", "/srv/private/x.txt")
    assert not matcher.matches("x.txt", "/srv/public/x.txt")


def test_segment_patterns_ignore_the_scan_root_location():
    matcher = PathMatcher(["tmp"])
    # the scan root lives under /tmp, but only the relative part is considered
    assert not matcher.matches("reports/a.txt", "/tmp/scan/reports/a.txt")
    assert matcher.matches("tmp/a.txt", "/tmp/scan/tmp/a.txt")


def test_empty_matcher_is_falsy_and_matches_nothing():
    matcher = PathMatcher([])
    assert not matcher and not matcher.matches("anything")


def test_name_matcher_is_case_insensitive_and_globbed():
    matcher = NameMatcher(["public.audit_*", "*.password_hash", "Tmp"])
    assert matcher.matches("public.audit_log", "audit_log")
    assert matcher.matches("public.users.password_hash", "users.password_hash", "password_hash")
    assert matcher.matches("TMP")
    assert not matcher.matches("public.users", "users")
    assert not NameMatcher([])


def test_glob_translation_escapes_regex_metacharacters():
    assert glob_to_regex("a+b(1).txt").match("a+b(1).txt")
    assert not glob_to_regex("a.txt").match("aXtxt")
