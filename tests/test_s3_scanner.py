import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from dcscanner.allowlist import PathMatcher
from dcscanner.config import S3SourceConfig
from dcscanner.scanners import BaseScanner, S3Scanner

from conftest import make_luhn

BUCKET = "test-bucket"
CARD = "4111 1111 1111 1111"


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    for name, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)


@pytest.fixture
def s3():
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=BUCKET)
        yield client


def put(client, key, body):
    client.put_object(Bucket=BUCKET, Key=key, Body=body if isinstance(body, bytes) else body.encode())


def scanner(engine, classifier, client, threads=1, allowlist=(), **config):
    config.setdefault("bucket", BUCKET)
    return S3Scanner(engine, classifier, S3SourceConfig(**config), PathMatcher(allowlist), threads, client=client)


def run(sc):
    return sorted(sc.scan(), key=lambda f: f.sort_key())


def test_is_a_base_scanner():
    assert issubclass(S3Scanner, BaseScanner)
    assert S3Scanner.source_type == "s3"


def test_scans_objects_and_reports_s3_uris(engine, classifier, s3):
    put(s3, "uploads/customers.csv", f"id,card,mail\n1,{CARD},ann@example.com\n")
    put(s3, "uploads/notes.txt", "hello\nssn 123-45-6789\n")
    sc = scanner(engine, classifier, s3)
    findings = run(sc)
    got = [(f.source, f.data_type, f.location.line, f.location.column_name) for f in findings]
    assert got == [
        (f"s3://{BUCKET}/uploads/customers.csv", "credit_card", 2, "card"),
        (f"s3://{BUCKET}/uploads/customers.csv", "email", 2, "mail"),
        (f"s3://{BUCKET}/uploads/notes.txt", "national_id", 2, None),
    ]
    assert sc.stats.objects_scanned == 2 and sc.stats.lines_scanned == 4


def test_prefix_limits_the_scan(engine, classifier, s3):
    put(s3, "uploads/a.txt", CARD)
    put(s3, "uploads/deep/b.txt", CARD)
    put(s3, "other/c.txt", CARD)
    put(s3, "uploadsX/d.txt", CARD)
    sources = {f.source for f in run(scanner(engine, classifier, s3, prefix="uploads/"))}
    assert sources == {f"s3://{BUCKET}/uploads/a.txt", f"s3://{BUCKET}/uploads/deep/b.txt"}
    nested = {f.source for f in run(scanner(engine, classifier, s3, prefix="uploads/deep/"))}
    assert nested == {f"s3://{BUCKET}/uploads/deep/b.txt"}


def test_no_prefix_scans_the_whole_bucket(engine, classifier, s3):
    put(s3, "a.txt", CARD)
    put(s3, "x/y/z.log", CARD)
    assert len(run(scanner(engine, classifier, s3))) == 2


def test_extension_filter_and_folder_placeholders(engine, classifier, s3):
    put(s3, "folder/", "")
    put(s3, "data.txt", CARD)
    put(s3, "image.png", CARD)
    put(s3, "script.py", CARD)
    put(s3, "UPPER.CSV", f"c\n{CARD}\n")
    put(s3, "empty.txt", "")
    sc = scanner(engine, classifier, s3)
    assert {f.source.rsplit("/", 1)[1] for f in run(sc)} == {"data.txt", "UPPER.CSV"}
    custom = scanner(engine, classifier, s3, extensions=(".png",))
    assert {f.source.rsplit("/", 1)[1] for f in run(custom)} == {"image.png"}


def test_pagination_covers_every_object(engine, classifier, s3):
    for i in range(7):
        put(s3, f"many/{i}.txt", make_luhn("4", 16, seed=i))
    sc = scanner(engine, classifier, s3, prefix="many/", page_size=2)
    assert len(run(sc)) == 7 and sc.stats.objects_scanned == 7


def test_allowlisted_keys_are_never_downloaded(engine, classifier, s3):
    put(s3, "keep/a.txt", CARD)
    put(s3, "archive/old.txt", CARD)
    put(s3, "keep/scratch.tmp.txt", CARD)

    downloads = []
    original = s3.get_object

    def spy(**kwargs):
        downloads.append(kwargs["Key"])
        return original(**kwargs)

    s3.get_object = spy
    sc = scanner(engine, classifier, s3, allowlist=["archive/**", "*.tmp.txt"])
    findings = run(sc)
    assert [f.source.rsplit("/", 1)[1] for f in findings] == ["a.txt"]
    assert downloads == ["keep/a.txt"]
    assert sc.stats.skipped == 2


def test_objects_over_the_size_limit_are_skipped(engine, classifier, s3):
    put(s3, "big.txt", CARD + "\n" + "x" * 1_500_000)
    put(s3, "small.txt", CARD)
    sc = scanner(engine, classifier, s3, max_object_size_mb=1)
    assert [f.source.rsplit("/", 1)[1] for f in run(sc)] == ["small.txt"]
    assert sc.stats.skipped == 1


def test_binary_objects_are_skipped(engine, classifier, s3):
    put(s3, "blob.txt", b"\x00\x01" + CARD.encode())
    put(s3, "ok.txt", CARD)
    sc = scanner(engine, classifier, s3)
    assert [f.source.rsplit("/", 1)[1] for f in run(sc)] == ["ok.txt"]
    assert sc.stats.objects_scanned == 1 and sc.stats.skipped == 1


def test_large_object_is_streamed_line_by_line(engine, classifier, s3):
    body = "".join(f"row {i} filler filler filler\n" for i in range(20000)) + f"card {CARD}\n"
    put(s3, "big.log", body)
    (finding,) = run(scanner(engine, classifier, s3))
    assert finding.location.line == 20001


def test_parallel_scan_matches_sequential(engine, classifier, s3):
    for i in range(30):
        put(s3, f"p/{i:02d}.txt", f"{make_luhn('51', 16, seed=i)}\nm{i}@example.com\n")
    seq = run(scanner(engine, classifier, s3, threads=1, prefix="p/"))
    par = run(scanner(engine, classifier, s3, threads=8, prefix="p/"))
    assert seq == par and len(par) == 60


def test_findings_hold_masked_values_only(engine, classifier, s3):
    put(s3, "a.txt", f"{CARD} jane@example.com")
    findings = run(scanner(engine, classifier, s3))
    assert {f.masked_value for f in findings} == {"**** **** **** 1111", "j***@example.com"}
    assert "4111" not in repr(findings)


def test_missing_bucket_fails_the_source(engine, classifier, s3):
    sc = scanner(engine, classifier, s3, bucket="no-such-bucket")
    with pytest.raises(ClientError) as info:
        list(sc.scan())
    assert info.value.response["Error"]["Code"] == "NoSuchBucket"


def test_object_that_disappears_is_reported_not_fatal(engine, classifier, s3):
    put(s3, "a.txt", CARD)
    put(s3, "b.txt", CARD)
    original = s3.get_object

    def flaky(**kwargs):
        if kwargs["Key"] == "a.txt":
            raise ClientError({"Error": {"Code": "NoSuchKey", "Message": "gone"}}, "GetObject")
        return original(**kwargs)

    s3.get_object = flaky
    sc = scanner(engine, classifier, s3)
    findings = run(sc)
    assert [f.source.rsplit("/", 1)[1] for f in findings] == ["b.txt"]
    assert len(sc.stats.errors) == 1 and "NoSuchKey" in sc.stats.errors[0]


def test_dry_run_lists_objects_without_downloading_them(engine, classifier, s3):
    put(s3, "a.txt", CARD)
    put(s3, "b.csv", CARD)

    def forbidden(**kwargs):
        raise AssertionError("dry run must not download")

    s3.get_object = forbidden
    targets = list(scanner(engine, classifier, s3).plan())
    assert [t.name for t in targets] == [f"s3://{BUCKET}/a.txt", f"s3://{BUCKET}/b.csv"]
    assert targets[0].size_bytes == len(CARD)


def test_bucket_is_required(engine, classifier, s3):
    with pytest.raises(ValueError, match="bucket"):
        list(scanner(engine, classifier, s3, bucket="").scan())


def test_default_client_uses_the_credentials_chain(engine, classifier, s3):
    """Without an injected client the scanner builds one from the environment."""
    put(s3, "a.txt", CARD)
    sc = S3Scanner(engine, classifier, S3SourceConfig(bucket=BUCKET))
    assert len(list(sc.scan())) == 1
