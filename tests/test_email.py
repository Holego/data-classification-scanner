import pytest

from dcscanner.detectors import EmailDetector, is_valid_email, mask_email

detector = EmailDetector()


def found(text):
    return [m.value for m in detector.detect(text)]


@pytest.mark.parametrize(
    "address",
    [
        "jane.doe@example.com",
        "j+tag@sub.domain.co.uk",
        "first_last@company.io",
        "a@b.de",
        "user-name@my-host.org",
        "UPPER@EXAMPLE.COM",
        "digits123@host9.net",
        "ivan@example.xn--p1ai",  # internationalised TLD (.рф) in punycode
    ],
)
def test_valid_addresses(address):
    assert found(f"contact: {address}, thanks") == [address]


@pytest.mark.parametrize(
    "text",
    [
        "logo@2x.png",  # image name, png is not a TLD
        "archive@v2.js",
        "user@host.invalidtld",
        "user@localhost",
        "user@@example.com",
        "@example.com",
        "user@.com",
        "user@example.c",
        "user@-example.com",
        "user@example-.com",
        "a..b@example.com",
        ".a@example.com",
        "a.@example.com",
        "no at sign here",
        "user @example.com",
        "user@ example.com",
    ],
)
def test_rejects_invalid_or_look_alike(text):
    assert found(text) == []


def test_trailing_punctuation_is_not_part_of_the_address():
    assert found("Mail me: x@y.io.") == ["x@y.io"]
    assert found("(x@y.io)") == ["x@y.io"]
    assert found('"x@y.io",') == ["x@y.io"]


def test_address_followed_by_an_unrelated_suffix_label():
    # exports are often named after their owner
    assert found("export_jane@example.com.txt") == ["export_jane@example.com"]
    assert found("a@b.co.uk.bak") == ["a@b.co.uk"]
    assert found("logo@2x.png.bak") == []


def test_several_addresses_and_offsets():
    text = "a@one.com; b@two.org"
    matches = list(detector.detect(text))
    assert [(m.start, m.end) for m in matches] == [(0, 9), (11, 20)]


def test_ignore_domains():
    detector = EmailDetector(ignore_domains=["example.com", "@Test.Org"])
    text = "a@example.com b@test.org c@real.com"
    assert [m.value for m in detector.detect(text)] == ["c@real.com"]


def test_length_limits():
    assert found("a" * 65 + "@example.com") == []  # local part is capped at 64
    assert found("a" * 64 + "@example.com") != []
    assert not is_valid_email("x@" + "a" * 64 + ".com")


@pytest.mark.parametrize(
    "value, expected",
    [
        ("jane.doe@example.com", "j******@example.com"),
        ("bob@example.org", "b**@example.org"),
        ("x@y.io", "x**@y.io"),
    ],
)
def test_mask(value, expected):
    assert mask_email(value) == expected
    local = value.split("@")[0]
    if len(local) > 1:
        assert local[1:] not in mask_email(value)
