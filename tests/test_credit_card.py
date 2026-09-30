import pytest

from dcscanner.detectors import CreditCardDetector, identify_scheme, mask_card_number

from conftest import make_luhn

detector = CreditCardDetector()


def find(text):
    return list(detector.detect(text))


@pytest.mark.parametrize(
    "number, scheme",
    [
        ("4111111111111111", "visa"),
        (make_luhn("4", 19), "visa"),
        ("5555555555554444", "mastercard"),
        ("2223003122003222", "mastercard"),
        ("378282246310005", "amex"),
        ("6011111111111117", "discover"),
        (make_luhn("65", 16), "discover"),
        ("30569309025904", "diners"),
        (make_luhn("39", 14), "diners"),
        ("3530111333300000", "jcb"),
        ("6200000000000005", "unionpay"),
        (make_luhn("2201", 16), "mir"),
        (make_luhn("6759", 16), "maestro"),
    ],
)
def test_detects_each_scheme(number, scheme):
    matches = find(f"payment card {number} on file")
    assert [(m.value, m.subtype) for m in matches] == [(number, scheme)]


@pytest.mark.parametrize(
    "written",
    ["4111 1111 1111 1111", "4111-1111-1111-1111", "378282246310005", "3782 822463 10005", "3056 930902 5904"],
)
def test_detects_grouped_formats(written):
    matches = find(f"Card: {written}.")
    assert len(matches) == 1
    assert matches[0].value == written


def test_reports_exact_span():
    text = "xx 4111 1111 1111 1111 yy"
    (match,) = find(text)
    assert text[match.start : match.end] == "4111 1111 1111 1111"


def test_multiple_cards_on_one_line():
    matches = find("a 4111111111111111, b 5555555555554444 and c 378282246310005")
    assert [m.subtype for m in matches] == ["visa", "mastercard", "amex"]


def test_card_after_a_date_is_still_found():
    matches = find("2024-01-15 4111 1111 1111 1111")
    assert [m.value for m in matches] == ["4111 1111 1111 1111"]


@pytest.mark.parametrize(
    "text",
    [
        "4111111111111112",  # right prefix, fails Luhn
        "1234567812345678",  # fails Luhn
        "1234-5678-9012-3456",
        make_luhn("9", 16),  # passes Luhn, no scheme
        make_luhn("4", 12),  # too short
        make_luhn("4", 20),  # too long
        "1700000000000",  # epoch millis
        "20240501123045",  # timestamp
        "ORD4111111111111111",  # glued to letters
        "4111111111111111abc",
        "id-4111111111111111x",
        "1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6",  # digits separated by spaces
        "4111 11 11 1111 1111",  # implausible grouping
        "0000000000000000",
        "",
    ],
)
def test_rejects_look_alikes(text):
    assert find(text) == []


def test_luhn_is_what_filters_random_sixteen_digit_numbers():
    """Of 1000 consecutive Visa-prefixed 16-digit numbers only ~10% pass."""
    hits = sum(bool(find(str(4_000_000_000_000_000 + i))) for i in range(1000))
    assert 60 <= hits <= 140


def test_long_digit_run_with_separators_does_not_blow_up():
    text = "1 " * 20000
    assert find(text) == []


@pytest.mark.parametrize(
    "value, expected",
    [
        ("4111111111111111", "**** **** **** 1111"),
        ("4111 1111 1111 1111", "**** **** **** 1111"),
        ("4111-1111-1111-1111", "**** **** **** 1111"),
        ("378282246310005", "**** ****** *0005"),
        ("30569309025904", "**** ****** 5904"),
        ("4111111111111111222", "**** **** **** *** 1222"),
    ],
)
def test_mask_keeps_only_last_four(value, expected):
    assert mask_card_number(value) == expected


def test_identify_scheme():
    assert identify_scheme("4111111111111111") == "visa"
    assert identify_scheme("1111111111111111") is None
