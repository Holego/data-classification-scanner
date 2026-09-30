import pytest

from dcscanner.detectors import luhn_check

from conftest import make_luhn


@pytest.mark.parametrize(
    "number",
    [
        "4111111111111111",  # Visa
        "4012888888881881",  # Visa
        "5555555555554444",  # Mastercard
        "5105105105105100",  # Mastercard
        "2223003122003222",  # Mastercard 2-series
        "378282246310005",  # American Express
        "371449635398431",  # American Express
        "6011111111111117",  # Discover
        "30569309025904",  # Diners Club
        "3530111333300000",  # JCB
        "6200000000000005",  # UnionPay
        "79927398713",  # textbook example
    ],
)
def test_valid_numbers(number):
    assert luhn_check(number) is True


@pytest.mark.parametrize(
    "number",
    [
        "4111111111111112",  # one digit off
        "4111111111111110",
        "5555555555554445",
        "378282246310006",
        "1234567812345678",
        "0000000000000001",
        "79927398710",
    ],
)
def test_invalid_numbers(number):
    assert luhn_check(number) is False


def test_separators_are_ignored():
    assert luhn_check("4111 1111 1111 1111")
    assert luhn_check("4111-1111-1111-1111")
    assert not luhn_check("4111 1111 1111 1112")


@pytest.mark.parametrize("value", ["", "0", "5", "abcd", "4111x111111111111", "4111.1111.1111.1111", "٤١١١١١١١١١١١١١١١"])
def test_malformed_input_is_rejected(value):
    assert luhn_check(value) is False


def test_all_zero_string_is_luhn_valid_but_that_is_the_callers_problem():
    # The checksum alone is not enough - which is why the card detector also
    # requires a known scheme prefix.
    assert luhn_check("0000000000000000") is True


def test_single_digit_change_is_always_detected():
    number = make_luhn("4", 16)
    assert luhn_check(number)
    for position in range(len(number)):
        for replacement in "0123456789":
            if replacement == number[position]:
                continue
            mutated = number[:position] + replacement + number[position + 1 :]
            assert not luhn_check(mutated)
