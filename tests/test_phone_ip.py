import pytest

from dcscanner.detectors import IPAddressDetector, PhoneDetector


def phones(text):
    return [m.value for m in PhoneDetector().detect(text)]


def ips(text, **kwargs):
    return [(m.subtype, m.value) for m in IPAddressDetector(**kwargs).detect(text)]


@pytest.mark.parametrize(
    "number",
    [
        "+1 (212) 555-0123",
        "+1 212 555 0123",
        "(212) 555-0123",
        "212-555-0123",
        "212.555.0123",
        "+44 20 7946 0958",
        "+7 912 345 67 89",
        "+79123456789",
        "8 (912) 345-67-89",
        "+49 30 901820",
    ],
)
def test_phone_positive(number):
    assert phones(f"call {number} today") == [number]


@pytest.mark.parametrize(
    "text",
    [
        "2125550123",  # bare digits are ambiguous
        "123456",
        "+1 234",
        "+00 000 000 0000",
        "1-800",
        "2024-05-17",
        "10:30:45",
        "order 12345678901234567890",
        "+123456789012345678",  # more than 15 digits
        "112-233-4455-9999",
    ],
)
def test_phone_negative(text):
    assert phones(text) == []


def test_phone_mask_keeps_last_four():
    (match,) = PhoneDetector().detect("+1 (212) 555-0123")
    assert PhoneDetector().mask(match.value) == "+* (***) ***-0123"


@pytest.mark.parametrize(
    "text, expected",
    [
        ("from 192.168.10.5 port", [("ipv4", "192.168.10.5")]),
        ("8.8.8.8", [("ipv4", "8.8.8.8")]),
        ("255.255.255.255", [("ipv4", "255.255.255.255")]),
        ("a 10.0.0.1, b 10.0.0.2", [("ipv4", "10.0.0.1"), ("ipv4", "10.0.0.2")]),
        ("2001:db8::1", [("ipv6", "2001:db8::1")]),
        ("fe80::1ff:fe23:4567:890a", [("ipv6", "fe80::1ff:fe23:4567:890a")]),
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", [("ipv6", "2001:0db8:85a3:0000:0000:8a2e:0370:7334")]),
        ("::1", [("ipv6", "::1")]),
    ],
)
def test_ip_positive(text, expected):
    assert ips(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "256.1.1.1",
        "1.2.3",
        "1.2.3.4.5",  # version-like
        "v1.2.3.4x",
        "01.02.03.04",
        "12:30:45",  # time of day
        "aa:bb:cc:dd:ee:ff",  # MAC address
        "10.0.0.1234",
        "abc1.2.3.4",
        "Programming Language :: Python :: 3",  # "::" is the unspecified address
        "0.0.0.0",
    ],
)
def test_ip_negative(text):
    assert ips(text) == []


def test_ignore_private_ranges():
    text = "10.1.2.3 192.168.0.1 127.0.0.1 8.8.4.4"
    assert ips(text, ignore_private=True) == [("ipv4", "8.8.4.4")]


def test_ip_mask():
    detector = IPAddressDetector()
    assert detector.mask("192.168.10.5") == "192.168.*.*"
    assert detector.mask("2001:db8::1") == "2001:db8:****"
    assert detector.mask("::1") == "::****"
