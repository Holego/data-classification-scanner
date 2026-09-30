import pytest

from conftest import make_luhn
from dcscanner.config import ConfigError, parse_config
from dcscanner.detectors import IdPattern, NationalIdDetector, build_engine
from dcscanner.detectors.national_id import (
    validate_br_cpf,
    validate_ca_sin,
    validate_pl_pesel,
    validate_ru_inn,
    validate_ru_snils,
    validate_us_ssn,
)


def found(detector, text):
    return [(m.subtype, m.value) for m in detector.detect(text)]


ssn = NationalIdDetector(["us_ssn"])


@pytest.mark.parametrize("value", ["123-45-6789", "001-01-0001", "899-99-9999", "078-05-1120"])
def test_ssn_positive(value):
    assert found(ssn, f"SSN: {value}.") == [("us_ssn", value)]


@pytest.mark.parametrize(
    "text",
    [
        "000-12-3456",  # area 000 never issued
        "666-12-3456",  # area 666 never issued
        "900-12-3456",  # 9xx reserved
        "123-00-4567",  # group 00
        "123-45-0000",  # serial 0000
        "12-345-6789",  # wrong grouping
        "1234-56-7890",  # longer number
        "123-45-67890",
        "123456789",  # no separators
        "123 45 6789",
        "555-123-4567",  # phone-like
        "2024-05-1234",  # date-like
    ],
)
def test_ssn_negative(text):
    assert found(ssn, text) == []


def test_ssn_mask_keeps_format_and_last_four():
    (match,) = ssn.detect("123-45-6789")
    assert ssn.mask(match.value, match.subtype) == "***-**-6789"


# --- other countries via built-in profiles ---------------------------------


def test_ca_sin():
    detector = NationalIdDetector(["ca_sin"])
    sin = make_luhn("1", 9)
    spaced = f"{sin[:3]} {sin[3:6]} {sin[6:]}"
    dashed = spaced.replace(" ", "-")
    bad = sin[:-1] + str((int(sin[-1]) + 1) % 10)
    assert found(detector, f"SIN {spaced}") == [("ca_sin", spaced)]
    assert found(detector, f"SIN {dashed}") == [("ca_sin", dashed)]
    assert found(detector, f"{bad[:3]} {bad[3:6]} {bad[6:]}") == []  # bad checksum
    assert found(detector, f"{sin[:3]}-{sin[3:6]} {sin[6:]}") == []  # mixed separators
    assert found(detector, "046 454 286") == []  # first digit 0 is never issued


def test_uk_nino():
    detector = NationalIdDetector(["uk_nino"])
    assert found(detector, "NI number AB 12 34 56 C") == [("uk_nino", "AB 12 34 56 C")]
    assert found(detector, "AB123456C")
    assert found(detector, "BG 12 34 56 A") == []  # disallowed prefix
    assert found(detector, "AB 12 34 56 E") == []  # suffix must be A-D


def test_ru_inn_needs_context_and_checksum():
    detector = NationalIdDetector(["ru_inn"])
    assert found(detector, "ИНН 7707083893") == [("ru_inn", "7707083893")]
    assert found(detector, "tax id: 500100732259") == [("ru_inn", "500100732259")]
    assert found(detector, "7707083893") == []  # no keyword nearby
    assert found(detector, "ИНН 7707083894") == []  # wrong checksum
    assert found(detector, "inn " + "x" * 200 + " 7707083893") == []  # keyword too far


def test_ru_snils():
    detector = NationalIdDetector(["ru_snils"])
    assert found(detector, "СНИЛС 112-233-445 95") == [("ru_snils", "112-233-445 95")]
    assert found(detector, "snils 11223344595") == [("ru_snils", "11223344595")]
    assert found(detector, "11223344595") == []
    assert found(detector, "112-233-445 96") == []


def test_pl_pesel():
    detector = NationalIdDetector(["pl_pesel"])
    assert found(detector, "PESEL 44051401359") == [("pl_pesel", "44051401359")]
    assert found(detector, "44051401359") == []
    assert found(detector, "PESEL 44051401358") == []


def test_br_cpf():
    detector = NationalIdDetector(["br_cpf"])
    assert found(detector, "CPF 529.982.247-25") == [("br_cpf", "529.982.247-25")]
    assert found(detector, "cpf 52998224725") == [("br_cpf", "52998224725")]
    assert found(detector, "111.111.111-11") == []
    assert found(detector, "529.982.247-26") == []


def test_validators_directly():
    assert validate_us_ssn("123-45-6789") and not validate_us_ssn("000-45-6789")
    assert validate_ca_sin(make_luhn("1", 9)) and not validate_ca_sin("046454286")
    assert validate_ru_inn("7707083893") and validate_ru_inn("500100732259")
    assert not validate_ru_inn("123")
    assert validate_ru_snils("112-233-445 95")
    assert validate_pl_pesel("44051401359")
    assert validate_br_cpf("52998224725")


def test_multiple_profiles_together():
    detector = NationalIdDetector(["us_ssn", "uk_nino"])
    assert {s for s, _ in found(detector, "123-45-6789 and AB 12 34 56 C")} == {"us_ssn", "uk_nino"}


def test_unknown_profile():
    with pytest.raises(ValueError, match="unknown national_id profile"):
        NationalIdDetector(["atlantis"])


# --- configurable regex ----------------------------------------------------


def test_custom_pattern_from_config():
    pattern = IdPattern.from_config(
        {
            "name": "de_steuer_id",
            "regex": r"(?<!\d)\d{2} \d{3} \d{3} \d{3}(?!\d)",
            "keep_last": 3,
            "context_keywords": ["steuer-id"],
        }
    )
    detector = NationalIdDetector(profiles=[], custom_patterns=[pattern])
    assert found(detector, "Steuer-ID 12 345 678 901") == [("de_steuer_id", "12 345 678 901")]
    assert found(detector, "12 345 678 901") == []
    (match,) = detector.detect("Steuer-ID 12 345 678 901")
    assert detector.mask(match.value, match.subtype) == "** *** *** 901"


def test_engine_built_from_yaml_style_settings():
    engine = build_engine(
        {
            "email": {"enabled": False},
            "credit_card": {"enabled": False},
            "api_key": {"enabled": False},
            "national_id": {
                "profiles": [],
                "custom_patterns": [{"name": "xx_id", "regex": r"\bXX-\d{6}\b"}],
            },
        }
    )
    matches = engine.find("id XX-123456 and 123-45-6789")
    assert [(m.detector, m.subtype) for m in matches] == [("national_id", "xx_id")]
    assert engine.mask(matches[0]) == "**-**3456"


def test_custom_pattern_errors():
    with pytest.raises(ValueError, match="invalid regex"):
        IdPattern.from_config({"name": "bad", "regex": "("})
    with pytest.raises(ValueError, match="missing 'regex'"):
        IdPattern.from_config({"name": "bad"})
    with pytest.raises(ValueError, match="unknown validator"):
        IdPattern.from_config({"name": "bad", "regex": "x", "validator": "nope"})
    with pytest.raises(ConfigError, match="invalid regex"):
        parse_config({"detectors": {"national_id": {"custom_patterns": [{"name": "x", "regex": "("}]}}})
