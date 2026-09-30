import pytest

from dcscanner.classifiers import RiskClassifier
from dcscanner.models import RiskLevel


@pytest.mark.parametrize(
    "data_type, risk, category",
    [
        ("credit_card", RiskLevel.HIGH, "PCI"),
        ("national_id", RiskLevel.HIGH, "PII"),
        ("api_key", RiskLevel.HIGH, "Credentials"),
        ("email", RiskLevel.MEDIUM, "PII"),
        ("phone", RiskLevel.MEDIUM, "PII"),
        ("ip_address", RiskLevel.LOW, "Network"),
    ],
)
def test_default_levels(data_type, risk, category):
    result = RiskClassifier().classify(data_type)
    assert (result.risk, result.category) == (risk, category)


def test_unknown_types_default_to_medium():
    assert RiskClassifier().classify("passport").risk is RiskLevel.MEDIUM


def test_type_override_keeps_category():
    result = RiskClassifier({"email": "high"}).classify("email", "anything")
    assert (result.risk, result.category) == (RiskLevel.HIGH, "PII")


def test_subtype_override_is_more_specific_than_type_override():
    classifier = RiskClassifier({"national_id": "MEDIUM", "national_id.uk_nino": "LOW"})
    assert classifier.classify("national_id", "us_ssn").risk is RiskLevel.MEDIUM
    assert classifier.classify("national_id", "uk_nino").risk is RiskLevel.LOW
    assert classifier.classify("credit_card", "visa").risk is RiskLevel.HIGH


def test_risk_level_parsing_and_ordering():
    assert RiskLevel.parse(" high ") is RiskLevel.HIGH
    assert RiskLevel.HIGH.at_least(RiskLevel.MEDIUM)
    assert not RiskLevel.LOW.at_least(RiskLevel.MEDIUM)
    with pytest.raises(ValueError, match="unknown risk level"):
        RiskLevel.parse("critical")
