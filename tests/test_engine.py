from dcscanner.detectors import DetectionEngine, EmailDetector, Match, PhoneDetector, build_engine
from dcscanner.detectors.base import BaseDetector, mask_keep_last

from conftest import ALL_DETECTORS, make_luhn


def test_match_repr_hides_the_value():
    match = Match("credit_card", "4111111111111111", 0, 16, "visa")
    assert "4111" not in repr(match)
    assert "credit_card" in repr(match)


def test_results_are_ordered_by_position(engine):
    text = "b@two.org then 4111111111111111 then a@one.com"
    starts = [m.start for m in engine.find(text)]
    assert starts == sorted(starts) and len(starts) == 3


def test_higher_priority_detector_wins_an_overlap():
    # A run of digits that is both a valid card and phone-shaped: the card
    # detector (priority 10) must keep it and the phone detector must not.
    card = make_luhn("4", 16)
    text = f"+{card}"
    engine = build_engine({"phone": {"enabled": True}, "credit_card": {"enabled": True}})
    assert {m.detector for m in engine.find(text)} == {"credit_card"}


def test_non_overlapping_matches_from_different_detectors_are_kept(engine):
    matches = engine.find("mail a@one.com from 10.1.2.3")
    assert {m.detector for m in matches} == {"email", "ip_address"}


def test_engine_rejects_duplicate_detector_names():
    import pytest

    with pytest.raises(ValueError, match="duplicate"):
        DetectionEngine([EmailDetector(), EmailDetector()])


def test_redact_replaces_values_with_masks(engine):
    text = "user a.b@example.com paid with 4111 1111 1111 1111 (ssn 123-45-6789)"
    redacted = engine.redact(text)
    assert redacted == "user a**@example.com paid with **** **** **** 1111 (ssn ***-**-6789)"
    for raw in ("a.b@example.com", "4111 1111 1111 1111", "123-45-6789"):
        assert raw not in redacted


def test_redact_leaves_clean_text_untouched(engine):
    assert engine.redact("nothing to see here") == "nothing to see here"
    assert engine.redact("") == ""


def test_empty_engine_finds_nothing():
    assert DetectionEngine([]).find("a@b.com 4111111111111111") == []


def test_default_registry_enables_core_detectors_only():
    names = build_engine().detector_names
    assert set(names) == {"credit_card", "national_id", "api_key", "email"}
    assert set(build_engine(ALL_DETECTORS).detector_names) == set(ALL_DETECTORS)


def test_unknown_detector_setting_is_rejected():
    import pytest

    with pytest.raises(ValueError, match="unknown detector"):
        build_engine({"passport": {"enabled": True}})


def test_custom_detectors_plug_in():
    class OrderIdDetector(BaseDetector):
        name = "order_id"
        priority = 5

        def detect(self, text):
            idx = text.find("ORD-")
            if idx >= 0:
                yield Match(self.name, text[idx : idx + 10], idx, idx + 10)

        def mask(self, value, subtype=None):
            return mask_keep_last(value, 2)

    engine = DetectionEngine([OrderIdDetector(), PhoneDetector()])
    (match,) = engine.find("see ORD-123456")
    assert engine.mask(match) == "***-****56"


def test_mask_keep_last_edge_cases():
    assert mask_keep_last("123-45-6789", 4) == "***-**-6789"
    assert mask_keep_last("12", 4) == "12"
    assert mask_keep_last("abc", 0) == "***"
