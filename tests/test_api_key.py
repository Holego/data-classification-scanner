import base64
import json

import pytest

from dcscanner.detectors import ApiKeyDetector
from dcscanner.detectors.api_key import GENERIC
from dcscanner.detectors.entropy import shannon_entropy

from conftest import random_token

detector = ApiKeyDetector()


def found(text, det=detector):
    return [(m.subtype, m.value) for m in det.detect(text)]


def test_entropy_values():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abab") == pytest.approx(1.0)
    assert shannon_entropy(random_token(64)) > 4.5


# Provider tokens are assembled from parts so this file holds no literal secret.
def _provider_tokens():
    b62 = random_token(40, seed=3)
    return {
        "aws_access_key_id": "AK" + "IA" + "ABCDEFGHIJKLMNOP",
        "github_token": "gh" + "p_" + b62[:36],
        "slack_token": "xo" + "xb-" + "123456789012-" + b62[:24],
        "stripe_key": "sk" + "_live_" + b62[:24],
        "google_api_key": "AI" + "za" + random_token(35, seed=4, alphabet="abcdefABCDEF0123456789_-"),
    }


@pytest.mark.parametrize("subtype", sorted(_provider_tokens()))
def test_provider_formats(subtype):
    token = _provider_tokens()[subtype]
    assert found(f"key = {token}") == [(subtype, token)]


def test_jwt():
    def part(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    token = ".".join([part({"alg": "HS256", "typ": "JWT"}), part({"sub": "1234567890", "name": "Test"}), random_token(43, 5)])
    assert found(f"Authorization: Bearer {token}") == [("jwt", token)]


def test_private_key_header():
    header = "-----BEGIN " + "RSA PRIVATE KEY-----"
    assert found(f"{header}\nMIIB...") == [("private_key", header)]
    assert detector.mask(header, "private_key") == "-----BEGIN PRIVATE KEY----- [redacted]"


def test_generic_high_entropy_secret():
    secret = random_token(40, seed=11)
    assert found(f'api_secret: "{secret}"') == [(GENERIC, secret)]
    b64 = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzq3rXpLmNs"
    assert found(f"secret={b64}") == [(GENERIC, b64)]


@pytest.mark.parametrize(
    "text",
    [
        "550e8400-e29b-41d4-a716-446655440000",  # UUID
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",  # sha256 hex
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # sha1 hex
        "getUserAccountDetailsFromDatabase2",  # camelCase identifier
        "ConfigManagerFactoryImplementation3",
        "internal_server_error_handler_v2",  # snake_case
        "my-long-descriptive-slug-name-2024",
        "thequickbrownfoxjumpsoverthelazydog",  # no digits
        "12345678901234567890123",  # digits only
        "short1Token",  # below min length
        "aaaaaaaaaaaaaaaaaaaa1",  # low entropy
        "/usr/local/lib/python3.11/site-packages",
        "https://example.com/some/long/path/segment/12345",
    ],
)
def test_ordinary_strings_are_not_secrets(text):
    assert found(text) == []


def test_threshold_and_min_length_are_configurable():
    secret = random_token(24, seed=21)
    assert found(secret, ApiKeyDetector(entropy_threshold=8.0)) == []
    assert found(secret, ApiKeyDetector(entropy_threshold=3.0)) == [(GENERIC, secret)]
    assert found(secret, ApiKeyDetector(min_length=30, entropy_threshold=3.0)) == []
    assert found(secret, ApiKeyDetector(detect_generic=False, entropy_threshold=3.0)) == []


def test_provider_token_is_reported_once_not_again_as_generic():
    token = "gh" + "p_" + random_token(36, seed=8)
    assert len(found(token)) == 1


def test_mask_never_reveals_the_secret_body():
    token = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
    assert detector.mask(token, "aws_access_key_id") == "AKIA********"
    secret = random_token(40, seed=11)
    masked = detector.mask(secret, GENERIC)
    assert masked == secret[:2] + "********"
