
import hashlib

import pytest

from app.integrity.evidence_integrity import (
    calculate_sha256,
    verify_sha256,
)


def test_sha256_matches_standard_library_digest() -> None:
    evidence = "hostname CoreRouter01"

    result = calculate_sha256(evidence)

    assert result.algorithm == "SHA-256"
    assert result.digest == hashlib.sha256(
        evidence.encode("utf-8")
    ).hexdigest()
    assert result.evidence_size == len(evidence.encode("utf-8"))


def test_identical_evidence_produces_identical_hashes() -> None:
    first = calculate_sha256("logging enabled")
    second = calculate_sha256("logging enabled")

    assert first.digest == second.digest


def test_binary_evidence_is_supported() -> None:
    evidence = b"\x00\x01\x02\xff"

    result = calculate_sha256(evidence)

    assert result.digest == hashlib.sha256(evidence).hexdigest()
    assert result.evidence_size == len(evidence)


def test_unchanged_evidence_verifies() -> None:
    evidence = "ip ssh version 2"
    expected = calculate_sha256(evidence).digest

    assert verify_sha256(evidence, expected) is True


def test_modified_evidence_fails_verification() -> None:
    evidence = "ip ssh version 2"
    expected = calculate_sha256(evidence).digest

    assert verify_sha256("ip ssh version 1", expected) is False


def test_empty_evidence_is_supported() -> None:
    result = calculate_sha256("")

    assert result.digest == hashlib.sha256(b"").hexdigest()
    assert result.evidence_size == 0


@pytest.mark.parametrize(
    "invalid_digest",
    [
        "",
        "not-a-hash",
        "a" * 63,
        "g" * 64,
    ],
)
def test_invalid_expected_digest_returns_false(
    invalid_digest: str,
) -> None:
    assert verify_sha256("evidence", invalid_digest) is False


@pytest.mark.parametrize("invalid_evidence", [None, 123, object()])
def test_unsupported_evidence_type_raises_type_error(
    invalid_evidence: object,
) -> None:
    with pytest.raises(TypeError, match="string or bytes"):
        calculate_sha256(invalid_evidence)  # type: ignore[arg-type]
from app.integrity.evidence_integrity import (
    calculate_configuration_hash,
    calculate_sha256,
    verify_sha256,
)

def test_configuration_hash_matches_original_text() -> None:
    config = (
        "hostname CoreRouter01\n"
        "ip ssh version 2\n"
        "no ip http server\n"
    )

    result = calculate_configuration_hash(config)

    assert result.algorithm == "SHA-256"
    assert result.digest == hashlib.sha256(
        config.encode("utf-8")
    ).hexdigest()
    assert result.evidence_size == len(config.encode("utf-8"))


def test_configuration_hash_detects_text_changes() -> None:
    original = "hostname CoreRouter01\nip ssh version 2\n"
    modified = "hostname CoreRouter01\nip ssh version 1\n"

    original_hash = calculate_configuration_hash(original)
    modified_hash = calculate_configuration_hash(modified)

    assert original_hash.digest != modified_hash.digest


def test_configuration_hash_detects_whitespace_changes() -> None:
    original = "hostname CoreRouter01\n"
    modified = "hostname CoreRouter01 \n"

    assert (
        calculate_configuration_hash(original).digest
        != calculate_configuration_hash(modified).digest
    )


def test_configuration_hash_rejects_non_string_input() -> None:
    with pytest.raises(
        TypeError,
        match="Configuration must be a string",
    ):
        calculate_configuration_hash(123)  # type: ignore[arg-type]
