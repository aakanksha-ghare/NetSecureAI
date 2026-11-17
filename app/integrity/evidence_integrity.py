
import hashlib
import hmac
from dataclasses import dataclass


@dataclass(frozen=True)
class EvidenceHash:
    """SHA-256 digest recorded for a piece of evidence."""

    algorithm: str
    digest: str
    evidence_size: int


def calculate_sha256(evidence: str | bytes) -> EvidenceHash:
    """Calculate a SHA-256 digest for text or binary evidence.

    Text is encoded as UTF-8. Binary evidence is hashed as-is.
    """
    if isinstance(evidence, str):
        evidence_bytes = evidence.encode("utf-8")
    elif isinstance(evidence, bytes):
        evidence_bytes = evidence
    else:
        raise TypeError("Evidence must be a string or bytes object.")

    digest = hashlib.sha256(evidence_bytes).hexdigest()

    return EvidenceHash(
        algorithm="SHA-256",
        digest=digest,
        evidence_size=len(evidence_bytes),
    )


def calculate_configuration_hash(
    config_text: str,
) -> EvidenceHash:
    """Hash the exact original network configuration text.

    The original text is encoded as UTF-8 without normalization.
    Even whitespace or line-ending changes produce a different hash.
    """
    if not isinstance(config_text, str):
        raise TypeError("Configuration must be a string.")

    return calculate_sha256(config_text)


def verify_sha256(
    evidence: str | bytes,
    expected_digest: str,
) -> bool:
    """Check whether evidence matches a previously recorded SHA-256 digest.

    Returns False for malformed or non-SHA-256 expected digests.
    Raises TypeError if evidence has an unsupported type.
    """
    if not isinstance(expected_digest, str):
        return False

    if (
        len(expected_digest) != 64
        or any(
            character not in "0123456789abcdefABCDEF"
            for character in expected_digest
        )
    ):
        return False

    actual = calculate_sha256(evidence).digest

    return hmac.compare_digest(
        actual,
        expected_digest.lower(),
    )
