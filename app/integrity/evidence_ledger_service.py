
import re

from app.integrity.evidence_ledger import (
    EvidenceLedger,
    LedgerAnchorResult,
    LedgerAnchorStatus,
    LedgerStatus,
    LedgerVerificationResult,
)


_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def _validate_inputs(record_id: str, digest: str) -> None:
    if not isinstance(record_id, str) or not record_id.strip():
        raise ValueError("record_id must be a non-empty string.")

    if (
        not isinstance(digest, str)
        or not _SHA256_PATTERN.fullmatch(digest)
    ):
        raise ValueError("digest must be a valid SHA-256 hex digest.")


def anchor_evidence_in_ledger(
    ledger: EvidenceLedger,
    record_id: str,
    digest: str,
) -> LedgerAnchorResult:
    """Anchor evidence independently without exposing adapter exceptions."""
    _validate_inputs(record_id, digest)

    try:
        result = ledger.anchor(record_id, digest)
    except Exception:
        return LedgerAnchorResult(
            status=LedgerAnchorStatus.UNAVAILABLE,
            record_id=record_id,
            detail="Ledger anchoring could not be completed.",
        )

    if not isinstance(result, LedgerAnchorResult):
        return LedgerAnchorResult(
            status=LedgerAnchorStatus.UNAVAILABLE,
            record_id=record_id,
            detail="Ledger adapter returned an invalid anchor result.",
        )

    if not isinstance(result.status, LedgerAnchorStatus):
        return LedgerAnchorResult(
            status=LedgerAnchorStatus.UNAVAILABLE,
            record_id=record_id,
            detail="Ledger adapter returned an unknown anchor status.",
        )

    if result.record_id != record_id:
        return LedgerAnchorResult(
            status=LedgerAnchorStatus.UNAVAILABLE,
            record_id=record_id,
            detail="Ledger adapter returned a different record ID.",
        )

    return result


def verify_evidence_against_ledger(
    ledger: EvidenceLedger,
    record_id: str,
    local_digest: str,
) -> LedgerVerificationResult:
    """Compare a local digest with an independently stored ledger entry."""
    _validate_inputs(record_id, local_digest)

    try:
        result = ledger.verify(record_id, local_digest)
    except Exception:
        return LedgerVerificationResult(
            status=LedgerStatus.UNAVAILABLE,
            record_id=record_id,
            detail="Ledger verification could not be completed.",
        )

    if not isinstance(result, LedgerVerificationResult):
        return LedgerVerificationResult(
            status=LedgerStatus.UNAVAILABLE,
            record_id=record_id,
            detail="Ledger adapter returned an invalid result.",
        )

    if not isinstance(result.status, LedgerStatus):
        return LedgerVerificationResult(
            status=LedgerStatus.UNAVAILABLE,
            record_id=record_id,
            detail="Ledger adapter returned an unknown status.",
        )

    if result.record_id != record_id:
        return LedgerVerificationResult(
            status=LedgerStatus.UNAVAILABLE,
            record_id=record_id,
            detail="Ledger adapter returned a different record ID.",
        )

    return result
