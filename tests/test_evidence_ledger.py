
from app.integrity.evidence_ledger import (
    LedgerStatus,
    LedgerVerificationResult,
)


def test_ledger_statuses_are_explicit():
    assert LedgerStatus.MATCH.value == "MATCH"
    assert LedgerStatus.MISMATCH.value == "MISMATCH"
    assert LedgerStatus.NOT_FOUND.value == "NOT_FOUND"
    assert LedgerStatus.UNAVAILABLE.value == "UNAVAILABLE"


def test_verification_result_records_status_and_record_id():
    result = LedgerVerificationResult(
        status=LedgerStatus.MATCH,
        record_id="evidence-123",
    )

    assert result.status is LedgerStatus.MATCH
    assert result.record_id == "evidence-123"
    assert result.detail == ""


def test_verification_result_can_include_safe_diagnostic_detail():
    result = LedgerVerificationResult(
        status=LedgerStatus.UNAVAILABLE,
        record_id="evidence-123",
        detail="Ledger service is unavailable.",
    )

    assert result.status is LedgerStatus.UNAVAILABLE
    assert result.detail == "Ledger service is unavailable."
