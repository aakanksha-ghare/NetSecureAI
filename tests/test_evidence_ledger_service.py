
import pytest

from app.integrity.evidence_ledger import (
    LedgerStatus,
    LedgerVerificationResult,
)
from app.integrity.evidence_ledger_service import (
    verify_evidence_against_ledger,
)


class FakeLedger:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error

    def verify(self, record_id, expected_digest):
        if self.error:
            raise self.error
        return self.result


@pytest.mark.parametrize("status", list(LedgerStatus))
def test_service_preserves_valid_ledger_outcomes(status):
    result = LedgerVerificationResult(
        status=status,
        record_id="evidence-123",
    )

    actual = verify_evidence_against_ledger(
        FakeLedger(result=result),
        "evidence-123",
        "a" * 64,
    )

    assert actual.status is status
    assert actual.record_id == "evidence-123"


def test_service_reports_adapter_exception_as_unavailable():
    actual = verify_evidence_against_ledger(
        FakeLedger(error=ConnectionError("internal connection details")),
        "evidence-123",
        "a" * 64,
    )

    assert actual.status is LedgerStatus.UNAVAILABLE
    assert "internal connection details" not in actual.detail


def test_service_rejects_invalid_adapter_result():
    actual = verify_evidence_against_ledger(
        FakeLedger(result={"status": "MATCH"}),
        "evidence-123",
        "a" * 64,
    )

    assert actual.status is LedgerStatus.UNAVAILABLE


def test_service_rejects_mismatched_record_id():
    actual = verify_evidence_against_ledger(
        FakeLedger(
            result=LedgerVerificationResult(
                status=LedgerStatus.MATCH,
                record_id="different-record",
            )
        ),
        "evidence-123",
        "a" * 64,
    )

    assert actual.status is LedgerStatus.UNAVAILABLE
    assert actual.record_id == "evidence-123"


@pytest.mark.parametrize(
    ("record_id", "digest"),
    [
        ("", "a" * 64),
        ("evidence-123", ""),
        (None, "a" * 64),
        ("evidence-123", None),
    ],
)
def test_service_rejects_missing_inputs(record_id, digest):
    with pytest.raises(ValueError):
        verify_evidence_against_ledger(
            FakeLedger(),
            record_id,
            digest,
        )

@pytest.mark.parametrize(
    "digest",
    [
        "not-a-digest",
        "a" * 63,
        "g" * 64,
        "a" * 65,
    ],
)
def test_service_rejects_invalid_sha256_digest(digest):
    with pytest.raises(ValueError, match="valid SHA-256"):
        verify_evidence_against_ledger(
            FakeLedger(),
            "evidence-123",
            digest,
        )


def test_service_rejects_non_enum_adapter_status():
    result = LedgerVerificationResult(
        status="UNKNOWN",
        record_id="evidence-123",
    )

    actual = verify_evidence_against_ledger(
        FakeLedger(result=result),
        "evidence-123",
        "a" * 64,
    )

    assert actual.status is LedgerStatus.UNAVAILABLE
