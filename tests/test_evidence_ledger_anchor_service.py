
import pytest

from app.integrity.evidence_ledger import (
    LedgerAnchorResult,
    LedgerAnchorStatus,
)
from app.integrity.evidence_ledger_service import (
    anchor_evidence_in_ledger,
)


class FakeAnchorLedger:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.record_id = None
        self.digest = None

    def anchor(self, record_id, digest):
        self.record_id = record_id
        self.digest = digest

        if self.error:
            raise self.error

        return self.result


def test_anchor_service_accepts_successful_anchor():
    ledger = FakeAnchorLedger(
        result=LedgerAnchorResult(
            status=LedgerAnchorStatus.ANCHORED,
            record_id="evidence-123",
        )
    )

    result = anchor_evidence_in_ledger(
        ledger,
        "evidence-123",
        "a" * 64,
    )

    assert result.status is LedgerAnchorStatus.ANCHORED
    assert ledger.record_id == "evidence-123"
    assert ledger.digest == "a" * 64


def test_anchor_service_preserves_already_exists():
    ledger = FakeAnchorLedger(
        result=LedgerAnchorResult(
            status=LedgerAnchorStatus.ALREADY_EXISTS,
            record_id="evidence-123",
        )
    )

    result = anchor_evidence_in_ledger(
        ledger,
        "evidence-123",
        "a" * 64,
    )

    assert result.status is LedgerAnchorStatus.ALREADY_EXISTS


def test_anchor_service_preserves_conflict():
    ledger = FakeAnchorLedger(
        result=LedgerAnchorResult(
            status=LedgerAnchorStatus.CONFLICT,
            record_id="evidence-123",
        )
    )

    result = anchor_evidence_in_ledger(
        ledger,
        "evidence-123",
        "a" * 64,
    )

    assert result.status is LedgerAnchorStatus.CONFLICT


def test_anchor_service_handles_adapter_exception():
    ledger = FakeAnchorLedger(error=ConnectionError("private details"))

    result = anchor_evidence_in_ledger(
        ledger,
        "evidence-123",
        "a" * 64,
    )

    assert result.status is LedgerAnchorStatus.UNAVAILABLE
    assert "private details" not in result.detail


def test_anchor_service_rejects_invalid_digest():
    with pytest.raises(ValueError, match="SHA-256"):
        anchor_evidence_in_ledger(
            FakeAnchorLedger(),
            "evidence-123",
            "invalid",
        )


def test_anchor_service_rejects_mismatched_record_id():
    ledger = FakeAnchorLedger(
        result=LedgerAnchorResult(
            status=LedgerAnchorStatus.ANCHORED,
            record_id="another-record",
        )
    )

    result = anchor_evidence_in_ledger(
        ledger,
        "evidence-123",
        "a" * 64,
    )

    assert result.status is LedgerAnchorStatus.UNAVAILABLE
    assert result.record_id == "evidence-123"
