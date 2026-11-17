
from app.integrity.evidence_ledger import (
    LedgerAnchorResult,
    LedgerAnchorStatus,
    LedgerStatus,
    LedgerVerificationResult,
)
from app.integrity.evidence_ledger_worker import process_ledger_outbox
from app.integrity.evidence_record import create_evidence_record
from app.integrity.evidence_store import (
    get_ledger_outbox_item,
    initialize_evidence_store,
    save_evidence_record,
)


class FakeLedger:
    def __init__(self, anchor_statuses, verification_statuses=None, raise_for=None):
        self.anchor_statuses = anchor_statuses
        self.verification_statuses = verification_statuses or {}
        self.raise_for = set(raise_for or [])
        self.anchor_calls = []

    def anchor(self, record_id, digest):
        self.anchor_calls.append(record_id)

        if record_id in self.raise_for:
            raise RuntimeError("simulated ledger outage")

        return LedgerAnchorResult(
            status=self.anchor_statuses[record_id],
            record_id=record_id,
        )

    def verify(self, record_id, local_digest):
        status = self.verification_statuses.get(
            record_id,
            LedgerStatus.UNAVAILABLE,
        )
        return LedgerVerificationResult(
            status=status,
            record_id=record_id,
        )


def queue_record(database_path, configuration_text):
    record = create_evidence_record(
        vendor="cisco_ios",
        configuration_text=configuration_text,
        finding_ids=[],
    )
    save_evidence_record(
        record,
        str(database_path),
        queue_for_ledger=True,
    )
    return record


def test_anchored_result_marks_outbox_item_anchored(tmp_path):
    database_path = tmp_path / "evidence.db"
    initialize_evidence_store(str(database_path))
    record = queue_record(database_path, "hostname router-a")

    ledger = FakeLedger({
        record.record_id: LedgerAnchorStatus.ANCHORED,
    })

    summary = process_ledger_outbox(ledger, str(database_path))

    assert summary["selected"] == 1
    assert summary["anchored"] == 1
    assert summary["retry"] == 0
    assert get_ledger_outbox_item(record.record_id, str(database_path))["status"] == "ANCHORED"


def test_duplicate_is_anchored_only_when_digest_matches(tmp_path):
    database_path = tmp_path / "evidence.db"
    initialize_evidence_store(str(database_path))
    record = queue_record(database_path, "hostname router-b")

    ledger = FakeLedger(
        {record.record_id: LedgerAnchorStatus.ALREADY_EXISTS},
        {record.record_id: LedgerStatus.MATCH},
    )

    summary = process_ledger_outbox(ledger, str(database_path))

    assert summary["anchored"] == 1
    assert get_ledger_outbox_item(record.record_id, str(database_path))["status"] == "ANCHORED"


def test_duplicate_with_mismatched_digest_becomes_conflict(tmp_path):
    database_path = tmp_path / "evidence.db"
    initialize_evidence_store(str(database_path))
    record = queue_record(database_path, "hostname router-c")

    ledger = FakeLedger(
        {record.record_id: LedgerAnchorStatus.ALREADY_EXISTS},
        {record.record_id: LedgerStatus.MISMATCH},
    )

    summary = process_ledger_outbox(ledger, str(database_path))

    assert summary["conflict"] == 1
    assert get_ledger_outbox_item(record.record_id, str(database_path))["status"] == "CONFLICT"


def test_unavailable_ledger_is_left_retryable(tmp_path):
    database_path = tmp_path / "evidence.db"
    initialize_evidence_store(str(database_path))
    record = queue_record(database_path, "hostname router-d")

    ledger = FakeLedger({
        record.record_id: LedgerAnchorStatus.UNAVAILABLE,
    })

    summary = process_ledger_outbox(ledger, str(database_path))

    item = get_ledger_outbox_item(record.record_id, str(database_path))
    assert summary["retry"] == 1
    assert item["status"] == "RETRY"
    assert item["attempts"] == 1


def test_unexpected_adapter_exception_is_retryable(tmp_path):
    database_path = tmp_path / "evidence.db"
    initialize_evidence_store(str(database_path))
    record = queue_record(database_path, "hostname router-e")

    ledger = FakeLedger(
        {record.record_id: LedgerAnchorStatus.ANCHORED},
        raise_for={record.record_id},
    )

    summary = process_ledger_outbox(ledger, str(database_path))

    item = get_ledger_outbox_item(record.record_id, str(database_path))
    assert summary["retry"] == 1
    assert item["status"] == "RETRY"
    assert "simulated ledger outage" not in (item["last_error"] or "")


def test_worker_continues_after_one_record_fails(tmp_path):
    database_path = tmp_path / "evidence.db"
    initialize_evidence_store(str(database_path))
    first = queue_record(database_path, "hostname router-f")
    second = queue_record(database_path, "hostname router-g")

    ledger = FakeLedger(
        {
            first.record_id: LedgerAnchorStatus.ANCHORED,
            second.record_id: LedgerAnchorStatus.ANCHORED,
        },
        raise_for={first.record_id},
    )

    summary = process_ledger_outbox(ledger, str(database_path))

    assert summary["selected"] == 2
    assert summary["retry"] == 1
    assert summary["anchored"] == 1
    assert get_ledger_outbox_item(first.record_id, str(database_path))["status"] == "RETRY"
    assert get_ledger_outbox_item(second.record_id, str(database_path))["status"] == "ANCHORED"


def test_duplicate_that_cannot_be_verified_is_retryable(tmp_path):
    database_path = tmp_path / "evidence.db"
    initialize_evidence_store(str(database_path))
    record = queue_record(database_path, "hostname router-h")

    ledger = FakeLedger({
        record.record_id: LedgerAnchorStatus.ALREADY_EXISTS,
    })

    summary = process_ledger_outbox(ledger, str(database_path))

    assert summary["retry"] == 1
    assert get_ledger_outbox_item(record.record_id, str(database_path))["status"] == "RETRY"
