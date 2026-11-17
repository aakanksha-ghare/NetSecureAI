
import sqlite3

import pytest

from app.integrity.evidence_record import create_evidence_record
from app.integrity.evidence_store import (
    get_ledger_outbox_item,
    initialize_evidence_store,
    list_pending_ledger_outbox,
    record_ledger_outbox_result,
    save_evidence_record,
)


def setup_record(tmp_path):
    database_path = str(tmp_path / "evidence.db")
    initialize_evidence_store(database_path)

    record = create_evidence_record(
        vendor="Cisco",
        configuration_text="hostname TestRouter\n",
        finding_ids=["NET-SSH-001"],
    )
    return database_path, record


def test_saving_with_queue_creates_pending_item(tmp_path):
    database_path, record = setup_record(tmp_path)

    save_evidence_record(
        record, database_path, queue_for_ledger=True
    )

    item = get_ledger_outbox_item(record.record_id, database_path)

    assert item is not None
    assert item["digest"] == record.configuration_hash.digest
    assert item["status"] == "PENDING"
    assert item["attempts"] == 0
    assert item["last_error"] is None


def test_existing_save_behavior_does_not_queue_by_default(tmp_path):
    database_path, record = setup_record(tmp_path)

    save_evidence_record(record, database_path)

    assert get_ledger_outbox_item(
        record.record_id, database_path
    ) is None


def test_evidence_and_outbox_insert_roll_back_together(tmp_path):
    database_path, record = setup_record(tmp_path)

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_outbox_insert
            BEFORE INSERT ON evidence_ledger_outbox
            BEGIN
                SELECT RAISE(ABORT, 'test failure');
            END
            """
        )

    with pytest.raises(sqlite3.IntegrityError):
        save_evidence_record(
            record, database_path, queue_for_ledger=True
        )

    from app.integrity.evidence_store import get_evidence_record

    assert get_evidence_record(
        record.record_id, database_path
    ) is None


def test_retry_result_increments_attempt_count(tmp_path):
    database_path, record = setup_record(tmp_path)
    save_evidence_record(
        record, database_path, queue_for_ledger=True
    )

    assert record_ledger_outbox_result(
        record.record_id,
        database_path,
        "RETRY",
        "Temporary connection failure",
    )

    item = get_ledger_outbox_item(record.record_id, database_path)

    assert item["status"] == "RETRY"
    assert item["attempts"] == 1
    assert item["last_error"] == "Temporary connection failure"
    assert len(list_pending_ledger_outbox(database_path)) == 1


def test_anchored_item_is_removed_from_pending_list(tmp_path):
    database_path, record = setup_record(tmp_path)
    save_evidence_record(
        record, database_path, queue_for_ledger=True
    )

    assert record_ledger_outbox_result(
        record.record_id, database_path, "ANCHORED"
    )
    assert list_pending_ledger_outbox(database_path) == []


def test_unknown_outbox_item_returns_false(tmp_path):
    database_path, _ = setup_record(tmp_path)

    assert not record_ledger_outbox_result(
        "missing-record", database_path, "RETRY"
    )


def test_invalid_status_is_rejected(tmp_path):
    database_path, record = setup_record(tmp_path)
    save_evidence_record(
        record, database_path, queue_for_ledger=True
    )

    with pytest.raises(ValueError, match="status"):
        record_ledger_outbox_result(
            record.record_id, database_path, "SUCCESS"
        )


def test_invalid_limit_is_rejected(tmp_path):
    database_path, _ = setup_record(tmp_path)

    with pytest.raises(ValueError, match="limit"):
        list_pending_ledger_outbox(database_path, limit=0)
