
import sqlite3

import pytest

from app.integrity.evidence_record import create_evidence_record
from app.integrity.evidence_store import (
    get_evidence_record,
    initialize_evidence_store,
    save_evidence_record,
)


def test_evidence_record_can_be_saved_and_retrieved(
    tmp_path,
) -> None:
    database_path = str(tmp_path / "evidence.db")
    initialize_evidence_store(database_path)

    record = create_evidence_record(
        vendor="Cisco",
        configuration_text="hostname CoreRouter01\n",
        finding_ids=["NET-SSH-001", "NET-HTTP-001"],
    )

    save_evidence_record(record, database_path)
    retrieved = get_evidence_record(record.record_id, database_path)

    assert retrieved is not None
    assert retrieved["record_id"] == record.record_id
    assert retrieved["vendor"] == "Cisco"
    assert retrieved["created_at"] == record.created_at
    assert retrieved["configuration_hash"] == {
        "algorithm": record.configuration_hash.algorithm,
        "digest": record.configuration_hash.digest,
        "evidence_size": record.configuration_hash.evidence_size,
    }
    assert retrieved["finding_ids"] == [
        "NET-SSH-001",
        "NET-HTTP-001",
    ]


def test_evidence_record_survives_database_reopening(
    tmp_path,
) -> None:
    database_path = str(tmp_path / "evidence.db")
    initialize_evidence_store(database_path)

    record = create_evidence_record(
        vendor="Juniper",
        configuration_text="set system host-name EdgeRouter\n",
        finding_ids=["NET-SSH-001"],
    )
    save_evidence_record(record, database_path)

    # Retrieval opens a new database connection.
    retrieved = get_evidence_record(record.record_id, database_path)

    assert retrieved is not None
    assert retrieved["record_id"] == record.record_id


def test_missing_evidence_record_returns_none(tmp_path) -> None:
    database_path = str(tmp_path / "evidence.db")
    initialize_evidence_store(database_path)

    assert get_evidence_record("missing-record", database_path) is None


def test_duplicate_record_id_is_rejected(tmp_path) -> None:
    database_path = str(tmp_path / "evidence.db")
    initialize_evidence_store(database_path)

    record = create_evidence_record(
        vendor="Cisco",
        configuration_text="hostname CoreRouter01\n",
        finding_ids=[],
    )

    save_evidence_record(record, database_path)

    with pytest.raises(sqlite3.IntegrityError):
        save_evidence_record(record, database_path)


def test_store_does_not_save_raw_configuration(tmp_path) -> None:
    database_path = str(tmp_path / "evidence.db")
    initialize_evidence_store(database_path)

    config = "hostname SecretInternalRouter\n"
    record = create_evidence_record(
        vendor="Cisco",
        configuration_text=config,
        finding_ids=[],
    )
    save_evidence_record(record, database_path)

    with sqlite3.connect(database_path) as connection:
        stored_values = connection.execute(
            """
            SELECT record_id, vendor, created_at,
                   configuration_hash, finding_ids
            FROM evidence_records
            """
        ).fetchone()

    assert stored_values is not None
    assert config not in repr(stored_values)


def test_store_rejects_invalid_record_type(tmp_path) -> None:
    database_path = str(tmp_path / "evidence.db")
    initialize_evidence_store(database_path)

    with pytest.raises(TypeError, match="EvidenceRecord"):
        save_evidence_record(None, database_path)  # type: ignore[arg-type]
