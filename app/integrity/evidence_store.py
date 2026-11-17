
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.integrity.evidence_record import EvidenceRecord


OUTBOX_STATUSES = {"PENDING", "RETRY", "ANCHORED", "CONFLICT"}


def _validate_database_path(database_path: str) -> None:
    if not isinstance(database_path, str) or not database_path.strip():
        raise ValueError("Database path must be a non-empty string.")


def initialize_evidence_store(database_path: str) -> None:
    """Initialize evidence storage and the ledger outbox."""
    _validate_database_path(database_path)

    if database_path != ":memory:":
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_records (
                record_id TEXT PRIMARY KEY,
                vendor TEXT NOT NULL,
                created_at TEXT NOT NULL,
                configuration_hash TEXT NOT NULL,
                finding_ids TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_ledger_outbox (
                record_id TEXT PRIMARY KEY,
                digest TEXT NOT NULL,
                status TEXT NOT NULL
                    CHECK (status IN (
                        'PENDING', 'RETRY', 'ANCHORED', 'CONFLICT'
                    )),
                attempts INTEGER NOT NULL DEFAULT 0
                    CHECK (attempts >= 0),
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )


def save_evidence_record(
    record: EvidenceRecord,
    database_path: str,
    *,
    queue_for_ledger: bool = False,
) -> None:
    """Save evidence and optionally queue its digest atomically."""
    if not isinstance(record, EvidenceRecord):
        raise TypeError("record must be an EvidenceRecord instance.")

    _validate_database_path(database_path)

    configuration_hash = json.dumps(
        {
            "algorithm": record.configuration_hash.algorithm,
            "digest": record.configuration_hash.digest,
            "evidence_size": record.configuration_hash.evidence_size,
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    finding_ids = json.dumps(
        list(record.finding_ids),
        separators=(",", ":"),
    )

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO evidence_records (
                record_id,
                vendor,
                created_at,
                configuration_hash,
                finding_ids
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                record.record_id,
                record.vendor,
                record.created_at,
                configuration_hash,
                finding_ids,
            ),
        )

        if queue_for_ledger:
            now = datetime.now(timezone.utc).isoformat()
            connection.execute(
                """
                INSERT INTO evidence_ledger_outbox (
                    record_id,
                    digest,
                    status,
                    attempts,
                    last_error,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, 'PENDING', 0, NULL, ?, ?)
                """,
                (
                    record.record_id,
                    record.configuration_hash.digest,
                    now,
                    now,
                ),
            )


def get_evidence_record(
    record_id: str,
    database_path: str,
) -> dict[str, Any] | None:
    """Retrieve persisted evidence metadata by record ID."""
    _validate_database_path(database_path)

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT
                record_id,
                vendor,
                created_at,
                configuration_hash,
                finding_ids
            FROM evidence_records
            WHERE record_id = ?
            """,
            (record_id,),
        ).fetchone()

    if row is None:
        return None

    return {
        "record_id": row["record_id"],
        "vendor": row["vendor"],
        "created_at": row["created_at"],
        "configuration_hash": json.loads(row["configuration_hash"]),
        "finding_ids": json.loads(row["finding_ids"]),
    }


def get_ledger_outbox_item(
    record_id: str,
    database_path: str,
) -> dict[str, Any] | None:
    """Retrieve one ledger outbox item."""
    _validate_database_path(database_path)

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT record_id, digest, status, attempts,
                   last_error, created_at, updated_at
            FROM evidence_ledger_outbox
            WHERE record_id = ?
            """,
            (record_id,),
        ).fetchone()

    return dict(row) if row is not None else None


def list_pending_ledger_outbox(
    database_path: str,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List pending or retryable ledger items, oldest first."""
    _validate_database_path(database_path)

    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer.")

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT record_id, digest, status, attempts,
                   last_error, created_at, updated_at
            FROM evidence_ledger_outbox
            WHERE status IN ('PENDING', 'RETRY')
            ORDER BY created_at ASC, record_id ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def record_ledger_outbox_result(
    record_id: str,
    database_path: str,
    status: str,
    error: str | None = None,
) -> bool:
    """Record an attempt outcome; return False if the item is missing."""
    _validate_database_path(database_path)

    if status not in OUTBOX_STATUSES:
        raise ValueError("Unsupported ledger outbox status.")

    if error is not None and not isinstance(error, str):
        raise TypeError("error must be a string or None.")

    # Store only bounded error text. Callers must avoid passing secrets.
    safe_error = error[:500] if error else None
    now = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(database_path) as connection:
        cursor = connection.execute(
            """
            UPDATE evidence_ledger_outbox
            SET status = ?,
                attempts = attempts + 1,
                last_error = ?,
                updated_at = ?
            WHERE record_id = ?
            """,
            (status, safe_error, now, record_id),
        )

    return cursor.rowcount == 1
