
"""Process queued evidence digests without blocking audit requests."""

from typing import Any

from app.integrity.evidence_ledger import (
    EvidenceLedger,
    LedgerAnchorStatus,
    LedgerStatus,
)
from app.integrity.evidence_ledger_service import (
    anchor_evidence_in_ledger,
    verify_evidence_against_ledger,
)
from app.integrity.evidence_store import (
    list_pending_ledger_outbox,
    record_ledger_outbox_result,
)


def process_ledger_outbox(
    ledger: EvidenceLedger,
    database_path: str,
    limit: int = 100,
) -> dict[str, int]:
    """Attempt to anchor queued digests and record each outcome.

    A duplicate is marked as anchored only if ledger verification confirms
    that its stored digest matches the local digest.
    """
    items = list_pending_ledger_outbox(database_path, limit=limit)

    summary = {
        "selected": len(items),
        "anchored": 0,
        "retry": 0,
        "conflict": 0,
        "not_updated": 0,
    }

    for item in items:
        record_id = item["record_id"]
        digest = item["digest"]

        status = "RETRY"
        error = "Ledger anchoring could not be confirmed."

        try:
            result = anchor_evidence_in_ledger(ledger, record_id, digest)

            if result.status == LedgerAnchorStatus.ANCHORED:
                status = "ANCHORED"
                error = None

            elif result.status == LedgerAnchorStatus.CONFLICT:
                status = "CONFLICT"
                error = "The ledger reports a digest conflict."

            elif result.status == LedgerAnchorStatus.UNAVAILABLE:
                status = "RETRY"
                error = "The ledger is unavailable or returned an invalid result."

            elif result.status == LedgerAnchorStatus.ALREADY_EXISTS:
                verification = verify_evidence_against_ledger(
                    ledger,
                    record_id,
                    digest,
                )

                if verification.status == LedgerStatus.MATCH:
                    status = "ANCHORED"
                    error = None
                elif verification.status == LedgerStatus.MISMATCH:
                    status = "CONFLICT"
                    error = "The existing ledger digest does not match."
                else:
                    status = "RETRY"
                    error = "The existing ledger entry could not be verified."

        except Exception:
            # Keep adapter details out of persisted error messages.
            status = "RETRY"
            error = "An unexpected error occurred during ledger processing."

        try:
            updated = record_ledger_outbox_result(
                record_id,
                database_path,
                status,
                error,
            )
        except Exception:
            # Continue processing other queued records if persistence fails.
            summary["not_updated"] += 1
            continue

        if not updated:
            summary["not_updated"] += 1
            continue

        if status == "ANCHORED":
            summary["anchored"] += 1
        elif status == "CONFLICT":
            summary["conflict"] += 1
        else:
            summary["retry"] += 1

    return summary
