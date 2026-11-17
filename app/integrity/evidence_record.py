
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.integrity.evidence_integrity import (
    EvidenceHash,
    calculate_sha256,
)


@dataclass(frozen=True)
class EvidenceRecord:
    """Immutable metadata record for a configuration audit."""

    record_id: str
    vendor: str
    configuration_hash: EvidenceHash
    created_at: str
    finding_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""
        return {
            "record_id": self.record_id,
            "vendor": self.vendor,
            "configuration_hash": {
                "algorithm": self.configuration_hash.algorithm,
                "digest": self.configuration_hash.digest,
                "evidence_size": self.configuration_hash.evidence_size,
            },
            "created_at": self.created_at,
            "finding_ids": list(self.finding_ids),
        }


def create_evidence_record(
    vendor: str,
    configuration_text: str,
    finding_ids: tuple[str, ...] | list[str],
) -> EvidenceRecord:
    """Create an evidence record from an audited configuration.

    The configuration itself is not stored in this record.
    Its SHA-256 digest and audit metadata are stored instead.
    """
    if not isinstance(vendor, str) or not vendor.strip():
        raise ValueError("Vendor must be a non-empty string.")

    if not isinstance(configuration_text, str):
        raise TypeError("Configuration must be a string.")

    if not configuration_text.strip():
        raise ValueError("Configuration must not be empty.")

    if not isinstance(finding_ids, (tuple, list)):
        raise TypeError("Finding IDs must be a list or tuple.")

    if any(
        not isinstance(finding_id, str) or not finding_id.strip()
        for finding_id in finding_ids
    ):
        raise ValueError("Finding IDs must be non-empty strings.")

    return EvidenceRecord(
        record_id=str(uuid4()),
        vendor=vendor.strip(),
        configuration_hash=calculate_sha256(configuration_text),
        created_at=datetime.now(timezone.utc).isoformat(),
        finding_ids=tuple(finding_ids),
    )
