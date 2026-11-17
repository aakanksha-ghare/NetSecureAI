
from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class LedgerStatus(str, Enum):
    """Possible outcomes of independent ledger verification."""

    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    NOT_FOUND = "NOT_FOUND"
    UNAVAILABLE = "UNAVAILABLE"


class LedgerAnchorStatus(str, Enum):
    """Possible outcomes when anchoring evidence."""

    ANCHORED = "ANCHORED"
    ALREADY_EXISTS = "ALREADY_EXISTS"
    CONFLICT = "CONFLICT"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class LedgerVerificationResult:
    """Result of comparing local and independently stored digests."""

    status: LedgerStatus
    record_id: str
    detail: str = ""


@dataclass(frozen=True)
class LedgerAnchorResult:
    """Result of attempting to anchor an evidence digest."""

    status: LedgerAnchorStatus
    record_id: str
    detail: str = ""


class EvidenceLedger(Protocol):
    """Interface implemented by independent evidence-ledger providers."""

    def anchor(
        self,
        record_id: str,
        digest: str,
    ) -> LedgerAnchorResult:
        """Independently store a record ID and its SHA-256 digest.

        Repeated writes with the same digest should be idempotent.
        An existing record with a different digest must be a conflict.
        """
        ...

    def verify(
        self,
        record_id: str,
        local_digest: str,
    ) -> LedgerVerificationResult:
        """Compare local_digest with the independently stored digest.

        MATCH: digests match.
        MISMATCH: record exists but digests differ.
        NOT_FOUND: no independent ledger record exists.
        UNAVAILABLE: verification could not be completed.
        """
        ...
