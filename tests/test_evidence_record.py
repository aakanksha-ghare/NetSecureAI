
import hashlib
import json
from datetime import datetime

import pytest

from app.integrity.evidence_record import create_evidence_record


def test_evidence_record_contains_configuration_hash() -> None:
    config = "hostname CoreRouter01\nip ssh version 2\n"

    record = create_evidence_record(
        vendor="Cisco",
        configuration_text=config,
        finding_ids=["NET-SSH-001", "NET-HTTP-001"],
    )

    assert record.vendor == "Cisco"
    assert record.configuration_hash.algorithm == "SHA-256"
    assert record.configuration_hash.digest == hashlib.sha256(
        config.encode("utf-8")
    ).hexdigest()
    assert record.configuration_hash.evidence_size == len(
        config.encode("utf-8")
    )
    assert record.finding_ids == (
        "NET-SSH-001",
        "NET-HTTP-001",
    )


def test_evidence_record_has_unique_ids() -> None:
    arguments = {
        "vendor": "Cisco",
        "configuration_text": "hostname CoreRouter01\n",
        "finding_ids": [],
    }

    first = create_evidence_record(**arguments)
    second = create_evidence_record(**arguments)

    assert first.record_id != second.record_id


def test_evidence_record_timestamp_is_valid_utc_datetime() -> None:
    record = create_evidence_record(
        vendor="Cisco",
        configuration_text="hostname CoreRouter01\n",
        finding_ids=[],
    )

    timestamp = datetime.fromisoformat(record.created_at)

    assert timestamp.tzinfo is not None
    assert timestamp.utcoffset().total_seconds() == 0


def test_evidence_record_serializes_to_json() -> None:
    record = create_evidence_record(
        vendor="Cisco",
        configuration_text="hostname CoreRouter01\n",
        finding_ids=["NET-SSH-001"],
    )

    serialized = record.to_dict()
    json_text = json.dumps(serialized)
    decoded = json.loads(json_text)

    assert decoded["record_id"] == record.record_id
    assert decoded["vendor"] == "Cisco"
    assert decoded["configuration_hash"]["algorithm"] == "SHA-256"
    assert decoded["finding_ids"] == ["NET-SSH-001"]


@pytest.mark.parametrize("vendor", ["", "   "])
def test_evidence_record_rejects_empty_vendor(vendor: str) -> None:
    with pytest.raises(ValueError, match="Vendor"):
        create_evidence_record(
            vendor=vendor,
            configuration_text="hostname CoreRouter01\n",
            finding_ids=[],
        )


def test_evidence_record_rejects_empty_configuration() -> None:
    with pytest.raises(ValueError, match="Configuration"):
        create_evidence_record(
            vendor="Cisco",
            configuration_text="  \n",
            finding_ids=[],
        )


def test_evidence_record_rejects_invalid_finding_ids() -> None:
    with pytest.raises(ValueError, match="Finding IDs"):
        create_evidence_record(
            vendor="Cisco",
            configuration_text="hostname CoreRouter01\n",
            finding_ids=["NET-SSH-001", "  "],
        )


def test_evidence_record_rejects_invalid_finding_ids_container() -> None:
    with pytest.raises(TypeError, match="list or tuple"):
        create_evidence_record(
            vendor="Cisco",
            configuration_text="hostname CoreRouter01\n",
            finding_ids="NET-SSH-001",  # type: ignore[arg-type]
        )


def test_evidence_record_rejects_non_string_configuration() -> None:
    with pytest.raises(TypeError, match="Configuration"):
        create_evidence_record(
            vendor="Cisco",
            configuration_text=123,  # type: ignore[arg-type]
            finding_ids=[],
        )

