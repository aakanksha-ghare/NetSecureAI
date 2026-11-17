
from app import create_app
from app.integrity.evidence_ledger import (
    LedgerStatus,
    LedgerVerificationResult,
)
from app.integrity.evidence_record import create_evidence_record
from app.integrity.evidence_store import save_evidence_record


class FakeLedger:
    def __init__(self, status=LedgerStatus.MATCH):
        self.status = status
        self.record_id = None
        self.digest = None

    def verify(self, record_id, expected_digest):
        self.record_id = record_id
        self.digest = expected_digest
        return LedgerVerificationResult(
            status=self.status,
            record_id=record_id,
        )


def make_client(tmp_path, enabled=False, ledger=None):
    database_path = str(tmp_path / "evidence.db")
    app = create_app({
        "TESTING": True,
        "EVIDENCE_DATABASE": database_path,
        "EVIDENCE_LEDGER_ENABLED": enabled,
        "EVIDENCE_LEDGER_ADAPTER": ledger,
    })

    record = create_evidence_record(
        vendor="Cisco",
        configuration_text="hostname CoreRouter01\n",
        finding_ids=["NET-SSH-001"],
    )
    save_evidence_record(record, database_path)

    return app.test_client(), record


def test_ledger_verification_is_unavailable_when_disabled(tmp_path):
    client, record = make_client(tmp_path)

    response = client.post(
        f"/api/evidence/{record.record_id}/verify-ledger"
    )

    assert response.status_code == 503
    assert response.get_json()["status"] == "UNAVAILABLE"


def test_ledger_verification_is_unavailable_without_adapter(tmp_path):
    client, record = make_client(tmp_path, enabled=True)

    response = client.post(
        f"/api/evidence/{record.record_id}/verify-ledger"
    )

    assert response.status_code == 503
    assert response.get_json()["status"] == "UNAVAILABLE"


def test_ledger_verification_returns_match(tmp_path):
    ledger = FakeLedger(LedgerStatus.MATCH)
    client, record = make_client(
        tmp_path, enabled=True, ledger=ledger
    )

    response = client.post(
        f"/api/evidence/{record.record_id}/verify-ledger"
    )

    assert response.status_code == 200
    assert response.get_json()["status"] == "MATCH"
    assert ledger.record_id == record.record_id
    assert ledger.digest == record.configuration_hash.digest


def test_ledger_verification_returns_mismatch(tmp_path):
    client, record = make_client(
        tmp_path,
        enabled=True,
        ledger=FakeLedger(LedgerStatus.MISMATCH),
    )

    response = client.post(
        f"/api/evidence/{record.record_id}/verify-ledger"
    )

    assert response.status_code == 200
    assert response.get_json()["status"] == "MISMATCH"


def test_ledger_verification_returns_not_found(tmp_path):
    client, record = make_client(
        tmp_path,
        enabled=True,
        ledger=FakeLedger(LedgerStatus.NOT_FOUND),
    )

    response = client.post(
        f"/api/evidence/{record.record_id}/verify-ledger"
    )

    assert response.status_code == 404
    assert response.get_json()["status"] == "NOT_FOUND"


def test_ledger_verification_returns_unavailable_on_adapter_error(
    tmp_path,
):
    class BrokenLedger:
        def verify(self, record_id, expected_digest):
            raise ConnectionError("private connection details")

    client, record = make_client(
        tmp_path, enabled=True, ledger=BrokenLedger()
    )

    response = client.post(
        f"/api/evidence/{record.record_id}/verify-ledger"
    )

    assert response.status_code == 503
    assert response.get_json()["status"] == "UNAVAILABLE"
    assert "private connection details" not in response.get_data(as_text=True)


def test_ledger_verification_returns_404_for_missing_local_record(
    tmp_path,
):
    client, _ = make_client(
        tmp_path, enabled=True, ledger=FakeLedger()
    )

    response = client.post(
        "/api/evidence/missing-record/verify-ledger"
    )

    assert response.status_code == 404
    assert response.get_json()["status"] == "NOT_FOUND"
