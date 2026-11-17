
from app import create_app
from app.integrity.evidence_record import create_evidence_record
from app.integrity.evidence_store import save_evidence_record


def test_retrieve_existing_evidence_record(tmp_path) -> None:
    database_path = str(tmp_path / "evidence.db")

    app = create_app(
        {
            "TESTING": True,
            "EVIDENCE_DATABASE": database_path,
        }
    )
    client = app.test_client()

    record = create_evidence_record(
        vendor="Cisco",
        configuration_text="hostname CoreRouter01\n",
        finding_ids=["NET-SSH-001"],
    )
    save_evidence_record(record, database_path)

    response = client.get(
        f"/api/evidence/{record.record_id}"
    )

    assert response.status_code == 200

    data = response.get_json()
    assert data is not None
    assert data["record_id"] == record.record_id
    assert data["vendor"] == "Cisco"
    assert data["finding_ids"] == ["NET-SSH-001"]
    assert data["configuration_hash"]["algorithm"] == "SHA-256"
    assert "hostname CoreRouter01" not in response.get_data(as_text=True)


def test_retrieve_missing_evidence_record_returns_404(tmp_path) -> None:
    database_path = str(tmp_path / "evidence.db")

    app = create_app(
        {
            "TESTING": True,
            "EVIDENCE_DATABASE": database_path,
        }
    )
    client = app.test_client()

    response = client.get("/api/evidence/nonexistent-record")

    assert response.status_code == 404

    data = response.get_json()
    assert data is not None
    assert data["error"] == "Evidence record not found."
    assert data["record_id"] == "nonexistent-record"
