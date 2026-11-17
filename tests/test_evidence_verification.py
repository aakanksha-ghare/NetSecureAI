
from app import create_app
from app.integrity.evidence_record import create_evidence_record
from app.integrity.evidence_store import save_evidence_record


def setup_test_client(tmp_path):
    database_path = str(tmp_path / "evidence.db")

    app = create_app(
        {
            "TESTING": True,
            "EVIDENCE_DATABASE": database_path,
        }
    )

    record = create_evidence_record(
        vendor="Cisco",
        configuration_text="hostname CoreRouter01\n",
        finding_ids=["NET-SSH-001"],
    )
    save_evidence_record(record, database_path)

    return app.test_client(), record


def test_verification_passes_for_original_configuration(tmp_path):
    client, record = setup_test_client(tmp_path)

    response = client.post(
        f"/api/evidence/{record.record_id}/verify",
        json={"configuration": "hostname CoreRouter01\n"},
    )

    assert response.status_code == 200
    assert response.get_json()["verified"] is True


def test_verification_fails_for_modified_configuration(tmp_path):
    client, record = setup_test_client(tmp_path)

    response = client.post(
        f"/api/evidence/{record.record_id}/verify",
        json={"configuration": "hostname ModifiedRouter\n"},
    )

    assert response.status_code == 200
    assert response.get_json()["verified"] is False


def test_verification_returns_404_for_missing_record(tmp_path):
    client, _ = setup_test_client(tmp_path)

    response = client.post(
        "/api/evidence/nonexistent-record/verify",
        json={"configuration": "hostname CoreRouter01\n"},
    )

    assert response.status_code == 404


def test_verification_rejects_missing_configuration(tmp_path):
    client, record = setup_test_client(tmp_path)

    response = client.post(
        f"/api/evidence/{record.record_id}/verify",
        json={},
    )

    assert response.status_code == 400

def test_verification_rejects_non_string_configuration(tmp_path):
    client, record = setup_test_client(tmp_path)

    response = client.post(
        f"/api/evidence/{record.record_id}/verify",
        json={"configuration": 123},
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == (
        "'configuration' must be a string."
    )


def test_verification_rejects_non_object_json(tmp_path):
    client, record = setup_test_client(tmp_path)

    response = client.post(
        f"/api/evidence/{record.record_id}/verify",
        json=["hostname CoreRouter01"],
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == (
        "A JSON object containing 'configuration' is required."
    )
