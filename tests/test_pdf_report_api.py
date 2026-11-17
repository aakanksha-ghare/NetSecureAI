
from app import create_app


def create_test_client(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "EVIDENCE_DATABASE": str(tmp_path / "evidence.db"),
        }
    )
    return app.test_client()


def sample_configuration():
    return (
        "hostname CoreRouter01\n"
        "ip ssh version 1\n"
        "no ip http server\n"
        "logging host 192.0.2.10\n"
    )


def create_evidence_record(client, config=None):
    response = client.post(
        "/api/audit/cisco",
        json={"config": config or sample_configuration()},
    )

    assert response.status_code == 200

    data = response.get_json()
    assert data["evidence_record"]["record_id"]

    return data["evidence_record"]["record_id"]


def test_audit_report_endpoint_returns_pdf(tmp_path):
    client = create_test_client(tmp_path)

    response = client.post(
        "/api/audit/cisco/report",
        json={
            "config": sample_configuration(),
            "risk_inputs": {
                "NET-SSH-001": {
                    "likelihood": 4,
                    "impact": 5,
                    "rationale": (
                        "Insecure remote administration could expose "
                        "the network device."
                    ),
                }
            },
        },
    )

    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert response.data.startswith(b"%PDF-")
    assert "attachment" in response.headers["Content-Disposition"]
    assert "audit-report.pdf" in response.headers["Content-Disposition"]


def test_audit_report_endpoint_rejects_missing_configuration(tmp_path):
    client = create_test_client(tmp_path)

    response = client.post(
        "/api/audit/cisco/report",
        json={},
    )

    assert response.status_code == 400
    assert response.is_json


def test_existing_audit_endpoint_still_returns_json(tmp_path):
    client = create_test_client(tmp_path)

    response = client.post(
        "/api/audit/cisco",
        json={"config": "hostname CoreRouter01\n"},
    )

    assert response.status_code == 200
    assert response.is_json
    assert "findings" in response.get_json()


def test_original_configuration_verifies_successfully(tmp_path):
    client = create_test_client(tmp_path)
    config = sample_configuration()
    record_id = create_evidence_record(client, config)

    response = client.post(
        f"/api/evidence/{record_id}/verify",
        json={"configuration": config},
    )

    assert response.status_code == 200
    assert response.get_json()["verified"] is True


def test_modified_configuration_fails_verification(tmp_path):
    client = create_test_client(tmp_path)
    config = sample_configuration()
    record_id = create_evidence_record(client, config)

    modified_config = config.replace(
        "CoreRouter01",
        "CoreRouter02",
    )

    response = client.post(
        f"/api/evidence/{record_id}/verify",
        json={"configuration": modified_config},
    )

    assert response.status_code == 200
    assert response.get_json()["verified"] is False


def test_verification_rejects_missing_configuration(tmp_path):
    client = create_test_client(tmp_path)
    record_id = create_evidence_record(client)

    response = client.post(
        f"/api/evidence/{record_id}/verify",
        json={},
    )

    assert response.status_code == 400


def test_verification_returns_404_for_unknown_record(tmp_path):
    client = create_test_client(tmp_path)

    response = client.post(
        "/api/evidence/nonexistent-record/verify",
        json={"configuration": sample_configuration()},
    )

    assert response.status_code == 404


def test_evidence_retrieval_returns_saved_record(tmp_path):
    client = create_test_client(tmp_path)
    record_id = create_evidence_record(client)

    response = client.get(f"/api/evidence/{record_id}")

    assert response.status_code == 200
    assert response.get_json()["record_id"] == record_id


def test_evidence_retrieval_returns_404_for_unknown_record(tmp_path):
    client = create_test_client(tmp_path)

    response = client.get("/api/evidence/nonexistent-record")

    assert response.status_code == 404
