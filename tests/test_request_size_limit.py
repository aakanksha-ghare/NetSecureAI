
from app import create_app
from app.integrity.evidence_record import create_evidence_record
from app.integrity.evidence_store import save_evidence_record


def make_test_app(tmp_path, extra_config=None):
    config = {
        "TESTING": True,
        "EVIDENCE_DATABASE": str(tmp_path / "evidence.db"),
    }

    if extra_config:
        config.update(extra_config)

    return create_app(config)


def test_default_request_size_limit(tmp_path):
    app = make_test_app(tmp_path)

    assert app.config["MAX_CONTENT_LENGTH"] == 1_048_576


def test_request_size_limit_can_be_overridden(tmp_path):
    app = make_test_app(
        tmp_path,
        {"MAX_CONTENT_LENGTH": 256},
    )

    assert app.config["MAX_CONTENT_LENGTH"] == 256


def test_oversized_audit_request_returns_413(tmp_path):
    app = make_test_app(
        tmp_path,
        {"MAX_CONTENT_LENGTH": 256},
    )
    client = app.test_client()

    response = client.post(
        "/api/audit/cisco",
        json={
            "config": (
                "hostname CoreRouter01\n"
                + ("! oversized configuration\n" * 100)
            )
        },
    )

    assert response.status_code == 413


def test_oversized_verification_request_returns_413(tmp_path):
    database_path = str(tmp_path / "evidence.db")

    app = create_app(
        {
            "TESTING": True,
            "EVIDENCE_DATABASE": database_path,
            "MAX_CONTENT_LENGTH": 256,
        }
    )

    record = create_evidence_record(
        vendor="Cisco",
        configuration_text="hostname CoreRouter01\n",
        finding_ids=["NET-SSH-001"],
    )
    save_evidence_record(record, database_path)

    client = app.test_client()

    response = client.post(
        f"/api/evidence/{record.record_id}/verify",
        json={
            "configuration": (
                "hostname CoreRouter01\n"
                + ("! oversized configuration\n" * 100)
            )
        },
    )

    assert response.status_code == 413
