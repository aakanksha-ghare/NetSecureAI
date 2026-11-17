import pytest

from app import create_app


@pytest.fixture
def app(tmp_path):
    return create_app({
        "TESTING": True,
        "EVIDENCE_DATABASE": str(tmp_path / "test_evidence.db"),
    })


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def finding():
    return {
        "rule_id": "NET-001",
        "title": "SSH password authentication enabled",
        "status": "FAIL",
        "severity": "HIGH",
        "description": "SSH password authentication is enabled.",
        "evidence": "PasswordAuthentication yes",
        "remediation": "Disable password authentication where appropriate.",
    }


def test_explanation_success(client, finding, monkeypatch):
    import app.routes.llm_routes as route

    monkeypatch.setattr(
        route,
        "explain_finding",
        lambda item: "This setting can increase unauthorized-access risk.",
    )

    response = client.post("/api/findings/explain", json=finding)

    assert response.status_code == 200
    assert "unauthorized-access risk" in response.json["explanation"]


def test_explanation_rejects_missing_fields(client):
    response = client.post(
        "/api/findings/explain",
        json={"title": "Incomplete finding"},
    )

    assert response.status_code == 400
    assert "missing_fields" in response.json


def test_explanation_rejects_non_json(client):
    response = client.post(
        "/api/findings/explain",
        data="not json",
        content_type="text/plain",
    )

    assert response.status_code == 415


def test_explanation_handles_missing_configuration(
    client, finding, monkeypatch
):
    import app.routes.llm_routes as route

    def missing_configuration(_finding):
        raise RuntimeError("LLM explanations are not configured.")

    monkeypatch.setattr(route, "explain_finding", missing_configuration)

    response = client.post("/api/findings/explain", json=finding)

    assert response.status_code == 503
    assert response.json["error"] == "LLM explanations are not configured."


def test_explanation_hides_provider_errors(client, finding, monkeypatch):
    import app.routes.llm_routes as route

    def provider_failure(_finding):
        raise RuntimeError("provider details must not leak")

    monkeypatch.setattr(route, "explain_finding", provider_failure)

    response = client.post("/api/findings/explain", json=finding)

    assert response.status_code == 502
    assert "provider details" not in response.get_data(as_text=True)


def test_explanation_rejects_oversized_finding(client, finding):
    finding["description"] = "x" * 17_000

    response = client.post("/api/findings/explain", json=finding)

    assert response.status_code == 413
