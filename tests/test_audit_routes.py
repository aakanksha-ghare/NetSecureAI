
from app import create_app
import hashlib

def test_audit_endpoint_returns_findings() -> None:
    client = create_app().test_client()

    response = client.post(
        "/api/audit/cisco",
        json={
            "config": (
                "hostname CoreRouter01\n"
                "ip ssh version 2\n"
                "no ip http server\n"
                "logging host 192.0.2.50\n"
            )
        },
    )

    assert response.status_code == 200

    data = response.get_json()
    assert data["vendor"] == "Cisco"
    assert data["device_type"] == "network_device"
    assert len(data["findings"]) == 4

    findings_by_id = {
        finding["rule_id"]: finding
        for finding in data["findings"]
    }

    assert findings_by_id["NET-SSH-001"]["status"] == "PASS"
    assert findings_by_id["NET-HTTP-001"]["status"] == "PASS"
    assert findings_by_id["NET-LOG-001"]["status"] == "PASS"

    ssh = findings_by_id["NET-SSH-001"]

    assert ssh["rule_source"] == "Internal Baseline"
    assert "framework" not in ssh
    assert ssh["risk_assessment"] is None

    ssh_mappings = ssh["framework_mappings"]
    assert len(ssh_mappings) > 0

    assert all(
        {
            "framework",
            "control_id",
            "control_title",
            "rationale",
        } <= mapping.keys()
        for mapping in ssh_mappings
    )


def test_failed_finding_can_receive_risk_assessment() -> None:
    client = create_app().test_client()

    response = client.post(
        "/api/audit/cisco",
        json={
            "config": (
                "hostname CoreRouter01\n"
                "ip ssh version 1\n"
                "no ip http server\n"
                "logging host 192.0.2.50\n"
            ),
            "risk_inputs": {
                "NET-SSH-001": {
                    "likelihood": 4,
                    "impact": 5,
                    "rationale": (
                        "Illustrative test assessment for insecure "
                        "remote access."
                    ),
                }
            },
        },
    )

    assert response.status_code == 200

    data = response.get_json()
    findings_by_id = {
        finding["rule_id"]: finding
        for finding in data["findings"]
    }

    ssh = findings_by_id["NET-SSH-001"]

    assert ssh["status"] == "FAIL"
    assert ssh["risk_assessment"]["likelihood"] == 4
    assert ssh["risk_assessment"]["impact"] == 5
    assert ssh["risk_assessment"]["score"] == 20
    assert ssh["risk_assessment"]["level"] == "CRITICAL"


def test_unknown_finding_has_unassessed_risk() -> None:
    client = create_app().test_client()

    response = client.post(
        "/api/audit/cisco",
        json={"config": "hostname CoreRouter01\n"},
    )

    assert response.status_code == 200

    data = response.get_json()
    findings_by_id = {
        finding["rule_id"]: finding
        for finding in data["findings"]
    }

    ssh = findings_by_id["NET-SSH-001"]

    assert ssh["status"] == "UNKNOWN"
    assert ssh["risk_assessment"]["level"] == "NOT_ASSESSED"
    assert ssh["risk_assessment"]["score"] is None


def test_audit_endpoint_rejects_invalid_likelihood() -> None:
    client = create_app().test_client()

    response = client.post(
        "/api/audit/cisco",
        json={
            "config": (
                "hostname CoreRouter01\n"
                "ip ssh version 1\n"
            ),
            "risk_inputs": {
                "NET-SSH-001": {
                    "likelihood": 6,
                    "impact": 3,
                    "rationale": "Test invalid input.",
                }
            },
        },
    )

    assert response.status_code == 400
    assert "likelihood" in response.get_json()["error"]


def test_audit_endpoint_rejects_invalid_impact() -> None:
    client = create_app().test_client()

    response = client.post(
        "/api/audit/cisco",
        json={
            "config": (
                "hostname CoreRouter01\n"
                "ip ssh version 1\n"
            ),
            "risk_inputs": {
                "NET-SSH-001": {
                    "likelihood": 3,
                    "impact": 0,
                    "rationale": "Test invalid input.",
                }
            },
        },
    )

    assert response.status_code == 400
    assert "impact" in response.get_json()["error"]


def test_audit_endpoint_rejects_non_object_risk_inputs() -> None:
    client = create_app().test_client()

    response = client.post(
        "/api/audit/cisco",
        json={
            "config": "hostname CoreRouter01\n",
            "risk_inputs": ["invalid"],
        },
    )

    assert response.status_code == 400
    assert "risk_inputs" in response.get_json()["error"]


def test_audit_endpoint_rejects_empty_risk_rationale() -> None:
    client = create_app().test_client()

    response = client.post(
        "/api/audit/cisco",
        json={
            "config": (
                "hostname CoreRouter01\n"
                "ip ssh version 1\n"
            ),
            "risk_inputs": {
                "NET-SSH-001": {
                    "likelihood": 3,
                    "impact": 4,
                    "rationale": "   ",
                }
            },
        },
    )

    assert response.status_code == 400
    assert "rationale" in response.get_json()["error"]


def test_audit_endpoint_rejects_empty_config() -> None:
    client = create_app().test_client()

    response = client.post(
        "/api/audit/cisco",
        json={"config": "   "},
    )

    assert response.status_code == 400
    assert "error" in response.get_json()


def test_audit_endpoint_rejects_invalid_body() -> None:
    client = create_app().test_client()

    response = client.post(
        "/api/audit/cisco",
        json=["not", "an", "object"],
    )

    assert response.status_code == 400

def test_audit_endpoint_returns_evidence_hash_metadata() -> None:
    client = create_app().test_client()

    response = client.post(
        "/api/audit/cisco",
        json={
            "config": (
                "hostname CoreRouter01\n"
                "ip ssh version 2\n"
                "no ip http server\n"
                "logging host 192.0.2.50\n"
            )
        },
    )

    assert response.status_code == 200

    data = response.get_json()
    findings_by_id = {
        finding["rule_id"]: finding
        for finding in data["findings"]
    }

    # These rules have supporting configuration evidence.
    for rule_id in (
        "NET-SSH-001",
        "NET-HTTP-001",
        "NET-LOG-001",
    ):
        evidence_hash = findings_by_id[rule_id]["evidence_hash"]

        assert evidence_hash is not None
        assert evidence_hash["algorithm"] == "SHA-256"
        assert len(evidence_hash["digest"]) == 64
        assert all(
            character in "0123456789abcdef"
            for character in evidence_hash["digest"]
        )
        assert evidence_hash["evidence_size"] > 0

    # The Telnet rule has no supporting evidence in this config.
    assert findings_by_id["NET-TELNET-001"]["evidence_hash"] is None
def test_audit_endpoint_returns_null_hash_without_supporting_evidence() -> None:
    client = create_app().test_client()

    response = client.post(
        "/api/audit/cisco",
        json={"config": "hostname CoreRouter01\n"},
    )

    assert response.status_code == 200

    data = response.get_json()
    findings_by_id = {
        finding["rule_id"]: finding
        for finding in data["findings"]
    }

    ssh = findings_by_id["NET-SSH-001"]

    assert ssh["status"] == "UNKNOWN"
    assert ssh["evidence_hash"] is None

def test_audit_endpoint_returns_configuration_hash() -> None:
    client = create_app().test_client()
    config = (
        "hostname CoreRouter01\n"
        "ip ssh version 2\n"
        "no ip http server\n"
        "logging host 192.0.2.50\n"
    )

    response = client.post(
        "/api/audit/cisco",
        json={"config": config},
    )

    assert response.status_code == 200

    configuration_hash = response.get_json()["configuration_hash"]

    assert configuration_hash["algorithm"] == "SHA-256"
    assert configuration_hash["digest"] == hashlib.sha256(
        config.encode("utf-8")
    ).hexdigest()
    assert configuration_hash["evidence_size"] == len(
        config.encode("utf-8")
    )


def test_audit_endpoint_hash_changes_when_configuration_changes() -> None:
    client = create_app().test_client()

    original_config = (
        "hostname CoreRouter01\n"
        "ip ssh version 2\n"
    )
    modified_config = (
        "hostname CoreRouter01\n"
        "ip ssh version 1\n"
    )

    original_response = client.post(
        "/api/audit/cisco",
        json={"config": original_config},
    )
    modified_response = client.post(
        "/api/audit/cisco",
        json={"config": modified_config},
    )

    assert original_response.status_code == 200
    assert modified_response.status_code == 200

    original_hash = original_response.get_json()["configuration_hash"]
    modified_hash = modified_response.get_json()["configuration_hash"]

    assert original_hash["digest"] != modified_hash["digest"]

from datetime import datetime


def test_audit_endpoint_returns_evidence_record() -> None:
    client = create_app().test_client()
    config = (
        "hostname CoreRouter01\n"
        "ip ssh version 2\n"
        "no ip http server\n"
        "logging host 192.0.2.50\n"
    )

    response = client.post(
        "/api/audit/cisco",
        json={"config": config},
    )

    assert response.status_code == 200

    data = response.get_json()
    record = data["evidence_record"]

    assert record["record_id"]
    assert record["vendor"] == "Cisco"
    assert record["configuration_hash"] == data["configuration_hash"]
    assert record["finding_ids"] == [
        finding["rule_id"] for finding in data["findings"]
    ]

    timestamp = datetime.fromisoformat(record["created_at"])
    assert timestamp.tzinfo is not None
    assert timestamp.utcoffset().total_seconds() == 0


def test_each_audit_request_gets_a_unique_evidence_record_id() -> None:
    client = create_app().test_client()
    payload = {
        "config": (
            "hostname CoreRouter01\n"
            "ip ssh version 2\n"
        )
    }

    first_response = client.post("/api/audit/cisco", json=payload)
    second_response = client.post("/api/audit/cisco", json=payload)

    assert first_response.status_code == 200
    assert second_response.status_code == 200

    first_record = first_response.get_json()["evidence_record"]
    second_record = second_response.get_json()["evidence_record"]

    assert first_record["record_id"] != second_record["record_id"]
    assert (
        first_record["configuration_hash"]["digest"]
        == second_record["configuration_hash"]["digest"]
    )
