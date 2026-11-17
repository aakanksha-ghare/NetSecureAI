
from app.models.security_baseline import SettingStatus
from app.rules.compliance_engine import ComplianceStatus
from app.services.audit_service import audit_cisco_config


def test_audit_service_connects_parser_and_engine() -> None:
    config = (
        "hostname CoreRouter01\n"
        "ip ssh version 2\n"
        "no ip http server\n"
        "logging host 192.0.2.50\n"
    )

    baseline, findings = audit_cisco_config(config)

    assert baseline.vendor == "Cisco"
    assert len(findings) == 4

    findings_by_id = {
        finding.rule_id: finding
        for finding in findings
    }

    ssh = findings_by_id["NET-SSH-001"]
    assert ssh.status == ComplianceStatus.PASS
    assert ssh.source_lines == (2,)

    http = findings_by_id["NET-HTTP-001"]
    assert http.status == ComplianceStatus.PASS

    logging = findings_by_id["NET-LOG-001"]
    assert logging.status == ComplianceStatus.PASS


def test_audit_service_preserves_unknown_status() -> None:
    config = "hostname TestRouter\n"

    baseline, findings = audit_cisco_config(config)

    ssh_setting = baseline.get_setting("ssh_protocol_version")
    assert ssh_setting is not None
    assert ssh_setting.status == SettingStatus.UNKNOWN
    assert ssh_setting.value is None

    findings_by_id = {
        finding.rule_id: finding
        for finding in findings
    }

    assert (
        findings_by_id["NET-SSH-001"].status
        == ComplianceStatus.UNKNOWN
    )


def test_parsed_settings_preserve_configuration_evidence() -> None:
    config = (
        "hostname CoreRouter01\n"
        "ip ssh version 2\n"
        "no ip http server\n"
        "logging host 192.0.2.50\n"
    )

    baseline, _ = audit_cisco_config(config)

    ssh = baseline.get_setting("ssh_protocol_version")
    http = baseline.get_setting("http_server_enabled")
    logging = baseline.get_setting("logging_enabled")

    assert ssh is not None
    assert ssh.value == 2
    assert ssh.evidence == ("ip ssh version 2",)
    assert ssh.source_lines == (2,)

    assert http is not None
    assert http.evidence == ("no ip http server",)
    assert http.source_lines == (3,)

    assert logging is not None
    assert logging.evidence == ("logging host 192.0.2.50",)
    assert logging.source_lines == (4,)

import pytest

from app.services.audit_service import PARSER_REGISTRY, audit_config


@pytest.mark.parametrize("vendor", list(PARSER_REGISTRY))
def test_audit_config_supports_registered_vendors(vendor: str) -> None:
    config = {
        "cisco": "hostname Router\nip ssh version 2",
        "juniper": "set system services ssh",
        "arista": "hostname Switch",
        "fortinet": "config system global\nend",
        "palo_alto": "<config></config>",
        "checkpoint": "set hostname Gateway",
        "huawei": "sysname Router",
        "aruba": "hostname Switch",
        "mikrotik": "/ip service",
    }[vendor]

    baseline, findings = audit_config(vendor, config)

    assert baseline.vendor
    assert isinstance(findings, list)
    assert len(findings) == 4


def test_audit_config_rejects_unsupported_vendor() -> None:
    with pytest.raises(ValueError, match="Unsupported vendor"):
        audit_config("unsupported_vendor", "some configuration")


def test_audit_config_rejects_empty_configuration() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        audit_config("cisco", "")

