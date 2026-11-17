
from app.models.security_baseline import (
    SecurityBaseline,
    SecuritySetting,
    SettingStatus,
)
from app.rules.compliance_engine import (
    ComplianceStatus,
    evaluate_baseline,
)


def get_ssh_finding(findings):
    return next(
        finding
        for finding in findings
        if finding.rule_id == "NET-SSH-001"
    )


def get_telnet_finding(findings):
    return next(
        finding
        for finding in findings
        if finding.rule_id == "NET-TELNET-001"
    )


def test_explicitly_configured_ssh_version_2_passes() -> None:
    baseline = SecurityBaseline(
        vendor="Cisco",
        device_type="router",
        settings={
            "ssh_protocol_version": SecuritySetting(
                name="ssh_protocol_version",
                value=2,
                status=SettingStatus.CONFIGURED,
                source_lines=(3,),
                evidence=("ip ssh version 2",),
            )
        },
    )

    findings = evaluate_baseline(baseline)
    ssh_finding = get_ssh_finding(findings)

    assert len(findings) == 4
    assert ssh_finding.status == ComplianceStatus.PASS
    assert ssh_finding.source_lines == (3,)


def test_explicitly_configured_ssh_version_1_fails() -> None:
    baseline = SecurityBaseline(
        vendor="Cisco",
        device_type="router",
        settings={
            "ssh_protocol_version": SecuritySetting(
                name="ssh_protocol_version",
                value=1,
                status=SettingStatus.CONFIGURED,
                source_lines=(7,),
                evidence=("ip ssh version 1",),
            )
        },
    )

    findings = evaluate_baseline(baseline)
    ssh_finding = get_ssh_finding(findings)

    assert ssh_finding.status == ComplianceStatus.FAIL
    assert ssh_finding.source_lines == (7,)


def test_missing_ssh_setting_is_unknown() -> None:
    baseline = SecurityBaseline(
        vendor="Cisco",
        device_type="router",
        settings={},
    )

    findings = evaluate_baseline(baseline)
    ssh_finding = get_ssh_finding(findings)

    assert ssh_finding.status == ComplianceStatus.UNKNOWN
    assert ssh_finding.source_lines == ()


def test_ssh_version_with_unknown_status_is_unknown() -> None:
    baseline = SecurityBaseline(
        vendor="Cisco",
        device_type="router",
        settings={
            "ssh_protocol_version": SecuritySetting(
                name="ssh_protocol_version",
                value=2,
                status=SettingStatus.UNKNOWN,
            )
        },
    )

    findings = evaluate_baseline(baseline)
    ssh_finding = get_ssh_finding(findings)

    assert ssh_finding.status == ComplianceStatus.UNKNOWN


def test_unknown_setting_preserves_evidence_and_source_lines() -> None:
    baseline = SecurityBaseline(
        vendor="Cisco",
        device_type="router",
        settings={
            "ssh_protocol_version": SecuritySetting(
                name="ssh_protocol_version",
                value=2,
                status=SettingStatus.UNKNOWN,
                source_lines=(12,),
                evidence=("Ambiguous SSH configuration",),
            )
        },
    )

    findings = evaluate_baseline(baseline)
    ssh_finding = get_ssh_finding(findings)

    assert ssh_finding.status == ComplianceStatus.UNKNOWN
    assert ssh_finding.source_lines == (12,)
    assert "Ambiguous SSH configuration" in ssh_finding.evidence
    assert "Inconclusive parser evidence" in ssh_finding.evidence


def test_unknown_setting_without_value_preserves_evidence() -> None:
    baseline = SecurityBaseline(
        vendor="Cisco",
        device_type="router",
        settings={
            "ssh_protocol_version": SecuritySetting(
                name="ssh_protocol_version",
                value=None,
                status=SettingStatus.UNKNOWN,
                source_lines=(8, 9),
                evidence=("Conflicting SSH commands",),
            )
        },
    )

    findings = evaluate_baseline(baseline)
    ssh_finding = get_ssh_finding(findings)

    assert ssh_finding.status == ComplianceStatus.UNKNOWN
    assert ssh_finding.source_lines == (8, 9)
    assert "Conflicting SSH commands" in ssh_finding.evidence


def test_telnet_disabled_passes() -> None:
    baseline = SecurityBaseline(
        vendor="Cisco",
        device_type="router",
        settings={
            "telnet_permitted": SecuritySetting(
                name="telnet_permitted",
                value=False,
                status=SettingStatus.CONFIGURED,
                source_lines=(12,),
                evidence=("transport input ssh",),
            )
        },
    )

    findings = evaluate_baseline(baseline)
    telnet_finding = get_telnet_finding(findings)

    assert telnet_finding.status == ComplianceStatus.PASS
    assert telnet_finding.source_lines == (12,)


def test_telnet_permitted_fails() -> None:
    baseline = SecurityBaseline(
        vendor="Cisco",
        device_type="router",
        settings={
            "telnet_permitted": SecuritySetting(
                name="telnet_permitted",
                value=True,
                status=SettingStatus.CONFIGURED,
                source_lines=(15,),
                evidence=("transport input ssh telnet",),
            )
        },
    )

    findings = evaluate_baseline(baseline)
    telnet_finding = get_telnet_finding(findings)

    assert telnet_finding.status == ComplianceStatus.FAIL
    assert telnet_finding.source_lines == (15,)


def test_unknown_telnet_setting_remains_unknown() -> None:
    baseline = SecurityBaseline(
        vendor="Cisco",
        device_type="router",
        settings={
            "telnet_permitted": SecuritySetting(
                name="telnet_permitted",
                value=None,
                status=SettingStatus.UNKNOWN,
            )
        },
    )

    findings = evaluate_baseline(baseline)
    telnet_finding = get_telnet_finding(findings)

    assert telnet_finding.status == ComplianceStatus.UNKNOWN
    assert telnet_finding.risk_assessment is not None
