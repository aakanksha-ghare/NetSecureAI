
import pytest

from app.models.security_baseline import SecurityBaseline
from app.services.audit_service import audit_config
from app.services.report_service import build_audit_report


@pytest.fixture
def audited_config():
    config = """
hostname CoreRouter01
ip ssh version 2
no ip http server
logging host 192.0.2.10
"""
    return audit_config("cisco", config)


def test_report_contains_device_and_summary(audited_config):
    baseline, findings = audited_config

    report = build_audit_report(baseline, findings)

    assert report["device"]["vendor"] == baseline.vendor
    assert report["device"]["device_type"] == baseline.device_type
    assert report["summary"]["total_findings"] == len(findings)
    assert report["summary"]["passed"] + report["summary"]["failed"] + (
        report["summary"]["unknown"]
    ) == len(findings)


def test_unknown_findings_are_not_counted_as_failures():
    baseline = SecurityBaseline(
        vendor="TestVendor",
        device_type="Router",
        settings={},
    )

    _, findings = audit_config(
        "cisco",
        "hostname TestRouter\n",
    )

    # Use a genuine empty baseline with the standard rules.
    from app.rules.compliance_engine import evaluate_baseline

    unknown_findings = evaluate_baseline(baseline)
    report = build_audit_report(baseline, unknown_findings)

    assert report["summary"]["failed"] == 0
    assert report["summary"]["unknown"] == len(unknown_findings)
    assert report["summary"]["compliance_rate_percent"] is None


def test_report_preserves_framework_mappings(audited_config):
    baseline, findings = audited_config

    report = build_audit_report(baseline, findings)

    assert report["framework_controls"]
    assert all(
        "framework" in control and "control_id" in control
        for control in report["framework_controls"]
    )



def test_report_preserves_assessed_risk_separately():
    from app.rules.compliance_engine import evaluate_baseline
    from app.parsers.cisco_parser import parse_cisco_config

    baseline = parse_cisco_config(
    "hostname CoreRouter01\n"
    "ip ssh version 1\n"
)

    findings = evaluate_baseline(
        baseline,
        risk_inputs={
            "NET-SSH-001": (
                4,
                5,
                "Unprotected remote administration could expose the device.",
            )
        },
    )

    report = build_audit_report(baseline, findings)

    ssh_finding = next(
        item
        for item in report["findings"]
        if item["rule_id"] == "NET-SSH-001"
    )

    assert ssh_finding["status"] == "FAIL"
    assert ssh_finding["severity"] == "HIGH"
    assert ssh_finding["risk_assessment"]["score"] == 20
    assert ssh_finding["risk_assessment"]["level"] == "CRITICAL"

def test_report_rejects_invalid_inputs():
    with pytest.raises(TypeError):
        build_audit_report(None, [])  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        build_audit_report(
            SecurityBaseline("Cisco", "Router", {}),
            [None],  # type: ignore[list-item]
        )
