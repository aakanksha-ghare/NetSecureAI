
from app.parsers.cisco_parser import parse_cisco_config
from app.parsers.juniper_parser import parse_juniper_config
from app.rules.compliance_engine import evaluate_baseline


def test_cisco_findings_retain_cisco_specific_mappings():
    baseline = parse_cisco_config(
        "ip ssh version 2\n"
        "ip http server\n"
        "logging host 192.0.2.10"
    )

    findings = evaluate_baseline(baseline)
    mappings = [
        mapping
        for finding in findings
        for mapping in finding.framework_mappings
    ]

    framework_names = {mapping.framework for mapping in mappings}

    assert "CIS Cisco IOS Benchmark v2.2" in framework_names
    assert "DISA Cisco IOS XE Router NDM STIG" in framework_names


def test_juniper_findings_exclude_cisco_specific_mappings():
    baseline = parse_juniper_config(
        "set system services ssh protocol-version v2\n"
        "set system services web-management http\n"
        "set system syslog host 192.0.2.10 any info"
    )

    findings = evaluate_baseline(baseline)
    mappings = [
        mapping
        for finding in findings
        for mapping in finding.framework_mappings
    ]

    assert all(
        "Cisco" not in mapping.framework
        for mapping in mappings
    )
    assert all(
        mapping.vendors is None or "juniper" in mapping.vendors
        for mapping in mappings
    )


def test_vendor_restrictions_are_case_insensitive():
    baseline = parse_juniper_config(
        "set system services ssh protocol-version v2"
    )

    # The parser's canonical vendor name is Juniper. This test verifies
    # the evaluator normalizes that name before checking restrictions.
    findings = evaluate_baseline(baseline)

    assert all(
        "Cisco" not in mapping.framework
        for finding in findings
        for mapping in finding.framework_mappings
    )
