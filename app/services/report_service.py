
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from app.models.security_baseline import SecurityBaseline
from app.rules.compliance_engine import (
    ComplianceFinding,
    ComplianceStatus,
)


def build_audit_report(
    baseline: SecurityBaseline,
    findings: list[ComplianceFinding],
    configuration_hash: dict[str, Any] | None = None,
    evidence_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a structured report from normalized audit results.

    Technical severity and assessed risk remain separate.
    UNKNOWN findings are not counted as failures.
    Framework mappings indicate related controls, not full
    framework compliance.
    """
    if not isinstance(baseline, SecurityBaseline):
        raise TypeError("baseline must be a SecurityBaseline instance.")

    if not isinstance(findings, list):
        raise TypeError("findings must be a list.")

    if any(
        not isinstance(finding, ComplianceFinding)
        for finding in findings
    ):
        raise TypeError(
            "Every item in findings must be a ComplianceFinding."
        )

    status_counts = Counter(
        finding.status.value for finding in findings
    )
    severity_counts = Counter(
        finding.severity.value for finding in findings
    )

    risk_counts = Counter()
    serialized_findings: list[dict[str, Any]] = []
    framework_controls: list[dict[str, str]] = []

    for finding in findings:
        risk = finding.risk_assessment

        if risk is not None:
            risk_counts[risk.level.value] += 1

        mappings = [
            {
                "framework": mapping.framework,
                "control_id": mapping.control_id,
                "control_title": mapping.control_title,
                "rationale": mapping.rationale,
            }
            for mapping in finding.framework_mappings
        ]

        framework_controls.extend(
            {
                "rule_id": finding.rule_id,
                **mapping,
            }
            for mapping in mappings
        )

        evidence_hash = finding.evidence_hash
        risk_data = None

        if risk is not None:
            risk_data = {
                "likelihood": risk.likelihood,
                "impact": risk.impact,
                "score": risk.score,
                "level": risk.level.value,
                "rationale": risk.rationale,
            }

        serialized_findings.append(
            {
                "rule_id": finding.rule_id,
                "title": finding.title,
                "status": finding.status.value,
                "severity": finding.severity.value,
                "description": finding.description,
                "evidence": finding.evidence,
                "source_lines": list(finding.source_lines),
                "remediation": finding.remediation,
                "framework": finding.framework,
                "framework_mappings": mappings,
                "risk_assessment": risk_data,
                "evidence_hash": (
                    {
                        "algorithm": evidence_hash.algorithm,
                        "digest": evidence_hash.digest,
                        "evidence_size": evidence_hash.evidence_size,
                    }
                    if evidence_hash is not None
                    else None
                ),
            }
        )

    total = len(findings)
    passed = status_counts[ComplianceStatus.PASS.value]
    failed = status_counts[ComplianceStatus.FAIL.value]
    unknown = status_counts[ComplianceStatus.UNKNOWN.value]

    # Only conclusive PASS/FAIL findings are included in the
    # compliance rate denominator. UNKNOWN is reported separately.
    conclusive = passed + failed
    compliance_rate = (
        round(passed / conclusive * 100, 2)
        if conclusive
        else None
    )

    return {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_type": "Network Security Compliance Audit",
            "assessment_note": (
                "Framework mappings identify related controls and do "
                "not establish full framework compliance."
            ),
        },
        "device": {
            "vendor": baseline.vendor,
            "device_type": baseline.device_type,
        },
        "summary": {
            "total_findings": total,
            "passed": passed,
            "failed": failed,
            "unknown": unknown,
            "compliance_rate_percent": compliance_rate,
            "severity_counts": {
                severity: severity_counts.get(severity, 0)
                for severity in (
                    "LOW",
                    "MEDIUM",
                    "HIGH",
                    "CRITICAL",
                )
            },
            "assessed_risk_counts": {
                level: risk_counts.get(level, 0)
                for level in (
                    "LOW",
                    "MEDIUM",
                    "HIGH",
                    "CRITICAL",
                    "NOT_ASSESSED",
                )
            },
        },
        "configuration_hash": configuration_hash,
        "evidence_record": evidence_record,
        "framework_controls": framework_controls,
        "findings": serialized_findings,
    }
