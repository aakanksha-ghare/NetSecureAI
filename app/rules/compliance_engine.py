
import json
from dataclasses import dataclass
from enum import Enum

from app.integrity.evidence_integrity import (
    EvidenceHash,
    calculate_sha256,
)
from app.models.risk_assessment import (
    RiskAssessment,
    RiskLevel,
    assess_risk,
)
from app.models.security_baseline import (
    SecurityBaseline,
    SecuritySetting,
    SettingStatus,
)


class ComplianceStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class FrameworkMapping:
    """A related framework control with optional vendor restrictions."""

    framework: str
    control_id: str
    control_title: str
    rationale: str
    vendors: tuple[str, ...] | None = None


@dataclass(frozen=True)
class ComplianceRule:
    rule_id: str
    title: str
    setting_name: str
    expected_value: object
    severity: Severity
    description: str
    remediation: str
    framework: str = "Internal Baseline"
    framework_mappings: tuple[FrameworkMapping, ...] = ()


@dataclass(frozen=True)
class ComplianceFinding:
    rule_id: str
    title: str
    status: ComplianceStatus
    severity: Severity
    description: str
    evidence: str
    source_lines: tuple[int, ...]
    remediation: str
    framework: str
    framework_mappings: tuple[FrameworkMapping, ...] = ()
    risk_assessment: RiskAssessment | None = None
    evidence_hash: EvidenceHash | None = None


# Risk is only assigned when explicitly assessed.
# Technical severity does not automatically determine risk.
DEFAULT_RULES = (
    ComplianceRule(
        rule_id="NET-SSH-001",
        title="Use SSH protocol version 2",
        setting_name="ssh_protocol_version",
        expected_value=2,
        severity=Severity.HIGH,
        description=(
            "SSH version 2 should be explicitly configured to avoid "
            "reliance on insecure SSH version 1 compatibility."
        ),
        remediation=(
            "Configure SSH version 2 and verify that insecure "
            "remote-management protocols are disabled."
        ),
        framework_mappings=(
            FrameworkMapping(
                framework="CIS Cisco IOS Benchmark v2.2",
                control_id="1.1.2.2",
                control_title="Require SSH for Remote Device Access",
                rationale=(
                    "Version-specific related recommendation for secure "
                    "SSH remote access. This rule checks the SSH version "
                    "command, not every benchmark requirement."
                ),
                vendors=("cisco",),
            ),
            FrameworkMapping(
                framework="NIST SP 800-53 Rev. 5",
                control_id="AC-17",
                control_title="Remote Access",
                rationale=(
                    "Related control for authorized and controlled remote "
                    "access. This finding alone does not establish full "
                    "AC-17 compliance."
                ),
            ),
            FrameworkMapping(
                framework="ISO/IEC 27001:2022",
                control_id="A.8.20",
                control_title="Network security",
                rationale=(
                    "Related control for network security. SSH version "
                    "alone is insufficient to assess the full control."
                ),
            ),
            FrameworkMapping(
                framework="DISA Cisco IOS XE Router NDM STIG",
                control_id="V-215845 / CISC-ND-001210",
                control_title="Protect remote maintenance sessions",
                rationale=(
                    "Related requirement for cryptographic protection of "
                    "remote maintenance. Check applicability against the "
                    "selected STIG release."
                ),
                vendors=("cisco",),
            ),
        ),
    ),
    ComplianceRule(
        rule_id="NET-HTTP-001",
        title="Disable the HTTP management server",
        setting_name="http_server_enabled",
        expected_value=False,
        severity=Severity.HIGH,
        description=(
            "The HTTP management server should be disabled unless "
            "there is a documented requirement for it."
        ),
        remediation=(
            "Disable the HTTP management server. If web management is "
            "required, evaluate secure HTTPS configuration."
        ),
        framework_mappings=(
            FrameworkMapping(
                framework="DISA Cisco IOS XE Router NDM STIG",
                control_id="V-215845 / CISC-ND-001210",
                control_title="Protect remote maintenance sessions",
                rationale=(
                    "Related secure remote-management requirement. This "
                    "rule detects HTTP server state but does not assess "
                    "HTTPS configuration or all STIG conditions."
                ),
                vendors=("cisco",),
            ),
            FrameworkMapping(
                framework="ISO/IEC 27001:2022",
                control_id="A.8.20",
                control_title="Network security",
                rationale=(
                    "Related control for network security; this setting "
                    "alone does not establish control compliance."
                ),
            ),
        ),
    ),
    ComplianceRule(
        rule_id="NET-LOG-001",
        title="Configure a logging destination",
        setting_name="logging_enabled",
        expected_value=True,
        severity=Severity.MEDIUM,
        description=(
            "A logging destination should be explicitly configured "
            "to support monitoring and incident investigation."
        ),
        remediation=(
            "Configure an approved logging destination and verify "
            "that events are received and retained."
        ),
        framework_mappings=(
            FrameworkMapping(
                framework="NIST SP 800-53 Rev. 5",
                control_id="AU-12",
                control_title="Audit Record Generation",
                rationale=(
                    "Related audit-record control. A configured "
                    "destination does not verify record coverage, "
                    "content, delivery, or retention."
                ),
            ),
            FrameworkMapping(
                framework="ISO/IEC 27001:2022",
                control_id="A.8.15",
                control_title="Logging",
                rationale=(
                    "Related logging control. This rule checks for a "
                    "destination, not all logging requirements."
                ),
            ),
            FrameworkMapping(
                framework="ISO/IEC 27001:2022",
                control_id="A.8.16",
                control_title="Monitoring activities",
                rationale=(
                    "Related monitoring control. This rule does not "
                    "verify active monitoring or alerting."
                ),
            ),
        ),
    ),
    ComplianceRule(
        rule_id="NET-TELNET-001",
        title="Restrict Telnet on VTY lines",
        setting_name="telnet_permitted",
        expected_value=False,
        severity=Severity.HIGH,
        description=(
            "Telnet should not be permitted for remote terminal access "
            "because it does not provide SSH-equivalent encryption."
        ),
        remediation=(
            "Configure each applicable VTY section to permit SSH only, "
            "then verify the effective remote-access configuration."
        ),
        framework_mappings=(
            FrameworkMapping(
                framework="NIST SP 800-53 Rev. 5",
                control_id="SC-8",
                control_title="Transmission Confidentiality and Integrity",
                rationale=(
                    "Related control for protecting transmitted "
                    "information. This finding alone does not establish "
                    "full SC-8 compliance."
                ),
            ),
            FrameworkMapping(
                framework="ISO/IEC 27001:2022",
                control_id="A.8.20",
                control_title="Network security",
                rationale=(
                    "Related network security control; this setting "
                    "alone does not establish full control compliance."
                ),
            ),
        ),
    ),
)


def _hash_setting_evidence(
    setting: SecuritySetting | None,
) -> EvidenceHash | None:
    """Hash a normalized setting when supporting evidence exists.

    The digest covers the normalized value and evidence metadata.
    It does not represent the entire original configuration file.
    """
    if setting is None:
        return None

    if not setting.evidence and not setting.source_lines:
        return None

    evidence_record = {
        "name": setting.name,
        "status": setting.status.value,
        "value": setting.value,
        "source_lines": list(setting.source_lines),
        "evidence": list(setting.evidence),
    }

    try:
        canonical_evidence = json.dumps(
            evidence_record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        # Avoid producing a misleading digest for unsupported values.
        return None

    return calculate_sha256(canonical_evidence)


def evaluate_baseline(
    baseline: SecurityBaseline,
    rules: tuple[ComplianceRule, ...] = DEFAULT_RULES,
    risk_inputs: dict[
        str, tuple[int | None, int | None, str]
    ] | None = None,
) -> list[ComplianceFinding]:
    """Evaluate normalized settings and assess risk for confirmed failures.

    risk_inputs maps a rule ID to:
        (likelihood, impact, rationale)

    Likelihood and impact use a 1-5 scale.
    Risk is not inferred from technical severity.
    """
    findings: list[ComplianceFinding] = []
    supplied_risk_inputs = risk_inputs or {}
    vendor = baseline.vendor.strip().lower()

    for rule in rules:
        setting = baseline.get_setting(rule.setting_name)

        if (
            setting is None
            or setting.status != SettingStatus.CONFIGURED
            or setting.value is None
        ):
            status = ComplianceStatus.UNKNOWN
            evidence_parts = [
                "No conclusive configuration evidence was found for "
                f"'{rule.setting_name}'."
            ]

            if setting is not None:
                source_lines = setting.source_lines
                if setting.evidence:
                    evidence_parts.append(
                        "Inconclusive parser evidence: "
                        + " | ".join(setting.evidence)
                    )
            else:
                source_lines = ()

            evidence = " ".join(evidence_parts)
        elif setting.value == rule.expected_value:
            status = ComplianceStatus.PASS
            evidence = (
                f"Observed '{rule.setting_name}' = {setting.value!r}; "
                f"expected {rule.expected_value!r}."
            )
            source_lines = setting.source_lines
        else:
            status = ComplianceStatus.FAIL
            evidence = (
                f"Observed '{rule.setting_name}' = {setting.value!r}; "
                f"expected {rule.expected_value!r}."
            )
            source_lines = setting.source_lines

        risk_assessment: RiskAssessment | None = None

        if (
            status == ComplianceStatus.FAIL
            and rule.rule_id in supplied_risk_inputs
        ):
            likelihood, impact, rationale = supplied_risk_inputs[
                rule.rule_id
            ]
            risk_assessment = assess_risk(
                likelihood=likelihood,
                impact=impact,
                rationale=rationale,
            )
        elif status == ComplianceStatus.UNKNOWN:
            risk_assessment = RiskAssessment(
                likelihood=None,
                impact=None,
                score=None,
                level=RiskLevel.NOT_ASSESSED,
                rationale=(
                    "Risk was not assessed because the configuration "
                    "evidence is inconclusive."
                ),
            )

        applicable_mappings = tuple(
            mapping
            for mapping in rule.framework_mappings
            if mapping.vendors is None
            or vendor in mapping.vendors
        )

        findings.append(
            ComplianceFinding(
                rule_id=rule.rule_id,
                title=rule.title,
                status=status,
                severity=rule.severity,
                description=rule.description,
                evidence=evidence,
                source_lines=source_lines,
                remediation=rule.remediation,
                framework=rule.framework,
                framework_mappings=applicable_mappings,
                risk_assessment=risk_assessment,
                evidence_hash=_hash_setting_evidence(setting),
            )
        )

    return findings
