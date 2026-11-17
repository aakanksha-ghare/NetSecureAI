
import json

from app.integrity.evidence_integrity import verify_sha256
from app.models.security_baseline import (
    SecurityBaseline,
    SecuritySetting,
    SettingStatus,
)
from app.rules.compliance_engine import (
    ComplianceRule,
    ComplianceStatus,
    Severity,
    _hash_setting_evidence,
    evaluate_baseline,
)


def make_setting(
    *,
    value: object = 2,
    evidence: tuple[str, ...] = ("ip ssh version 2",),
    source_lines: tuple[int, ...] = (5,),
) -> SecuritySetting:
    return SecuritySetting(
        name="ssh_protocol_version",
        value=value,
        status=SettingStatus.CONFIGURED,
        source_lines=source_lines,
        evidence=evidence,
    )


def canonical_setting_evidence(setting: SecuritySetting) -> str:
    """Recreate the canonical payload used by the evidence hash helper."""
    return json.dumps(
        {
            "name": setting.name,
            "status": setting.status.value,
            "value": setting.value,
            "source_lines": list(setting.source_lines),
            "evidence": list(setting.evidence),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def test_evidence_hash_is_generated_for_supported_evidence() -> None:
    evidence_hash = _hash_setting_evidence(make_setting())

    assert evidence_hash is not None
    assert evidence_hash.algorithm == "SHA-256"
    assert len(evidence_hash.digest) == 64
    assert evidence_hash.evidence_size > 0


def test_unchanged_evidence_produces_the_same_hash() -> None:
    first_hash = _hash_setting_evidence(make_setting())
    second_hash = _hash_setting_evidence(make_setting())

    assert first_hash is not None
    assert second_hash is not None
    assert first_hash.digest == second_hash.digest


def test_changed_evidence_produces_a_different_hash() -> None:
    first_hash = _hash_setting_evidence(
        make_setting(evidence=("ip ssh version 2",))
    )
    second_hash = _hash_setting_evidence(
        make_setting(evidence=("ip ssh version 1",))
    )

    assert first_hash is not None
    assert second_hash is not None
    assert first_hash.digest != second_hash.digest


def test_changed_setting_value_produces_a_different_hash() -> None:
    first_hash = _hash_setting_evidence(make_setting(value=2))
    second_hash = _hash_setting_evidence(make_setting(value=1))

    assert first_hash is not None
    assert second_hash is not None
    assert first_hash.digest != second_hash.digest


def test_hash_is_absent_when_supporting_evidence_is_missing() -> None:
    setting = make_setting(evidence=(), source_lines=())

    assert _hash_setting_evidence(setting) is None
    assert _hash_setting_evidence(None) is None


def test_hash_verification_accepts_matching_evidence() -> None:
    setting = make_setting()
    evidence_hash = _hash_setting_evidence(setting)

    assert evidence_hash is not None
    assert verify_sha256(
        canonical_setting_evidence(setting),
        evidence_hash.digest,
    )


def test_compliance_finding_contains_evidence_hash() -> None:
    setting = make_setting()

    baseline = SecurityBaseline(
        vendor="cisco",
        device_type="router",
        settings={setting.name: setting},
    )

    rule = ComplianceRule(
        rule_id="TEST-SSH-001",
        title="Use SSH version 2",
        setting_name="ssh_protocol_version",
        expected_value=2,
        severity=Severity.HIGH,
        description="SSH version 2 should be configured.",
        remediation="Configure SSH version 2.",
    )

    findings = evaluate_baseline(baseline, rules=(rule,))

    assert len(findings) == 1
    finding = findings[0]

    assert finding.status == ComplianceStatus.PASS
    assert finding.evidence_hash is not None
    assert finding.evidence_hash.algorithm == "SHA-256"
    assert verify_sha256(
        canonical_setting_evidence(setting),
        finding.evidence_hash.digest,
    )
