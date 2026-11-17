
import pytest

from app.services.audit_service import audit_config
from app.services.pdf_report_service import generate_pdf_report
from app.services.report_service import build_audit_report


def test_generate_pdf_report_returns_valid_pdf_bytes():
    baseline, findings = audit_config(
        "cisco",
        "hostname CoreRouter01\nip ssh version 1\n",
        risk_inputs={
            "NET-SSH-001": (
                4,
                5,
                "Insecure SSH version could expose remote administration.",
            )
        },
    )

    report = build_audit_report(
        baseline,
        findings,
        configuration_hash={
            "algorithm": "SHA-256",
            "digest": "a" * 64,
            "evidence_size": 35,
        },
        evidence_record={
            "record_id": "test-record",
            "created_at": "2026-10-17T00:00:00+00:00",
        },
    )

    pdf_bytes = generate_pdf_report(report)

    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 500


def test_generate_pdf_report_supports_unknown_findings():
    baseline, _ = audit_config("cisco", "hostname CoreRouter01\n")
    from app.rules.compliance_engine import evaluate_baseline

    findings = evaluate_baseline(baseline)
    report = build_audit_report(baseline, findings)

    pdf_bytes = generate_pdf_report(report)

    assert pdf_bytes.startswith(b"%PDF-")


def test_generate_pdf_report_rejects_invalid_report_type():
    with pytest.raises(TypeError, match="dictionary"):
        generate_pdf_report(None)  # type: ignore[arg-type]


def test_generate_pdf_report_rejects_missing_sections():
    with pytest.raises(ValueError, match="report_metadata"):
        generate_pdf_report({})
