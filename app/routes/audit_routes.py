
from io import BytesIO

from flask import (
    Blueprint,
    current_app,
    jsonify,
    request,
    send_file,
)

from app.integrity.evidence_integrity import (
    calculate_configuration_hash,
    verify_sha256,
)
from app.integrity.evidence_record import create_evidence_record
from app.integrity.evidence_store import (
    get_evidence_record,
    save_evidence_record,
)
from app.services.audit_service import audit_config
from app.services.pdf_report_service import generate_pdf_report
from app.services.report_service import build_audit_report
from app.integrity.evidence_ledger import LedgerStatus
from app.integrity.evidence_ledger_service import (
    verify_evidence_against_ledger,
)

audit_bp = Blueprint("audit", __name__)


def serialize_findings(findings):
    """Convert compliance findings into JSON-compatible dictionaries."""

    serialized = []

    for finding in findings:
        risk = finding.risk_assessment
        evidence_hash = finding.evidence_hash

        serialized.append(
            {
                "rule_id": finding.rule_id,
                "title": finding.title,
                "status": finding.status.value,
                "severity": finding.severity.value,
                "description": finding.description,
                "evidence": finding.evidence,
                "source_lines": list(finding.source_lines),
                "remediation": finding.remediation,
                "rule_source": finding.framework,
                "framework_mappings": [
                    {
                        "framework": mapping.framework,
                        "control_id": mapping.control_id,
                        "control_title": mapping.control_title,
                        "rationale": mapping.rationale,
                    }
                    for mapping in finding.framework_mappings
                ],
                "risk_assessment": (
                    {
                        "likelihood": risk.likelihood,
                        "impact": risk.impact,
                        "score": risk.score,
                        "level": risk.level.value,
                        "rationale": risk.rationale,
                    }
                    if risk is not None
                    else None
                ),
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

    return serialized


def process_audit(vendor, as_pdf=False):
    """Validate an audit request and return JSON results or a PDF report."""

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify(
            error="Request body must be a JSON object."
        ), 400

    config_text = data.get("config")

    if not isinstance(config_text, str) or not config_text.strip():
        return jsonify(
            error="'config' must contain configuration text."
        ), 400

    raw_risk_inputs = data.get("risk_inputs", {})

    if not isinstance(raw_risk_inputs, dict):
        return jsonify(
            error="'risk_inputs' must be a JSON object."
        ), 400

    risk_inputs = {}

    for rule_id, values in raw_risk_inputs.items():
        if not isinstance(rule_id, str) or not isinstance(values, dict):
            return jsonify(
                error=(
                    "Each risk input must be an object keyed by a "
                    "compliance rule ID."
                )
            ), 400

        likelihood = values.get("likelihood")
        impact = values.get("impact")
        rationale = values.get("rationale")

        if (
            likelihood is not None
            and (
                isinstance(likelihood, bool)
                or not isinstance(likelihood, int)
                or not 1 <= likelihood <= 5
            )
        ):
            return jsonify(
                error=(
                    f"Invalid likelihood for rule '{rule_id}'; "
                    "use 1-5 or null."
                )
            ), 400

        if (
            impact is not None
            and (
                isinstance(impact, bool)
                or not isinstance(impact, int)
                or not 1 <= impact <= 5
            )
        ):
            return jsonify(
                error=(
                    f"Invalid impact for rule '{rule_id}'; "
                    "use 1-5 or null."
                )
            ), 400

        if not isinstance(rationale, str) or not rationale.strip():
            return jsonify(
                error=(
                    f"A non-empty rationale is required "
                    f"for rule '{rule_id}'."
                )
            ), 400

        risk_inputs[rule_id] = (likelihood, impact, rationale)

    try:
        baseline, findings = audit_config(
            vendor=vendor,
            config_text=config_text,
            risk_inputs=risk_inputs,
        )
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    configuration_hash = calculate_configuration_hash(config_text)

    finding_ids = tuple(
        finding.rule_id for finding in findings
    )

    evidence_record = create_evidence_record(
        vendor=baseline.vendor,
        configuration_text=config_text,
        finding_ids=finding_ids,
    )

    # Queue the digest only when ledger integration is enabled.
    # Evidence persistence and outbox insertion are atomic, and no
    # network or ledger operation is performed during the audit request.
    queue_for_ledger = bool(
        current_app.config.get("EVIDENCE_LEDGER_ENABLED", False)
    )

    save_evidence_record(
        evidence_record,
        current_app.config["EVIDENCE_DATABASE"],
        queue_for_ledger=queue_for_ledger,
    )

    hash_data = {
        "algorithm": configuration_hash.algorithm,
        "digest": configuration_hash.digest,
        "evidence_size": configuration_hash.evidence_size,
    }

    evidence_record_data = evidence_record.to_dict()

    if as_pdf:
        report = build_audit_report(
            baseline=baseline,
            findings=findings,
            configuration_hash=hash_data,
            evidence_record=evidence_record_data,
        )

        pdf_bytes = generate_pdf_report(report)
        filename_vendor = baseline.vendor.lower().replace(" ", "-")

        return send_file(
            BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=(
                f"netsecureai-{filename_vendor}-audit-report.pdf"
            ),
        )

    return jsonify(
        vendor=baseline.vendor,
        device_type=baseline.device_type,
        configuration_hash=hash_data,
        evidence_record=evidence_record_data,
        findings=serialize_findings(findings),
    ), 200


@audit_bp.post("/api/audit/<vendor>")
def audit_vendor(vendor):
    """Audit a configuration for a registered vendor."""

    return process_audit(vendor)


@audit_bp.post("/api/audit/<vendor>/report")
def audit_vendor_report(vendor):
    """Audit a vendor configuration and return a downloadable PDF."""

    return process_audit(vendor, as_pdf=True)


@audit_bp.post("/api/audit/cisco")
def audit_cisco():
    """Backward-compatible Cisco audit endpoint."""

    return process_audit("cisco")


@audit_bp.get("/api/evidence/<record_id>")
def retrieve_evidence(record_id: str):
    """Retrieve persisted evidence metadata by record ID."""

    record = get_evidence_record(
        record_id,
        current_app.config["EVIDENCE_DATABASE"],
    )

    if record is None:
        return jsonify(
            error="Evidence record not found.",
            record_id=record_id,
        ), 404

    return jsonify(record), 200


@audit_bp.post("/api/evidence/<record_id>/verify")
def verify_evidence(record_id: str):
    """Verify supplied configuration against a stored SHA-256 hash."""

    record = get_evidence_record(
        record_id,
        current_app.config["EVIDENCE_DATABASE"],
    )

    if record is None:
        return jsonify(
            error="Evidence record not found.",
            record_id=record_id,
        ), 404

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify(
            error="A JSON object containing 'configuration' is required."
        ), 400

    configuration = payload.get("configuration")

    if not isinstance(configuration, str):
        return jsonify(
            error="'configuration' must be a string."
        ), 400

    expected_hash = record["configuration_hash"]["digest"]

    try:
        matches = verify_sha256(configuration, expected_hash)
    except (TypeError, ValueError):
        matches = False

    actual_hash = calculate_configuration_hash(configuration)

    return jsonify(
        record_id=record_id,
        verified=matches,
        expected_hash=expected_hash,
        supplied_hash=actual_hash.digest,
        message=(
            "Configuration integrity verified."
            if matches
            else "Configuration does not match the recorded hash."
        ),
    ), 200


@audit_bp.post("/api/evidence/<record_id>/verify-ledger")
def verify_evidence_ledger(record_id: str):
    """Verify evidence metadata against an independent ledger."""

    record = get_evidence_record(
        record_id,
        current_app.config["EVIDENCE_DATABASE"],
    )

    if record is None:
        return jsonify(
            status="NOT_FOUND",
            record_id=record_id,
            message="Evidence record not found locally.",
        ), 404

    if not current_app.config.get("EVIDENCE_LEDGER_ENABLED", False):
        return jsonify(
            status="UNAVAILABLE",
            record_id=record_id,
            message="Independent ledger verification is not enabled.",
        ), 503

    ledger = current_app.extensions.get("evidence_ledger")

    if ledger is None:
        return jsonify(
            status="UNAVAILABLE",
            record_id=record_id,
            message="No ledger adapter is configured.",
        ), 503

    hash_data = record.get("configuration_hash")

    if not isinstance(hash_data, dict):
        return jsonify(
            status="UNAVAILABLE",
            record_id=record_id,
            message="Stored evidence hash metadata is invalid.",
        ), 503

    if hash_data.get("algorithm") != "SHA-256":
        return jsonify(
            status="UNAVAILABLE",
            record_id=record_id,
            message="Stored evidence hash algorithm is unsupported.",
        ), 503

    digest = hash_data.get("digest")

    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(c not in "0123456789abcdefABCDEF" for c in digest)
    ):
        return jsonify(
            status="UNAVAILABLE",
            record_id=record_id,
            message="Stored evidence digest is invalid.",
        ), 503

    result = verify_evidence_against_ledger(
        ledger,
        record_id,
        digest,
    )

    status_codes = {
        LedgerStatus.MATCH: 200,
        LedgerStatus.MISMATCH: 200,
        LedgerStatus.NOT_FOUND: 404,
        LedgerStatus.UNAVAILABLE: 503,
    }

    return jsonify(
        status=result.status.value,
        record_id=record_id,
        message=result.detail or {
            LedgerStatus.MATCH: "Ledger digest matches the stored digest.",
            LedgerStatus.MISMATCH: "Ledger digest differs from the stored digest.",
            LedgerStatus.NOT_FOUND: "Evidence record was not found in the ledger.",
            LedgerStatus.UNAVAILABLE: "Ledger verification is unavailable.",
        }[result.status],
    ), status_codes[result.status]
