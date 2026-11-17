from flask import Blueprint, current_app, jsonify, request

from app.services.llm_explanation_service import explain_finding

llm_bp = Blueprint("llm", __name__)

MAX_FINDING_CHARS = 16_000
REQUIRED_FIELDS = {
    "rule_id",
    "title",
    "status",
    "severity",
    "description",
}


@llm_bp.post("/api/findings/explain")
def explain_audit_finding():
    if not request.is_json:
        return jsonify(error="Request body must be JSON."), 415

    finding = request.get_json(silent=True)

    if not isinstance(finding, dict):
        return jsonify(error="Request body must be a JSON object."), 400

    missing = sorted(REQUIRED_FIELDS - finding.keys())
    if missing:
        return jsonify(
            error="Required finding fields are missing.",
            missing_fields=missing,
        ), 400

    if any(
        not isinstance(finding[field], str) or not finding[field].strip()
        for field in REQUIRED_FIELDS
    ):
        return jsonify(
            error="Required finding fields must be non-empty strings."
        ), 400

    if any(
        not isinstance(value, (str, int, float, bool, list, dict, type(None)))
        for value in finding.values()
    ):
        return jsonify(error="Finding contains unsupported data."), 400

    if len(str(finding)) > MAX_FINDING_CHARS:
        return jsonify(error="Finding exceeds the size limit."), 413

    try:
        explanation = explain_finding(finding)
        return jsonify(explanation=explanation), 200
    except RuntimeError as exc:
        if str(exc) == "LLM explanations are not configured.":
            return jsonify(error="LLM explanations are not configured."), 503

        current_app.logger.warning("LLM explanation configuration error.")
        return jsonify(error="Unable to generate an explanation."), 502
    except Exception:
        current_app.logger.warning("LLM explanation request failed.")
        return jsonify(error="Unable to generate an explanation."), 502
