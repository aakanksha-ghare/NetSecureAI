
import os
from pathlib import Path

import click
from flask import Flask, Response, jsonify

from app.integrity.evidence_store import initialize_evidence_store
from app.integrity.evidence_ledger_worker import process_ledger_outbox
from app.routes.audit_routes import audit_bp
from app.routes.dashboard_routes import dashboard_bp
from app.routes.llm_routes import llm_bp


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)

    default_database_path = (
        Path(__file__).resolve().parent.parent
        / "instance"
        / "evidence.db"
    )

    app.config.from_mapping(
        EVIDENCE_DATABASE=os.environ.get(
            "NETSECUREAI_EVIDENCE_DATABASE",
            str(default_database_path),
        ),
        MAX_CONTENT_LENGTH=1_048_576,
        EVIDENCE_LEDGER_ENABLED=False,
        EVIDENCE_LEDGER_ADAPTER=None,
    )

    if test_config:
        app.config.update(test_config)

    app.extensions["evidence_ledger"] = app.config.get(
        "EVIDENCE_LEDGER_ADAPTER"
    )

    initialize_evidence_store(app.config["EVIDENCE_DATABASE"])

    app.register_blueprint(audit_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(llm_bp)

    @app.cli.command("process-evidence-ledger-outbox")
    @click.option(
        "--limit",
        type=click.IntRange(min=1),
        default=100,
        show_default=True,
        help="Maximum number of queued evidence records to process.",
    )
    def process_evidence_ledger_outbox(limit: int) -> None:
        """Process queued evidence digests using the configured ledger."""

        if not app.config.get("EVIDENCE_LEDGER_ENABLED", False):
            raise click.ClickException(
                "Ledger integration is disabled. "
                "Enable EVIDENCE_LEDGER_ENABLED before processing the outbox."
            )

        ledger = app.extensions.get("evidence_ledger")

        if ledger is None:
            raise click.ClickException(
                "No evidence ledger adapter is configured. "
                "Configure EVIDENCE_LEDGER_ADAPTER before processing the outbox."
            )

        try:
            summary = process_ledger_outbox(
                ledger=ledger,
                database_path=app.config["EVIDENCE_DATABASE"],
                limit=limit,
            )
        except Exception as exc:
            raise click.ClickException(
                f"Outbox processing failed: {type(exc).__name__}."
            ) from exc

        click.echo("Evidence ledger outbox processing complete.")
        click.echo(f"Selected: {summary['selected']}")
        click.echo(f"Anchored: {summary['anchored']}")
        click.echo(f"Retry required: {summary['retry']}")
        click.echo(f"Conflicts: {summary['conflict']}")
        click.echo(f"Not updated: {summary['not_updated']}")

    @app.get("/health")
    def health() -> Response:
        return jsonify(status="healthy")

    return app
