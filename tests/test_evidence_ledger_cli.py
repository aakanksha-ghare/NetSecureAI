
from app import create_app
from app.integrity.evidence_ledger import (
    LedgerAnchorResult,
    LedgerAnchorStatus,
)
from app.integrity.evidence_record import create_evidence_record
from app.integrity.evidence_store import (
    get_ledger_outbox_item,
    save_evidence_record,
)


class FakeLedger:
    def anchor(self, record_id, digest):
        return LedgerAnchorResult(
            status=LedgerAnchorStatus.ANCHORED,
            record_id=record_id,
        )

    def verify(self, record_id, local_digest):
        raise AssertionError(
            "Verification should not be needed for a new anchor."
        )


def test_cli_refuses_when_ledger_integration_is_disabled(tmp_path):
    app = create_app({
        "TESTING": True,
        "EVIDENCE_DATABASE": str(tmp_path / "evidence.db"),
        "EVIDENCE_LEDGER_ENABLED": False,
        "EVIDENCE_LEDGER_ADAPTER": FakeLedger(),
    })

    result = app.test_cli_runner().invoke(
        args=["process-evidence-ledger-outbox"]
    )

    assert result.exit_code != 0
    assert "Ledger integration is disabled" in result.output


def test_cli_refuses_when_adapter_is_missing(tmp_path):
    app = create_app({
        "TESTING": True,
        "EVIDENCE_DATABASE": str(tmp_path / "evidence.db"),
        "EVIDENCE_LEDGER_ENABLED": True,
        "EVIDENCE_LEDGER_ADAPTER": None,
    })

    result = app.test_cli_runner().invoke(
        args=["process-evidence-ledger-outbox"]
    )

    assert result.exit_code != 0
    assert "No evidence ledger adapter is configured" in result.output


def test_cli_processes_pending_evidence(tmp_path):
    database_path = str(tmp_path / "evidence.db")

    app = create_app({
        "TESTING": True,
        "EVIDENCE_DATABASE": database_path,
        "EVIDENCE_LEDGER_ENABLED": True,
        "EVIDENCE_LEDGER_ADAPTER": FakeLedger(),
    })

    record = create_evidence_record(
        vendor="cisco_ios",
        configuration_text="hostname test-router",
        finding_ids=(),
    )

    save_evidence_record(
        record,
        database_path,
        queue_for_ledger=True,
    )

    result = app.test_cli_runner().invoke(
        args=["process-evidence-ledger-outbox"]
    )

    assert result.exit_code == 0, result.output
    assert "Selected: 1" in result.output
    assert "Anchored: 1" in result.output
    assert "Retry required: 0" in result.output
    assert "Conflicts: 0" in result.output

    outbox_item = get_ledger_outbox_item(
        record.record_id,
        database_path,
    )
    assert outbox_item["status"] == "ANCHORED"
    assert outbox_item["attempts"] == 1


def test_cli_respects_limit_option(tmp_path):
    database_path = str(tmp_path / "evidence.db")

    app = create_app({
        "TESTING": True,
        "EVIDENCE_DATABASE": database_path,
        "EVIDENCE_LEDGER_ENABLED": True,
        "EVIDENCE_LEDGER_ADAPTER": FakeLedger(),
    })

    for index in range(2):
        record = create_evidence_record(
            vendor="cisco_ios",
            configuration_text=f"hostname test-router-{index}",
            finding_ids=(),
        )
        save_evidence_record(
            record,
            database_path,
            queue_for_ledger=True,
        )

    result = app.test_cli_runner().invoke(
        args=["process-evidence-ledger-outbox", "--limit", "1"]
    )

    assert result.exit_code == 0, result.output
    assert "Selected: 1" in result.output
