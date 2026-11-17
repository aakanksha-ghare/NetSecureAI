import json
from types import SimpleNamespace

import pytest

import app.services.llm_explanation_service as service


def test_missing_api_key_fails_safely(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="not configured"):
        service.explain_finding({"rule_id": "NET-001"})


def test_explanation_uses_json_and_returns_text(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_MODEL", "test-model")

    captured = {}

    class FakeCompletions:
        def create(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content="Meaning\nThis setting may increase risk."
                        )
                    )
                ]
            )

    class FakeClient:
        def __init__(self, **kwargs):
            captured["client_options"] = kwargs
            self.chat = SimpleNamespace(
                completions=FakeCompletions()
            )

    monkeypatch.setattr(service, "OpenAI", FakeClient)

    finding = {
        "rule_id": "NET-001",
        "title": "SSH password authentication enabled",
        "status": "FAIL",
        "severity": "HIGH",
        "description": "SSH password authentication is enabled.",
    }

    result = service.explain_finding(finding)

    assert result == "Meaning\nThis setting may increase risk."
    assert captured["client_options"]["api_key"] == "test-key"
    assert captured["client_options"]["timeout"] == 20.0
    assert captured["model"] == "test-model"
    assert captured["temperature"] == 0.2
    assert captured["max_tokens"] == 700

    user_message = captured["messages"][1]["content"]
    assert json.loads(user_message) == finding


def test_empty_llm_response_is_rejected(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    class FakeCompletions:
        def create(self, **kwargs):
            return SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(content="  ")
                    )
                ]
            )

    class FakeClient:
        def __init__(self, **kwargs):
            self.chat = SimpleNamespace(
                completions=FakeCompletions()
            )

    monkeypatch.setattr(service, "OpenAI", FakeClient)

    with pytest.raises(RuntimeError, match="empty explanation"):
        service.explain_finding({"rule_id": "NET-001"})


def test_provider_errors_propagate_to_route_handler(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    class FakeCompletions:
        def create(self, **kwargs):
            raise RuntimeError("simulated provider failure")

    class FakeClient:
        def __init__(self, **kwargs):
            self.chat = SimpleNamespace(
                completions=FakeCompletions()
            )

    monkeypatch.setattr(service, "OpenAI", FakeClient)

    with pytest.raises(RuntimeError, match="simulated provider failure"):
        service.explain_finding({"rule_id": "NET-001"})
