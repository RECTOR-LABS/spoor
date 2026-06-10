import pytest

from spoor_sift.model import build_chat_model


def _model_of(m):
    return getattr(m, "model", None) or getattr(m, "model_name", None)


def test_uses_openrouter_when_key_present(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("SPOOR_MODEL", "anthropic/claude-sonnet-4")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    from langchain_openai import ChatOpenAI

    model = build_chat_model("specialist")
    assert isinstance(model, ChatOpenAI)
    assert _model_of(model) == "anthropic/claude-sonnet-4"
    assert "openrouter.ai" in str(model.openai_api_base)


def test_lead_role_prefers_lead_model(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("SPOOR_MODEL", "model-specialist")
    monkeypatch.setenv("SPOOR_LEAD_MODEL", "model-lead")
    assert _model_of(build_chat_model("lead")) == "model-lead"


def test_lead_falls_back_to_spoor_model(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("SPOOR_MODEL", "model-specialist")
    monkeypatch.delenv("SPOOR_LEAD_MODEL", raising=False)
    assert _model_of(build_chat_model("lead")) == "model-specialist"


def test_falls_back_to_anthropic_when_only_anthropic_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("SPOOR_MODEL", "anthropic/claude-sonnet-4")

    from langchain_anthropic import ChatAnthropic

    model = build_chat_model("specialist")
    assert isinstance(model, ChatAnthropic)
    assert _model_of(model) == "claude-sonnet-4"  # provider prefix stripped for native SDK


def test_raises_when_no_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        build_chat_model()
