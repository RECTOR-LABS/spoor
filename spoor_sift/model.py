"""LLM model factory — provider-agnostic, env-driven.

Default path is OpenRouter (OpenAI-compatible); direct Anthropic is a drop-in
fallback. The provider is chosen from the environment, so it's config, not code.

Call ``load_env()`` once at an entry point to also pick up a repo-local ``.env``
(``os.environ`` always wins, so a shell / ``~/Documents/secret/.env`` key takes
precedence over a committed-by-mistake ``.env``). Secrets never live in the repo.
"""

from __future__ import annotations

import os

DEFAULT_MODEL = "anthropic/claude-sonnet-4"
DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


def load_env() -> None:
    """Load a repo-local .env as a fallback (does not override existing env vars)."""
    from dotenv import load_dotenv

    load_dotenv()


def _model_id(role: str) -> str:
    if role == "lead":
        return (
            os.environ.get("SPOOR_LEAD_MODEL")
            or os.environ.get("SPOOR_MODEL")
            or DEFAULT_MODEL
        )
    return os.environ.get("SPOOR_MODEL") or DEFAULT_MODEL


def build_chat_model(role: str = "specialist", *, temperature: float = 0.0):
    """Build a LangChain chat model for ``role`` ('specialist' | 'lead') from env.

    Order of preference: OpenRouter (``OPENROUTER_API_KEY``) → Anthropic
    (``ANTHROPIC_API_KEY``). Raises if neither is set.
    """
    model_id = _model_id(role)

    if os.environ.get("OPENROUTER_API_KEY"):
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=model_id,
            api_key=os.environ["OPENROUTER_API_KEY"],
            base_url=os.environ.get("OPENROUTER_BASE_URL", DEFAULT_OPENROUTER_BASE_URL),
            temperature=temperature,
        )

    if os.environ.get("ANTHROPIC_API_KEY"):
        from langchain_anthropic import ChatAnthropic

        native = model_id.split("/", 1)[-1]  # strip "anthropic/" for the native SDK
        return ChatAnthropic(
            model=native,
            api_key=os.environ["ANTHROPIC_API_KEY"],
            temperature=temperature,
        )

    raise RuntimeError(
        "No LLM key found. Set OPENROUTER_API_KEY (preferred) or ANTHROPIC_API_KEY "
        "in your shell, ~/Documents/secret/.env, or ./.env"
    )
