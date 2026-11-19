"""Application settings via pydantic-settings.

Provider and model selection is explicit; there is never a silent
fallback to another provider. API keys come from the environment only.

Convenience default: when an API key is present but provider/model are
not set, the single supported provider and its default model are used.
This makes "export the key and go" work without hiding which provider
is being called — the resolved values are always shown by ``config show``
and ``doctor``.
"""

from __future__ import annotations

import os

from pydantic import BaseModel, Field, field_validator

SUPPORTED_PROVIDERS = ("openai",)
DEFAULT_PROVIDER = "openai"
DEFAULT_MODEL = "gpt-4o-mini"

ENV_PROVIDER = "MSAI_PROVIDER"
ENV_MODEL = "MSAI_MODEL"
ENV_TIMEOUT = "MSAI_TIMEOUT"
ENV_LOG_JSON = "MSAI_LOG_JSON"


class SettingsError(Exception):
    """Raised for invalid or incomplete configuration."""


class CloudSettings(BaseModel):
    """Cloud model configuration resolved from environment variables."""

    provider: str | None = None
    model: str | None = None
    api_key: str | None = Field(default=None, repr=False)
    timeout_seconds: float = 30.0

    @field_validator("provider")
    @classmethod
    def _validate_provider(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        value = value.strip().lower()
        if value not in SUPPORTED_PROVIDERS:
            raise SettingsError(
                f"Unsupported provider '{value}'. Supported: {', '.join(SUPPORTED_PROVIDERS)}."
            )
        return value

    @property
    def is_configured(self) -> bool:
        return bool(self.provider and self.model and self.api_key)


def load_settings(env: dict[str, str] | None = None) -> CloudSettings:
    """Resolve settings from *env* (defaults to ``os.environ``)..

    Raises SettingsError for unsupported provider names so misconfiguration
    is loud rather than silently ignored.
    """
    env_map: dict[str, str] = dict(os.environ) if env is None else dict(env)
    timeout_raw = env_map.get(ENV_TIMEOUT, "").strip()
    timeout = float(timeout_raw) if timeout_raw else 30.0
    if timeout <= 0:
        raise SettingsError(f"{ENV_TIMEOUT} must be a positive number of seconds.")

    provider = env_map.get(ENV_PROVIDER) or None
    model = env_map.get(ENV_MODEL) or None
    api_key = env_map.get("OPENAI_API_KEY") or None

    # Key-only setup: the key is the only required input. Fill in the
    # single supported provider and its default model, never a different
    # provider. Without a key nothing is defaulted and the CLI stays
    # unconfigured so misconfiguration remains loud.
    if api_key:
        provider = provider or DEFAULT_PROVIDER
        model = model or DEFAULT_MODEL

    return CloudSettings(
        provider=provider,
        model=model,
        api_key=api_key,
        timeout_seconds=timeout,
    )


def provider_api_key_env(provider: str) -> str:
    """Environment variable name holding the API key for *provider*."""
    return f"{provider.upper()}_API_KEY"


def sys_platform() -> str:
    import sys

    return sys.platform
