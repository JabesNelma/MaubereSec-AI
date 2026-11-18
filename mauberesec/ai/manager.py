"""Provider manager: resolves exactly one provider from settings.

There is never a silent fallback: if the configured provider fails, the
error surfaces to the user.
"""

from __future__ import annotations

from ..config.settings import CloudSettings, SettingsError
from .base import AuthenticationError, ModelProvider, ProviderError
from .providers.openai_provider import OpenAIProvider

_PROVIDERS: dict[str, type] = {
    "openai": OpenAIProvider,
}


class NotConfiguredError(ProviderError):
    """Cloud provider/model/key selection is incomplete."""


def build_provider(settings: CloudSettings) -> ModelProvider:
    """Construct the single configured provider or raise a clear error."""
    if not settings.provider:
        raise NotConfiguredError(
            "No cloud provider configured. Set MSAI_PROVIDER (supported: openai)."
        )
    if not settings.model:
        raise NotConfiguredError(
            "No model configured. Set MSAI_MODEL to a model ID from 'mauberesec models list'."
        )
    if not settings.api_key:
        raise AuthenticationError("API key missing. Set OPENAI_API_KEY in the environment.")
    try:
        cls = _PROVIDERS[settings.provider]
    except KeyError as exc:  # pragma: no cover - guarded by Settings validation
        raise SettingsError(f"Unsupported provider '{settings.provider}'.") from exc
    provider: ModelProvider = cls(
        api_key=settings.api_key,
        model=settings.model,
        timeout=settings.timeout_seconds,
    )
    return provider


def configured_provider_summary(settings: CloudSettings) -> str:
    if not settings.provider:
        return "not set"
    return settings.provider
