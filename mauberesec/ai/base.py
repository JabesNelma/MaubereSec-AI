"""Provider-neutral model interface.

Every cloud provider adapter implements this protocol. The rest of the
application only depends on this interface, never on provider SDKs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


class ProviderError(Exception):
    """Base error for provider failures."""


class AuthenticationError(ProviderError):
    """Credentials were missing, invalid, or expired."""


class RateLimitError(ProviderError):
    """Provider throttled the request."""


@dataclass(frozen=True)
class ModelInfo:
    provider: str
    model_id: str
    owned_by: str | None = None


@dataclass(frozen=True)
class CompletionResult:
    text: str
    model: str
    provider: str


@runtime_checkable
class ModelProvider(Protocol):
    """Minimal contract implemented by every cloud provider adapter."""

    name: str

    def list_models(self) -> list[ModelInfo]:
        """Return the models currently offered by the provider."""
        ...

    def health_check(self) -> ModelInfo:
        """Verify credentials and connectivity for the selected model.

        Raises AuthenticationError on missing/invalid credentials and
        ProviderError on connectivity or unexpected failures.
        """
        ...

    def complete(self, prompt: str, *, max_output_tokens: int = 512) -> CompletionResult:
        """Run a single completion. Input must already be redacted."""
        ...
