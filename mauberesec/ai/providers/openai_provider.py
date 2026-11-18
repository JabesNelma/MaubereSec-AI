"""OpenAI cloud provider adapter (REST via httpx, no vendor SDK).

Deliberately thin and auditable. Enforces timeout and output limits.
Never logs the API key.
"""

from __future__ import annotations

import httpx

from ..base import (
    AuthenticationError,
    CompletionResult,
    ModelInfo,
    ProviderError,
    RateLimitError,
)

API_BASE = "https://api.openai.com/v1"
MAX_HTTP_RETRIES = 2


class OpenAIProvider:
    name = "openai"

    def __init__(self, api_key: str, model: str, timeout: float = 30.0) -> None:
        if not api_key:
            raise AuthenticationError("OPENAI_API_KEY is not set.")
        if not model:
            raise ProviderError("MSAI_MODEL is not set.")
        self._api_key = api_key
        self.model = model
        self._client = httpx.Client(
            base_url=API_BASE,
            timeout=timeout,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )

    def close(self) -> None:
        self._client.close()

    # -- internals ---------------------------------------------------------

    def _request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        try:
            response = self._client.request(method, path, **kwargs)  # type: ignore[arg-type]
        except httpx.TimeoutException as exc:
            raise ProviderError(f"Request to {self.name} timed out.") from exc
        except httpx.HTTPError as exc:
            raise ProviderError(f"Cannot reach {self.name}: {exc}") from exc

        if response.status_code in (401, 403):
            raise AuthenticationError(
                f"{self.name} rejected the credentials (HTTP {response.status_code})."
            )
        if response.status_code == 429:
            raise RateLimitError(f"{self.name} rate limit reached (HTTP 429).")
        if response.status_code >= 400:
            body = response.text[:300]
            raise ProviderError(f"{self.name} returned HTTP {response.status_code}: {body}")
        return response

    # -- ModelProvider protocol ---------------------------------------------

    def list_models(self) -> list[ModelInfo]:
        data = self._request("GET", "/models").json()
        models = [
            ModelInfo(
                provider=self.name,
                model_id=item.get("id", ""),
                owned_by=item.get("owned_by"),
            )
            for item in data.get("data", [])
        ]
        return sorted(models, key=lambda m: m.model_id)

    def health_check(self) -> ModelInfo:
        # Connectivity + credential check: cheap authenticated endpoint.
        models = self.list_models()
        matching = [m for m in models if m.model_id == self.model]
        if not matching:
            available = ", ".join(m.model_id for m in models[:25])
            raise ProviderError(
                f"Model '{self.model}' was not found in the {self.name} model list. "
                f"Sample of available models: {available}"
            )
        return matching[0]

    def complete(self, prompt: str, *, max_output_tokens: int = 512) -> CompletionResult:
        response = self._request(
            "POST",
            "/chat/completions",
            json={
                "model": self.model,
                "max_completion_tokens": max_output_tokens,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        data = response.json()
        choices = data.get("choices") or [{}]
        text = (choices[0].get("message") or {}).get("content") or ""
        return CompletionResult(text=text, model=self.model, provider=self.name)
