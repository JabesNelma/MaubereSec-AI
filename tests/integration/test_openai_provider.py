"""Integration tests for the OpenAI provider against a mocked API."""

import httpx
import pytest
import respx

from mauberesec.ai.base import AuthenticationError, ProviderError
from mauberesec.ai.providers.openai_provider import OpenAIProvider

BASE = "https://api.openai.com/v1"


def make_provider() -> OpenAIProvider:
    return OpenAIProvider(api_key="sk-test-key", model="gpt-test", timeout=5.0)


@respx.mock
def test_list_models_success():
    respx.get(f"{BASE}/models").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"id": "gpt-a", "owned_by": "openai"}, {"id": "gpt-b"}]},
        )
    )
    models = make_provider().list_models()
    assert [m.model_id for m in models] == ["gpt-a", "gpt-b"]


@respx.mock
def test_health_check_unknown_model_raises():
    respx.get(f"{BASE}/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "gpt-a"}]})
    )
    with pytest.raises(ProviderError, match="was not found"):
        make_provider().health_check()


@respx.mock
def test_health_check_matching_model():
    respx.get(f"{BASE}/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "gpt-test"}]})
    )
    info = make_provider().health_check()
    assert info.model_id == "gpt-test"


@respx.mock
def test_invalid_credentials_raise_authentication_error():
    respx.get(f"{BASE}/models").mock(return_value=httpx.Response(401, json={"error": {}}))
    with pytest.raises(AuthenticationError):
        make_provider().list_models()


@respx.mock
def test_rate_limit_raise():
    respx.get(f"{BASE}/models").mock(return_value=httpx.Response(429, json={}))
    from mauberesec.ai.base import RateLimitError

    with pytest.raises(RateLimitError):
        make_provider().list_models()


@respx.mock
def test_server_error_raise():
    respx.get(f"{BASE}/models").mock(return_value=httpx.Response(500, text="boom"))
    with pytest.raises(ProviderError, match="HTTP 500"):
        make_provider().list_models()


@respx.mock
def test_timeout_raise():
    respx.get(f"{BASE}/models").mock(side_effect=httpx.ConnectTimeout("timeout"))
    with pytest.raises(ProviderError, match=r"timed out|Cannot reach"):
        make_provider().list_models()


@respx.mock
def test_complete_returns_text():
    respx.post(f"{BASE}/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={"choices": [{"message": {"content": "hello"}}]},
        )
    )
    result = make_provider().complete("say hi")
    assert result.text == "hello"
    assert result.provider == "openai"
