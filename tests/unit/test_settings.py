"""Unit tests for settings resolution and provider selection."""

import pytest

from mauberesec.ai.manager import build_provider
from mauberesec.ai.providers.openai_provider import OpenAIProvider
from mauberesec.config.settings import (
    SettingsError,
    load_settings,
)


def test_empty_env_yields_unconfigured():
    settings = load_settings(env={})
    assert settings.is_configured is False
    assert settings.provider is None


def test_full_env_configures():
    settings = load_settings(
        env={"MSAI_PROVIDER": "openai", "MSAI_MODEL": "gpt-x", "OPENAI_API_KEY": "sk-test"}
    )
    assert settings.is_configured is True


def test_unsupported_provider_rejected():
    with pytest.raises(SettingsError, match="Unsupported provider"):
        load_settings(env={"MSAI_PROVIDER": "ollama"})


def test_missing_key_fails_without_fallback():
    settings = load_settings(env={"MSAI_PROVIDER": "openai", "MSAI_MODEL": "gpt-x"})
    with pytest.raises(Exception, match="API key missing"):
        build_provider(settings)


def test_key_only_defaults_provider_and_model():
    settings = load_settings(env={"OPENAI_API_KEY": "sk-test"})
    assert settings.provider == "openai"
    assert settings.model == "gpt-4o-mini"
    assert settings.is_configured is True
    provider = build_provider(settings)
    assert isinstance(provider, OpenAIProvider)


def test_key_only_honours_explicit_model():
    settings = load_settings(env={"OPENAI_API_KEY": "sk-test", "MSAI_MODEL": "gpt-x"})
    assert settings.provider == "openai"
    assert settings.model == "gpt-x"


def test_no_key_does_not_default_anything():
    settings = load_settings(env={"MSAI_PROVIDER": "openai", "MSAI_MODEL": "gpt-x"})
    assert settings.provider == "openai"
    assert settings.model == "gpt-x"
    assert settings.api_key is None
    with pytest.raises(Exception, match="API key missing"):
        build_provider(settings)


def test_provider_case_normalized():
    settings = load_settings(env={"MSAI_PROVIDER": " OpenAI "})
    assert settings.provider == "openai"


def test_build_provider_returns_openai_adapter():
    settings = load_settings(
        env={"MSAI_PROVIDER": "openai", "MSAI_MODEL": "gpt-x", "OPENAI_API_KEY": "sk-test"}
    )
    provider = build_provider(settings)
    assert isinstance(provider, OpenAIProvider)
    assert provider.name == "openai"
