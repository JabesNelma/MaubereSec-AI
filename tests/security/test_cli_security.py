"""Security tests: CLI behavior, secret leakage, no silent fallback."""

from typer.testing import CliRunner

from mauberesec.cli.app import app

runner = CliRunner()

FAKE_KEY = "sk-proj-AbCdEfGh1234567890IjKlMnOpQrsTuv"


def test_help_works():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "doctor" in result.output


def test_version_works():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_config_show_never_prints_api_key(monkeypatch):
    monkeypatch.setenv("MSAI_PROVIDER", "openai")
    monkeypatch.setenv("MSAI_MODEL", "gpt-x")
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)
    result = runner.invoke(app, ["config", "show"])
    assert result.exit_code == 0
    assert FAKE_KEY not in result.stdout
    assert FAKE_KEY not in (result.stderr or "")
    assert "set" in result.stdout


def test_models_test_missing_key_clear_error(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("MSAI_PROVIDER", "openai")
    monkeypatch.setenv("MSAI_MODEL", "gpt-x")
    result = runner.invoke(app, ["models", "test"])
    assert result.exit_code == 2
    assert "missing" in (result.output + (result.stderr or "")).lower()


def test_models_test_without_config_does_not_fallback(monkeypatch):
    for var in ("MSAI_PROVIDER", "MSAI_MODEL", "OPENAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    result = runner.invoke(app, ["models", "test"])
    assert result.exit_code == 2
    # No other provider name may be attempted or mentioned as in-use.
    assert "anthropic" not in (result.output + (result.stderr or "")).lower()


def test_disclosure_shown_for_models_commands(monkeypatch):
    monkeypatch.setenv("MSAI_PROVIDER", "openai")
    monkeypatch.setenv("MSAI_MODEL", "gpt-x")
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)
    # Will fail to reach the network; disclosure must be emitted first.
    result = runner.invoke(app, ["models", "test"])
    combined = result.output + (result.stderr or "")
    assert "Cloud AI disclosure" in combined


def test_doctor_masks_key(monkeypatch):
    monkeypatch.setenv("MSAI_PROVIDER", "openai")
    monkeypatch.setenv("MSAI_MODEL", "gpt-x")
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)
    result = runner.invoke(app, ["doctor"])
    assert FAKE_KEY not in result.stdout
