"""Unit tests for secret redaction."""

from mauberesec.redaction import contains_secret, redact


def test_openai_key_redacted():
    text = "using key sk-proj-AbCdEfGh1234567890IjKlMnOp for the call"
    out = redact(text)
    assert "sk-proj-" not in out
    assert "[REDACTED:openai-key]" in out


def test_bearer_token_redacted():
    out = redact("Authorization: bearer abc123def456ghi789jkl")
    assert "abc123def456ghi789jkl" not in out


def test_jwt_redacted():
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
    )
    out = redact(f"token={jwt}")
    assert "eyJhbGci" not in out


def test_private_key_block_redacted():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234\n-----END RSA PRIVATE KEY-----"
    out = redact(text)
    assert "MIIEowIBAAKCAQEA1234" not in out
    assert "[REDACTED:private-key-block]" in out


def test_generic_key_value_redacted():
    out = redact("password = 'supersecret123'")
    assert "supersecret123" not in out
    assert "password=[REDACTED" in out


def test_plain_text_untouched():
    text = "The scan found 3 findings on https://example.com/path"
    assert redact(text) == text


def test_contains_secret():
    assert contains_secret("api_key=abcdefgh1234")
    assert not contains_secret("nothing suspicious here")
