"""Secret redaction utilities.

Applied to all log output and to any text submitted to cloud model
providers. Secrets must never appear in logs, reports, or prompts.
"""

from __future__ import annotations

import re

# Ordered (name, pattern, replacement). Longest/most-specific first.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "bearer-token",
        re.compile(r"(?i)bearer\s+[a-z0-9\-._~+/]+=*"),
    ),
    (
        "openai-key",
        re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "anthropic-key",
        re.compile(r"\bsk-ant-(?:api|admin)03-[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "google-api-key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    (
        "aws-access-key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "github-token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ),
    (
        "generic-api-key",
        re.compile(
            r"(?i)\b(api[_-]?key|apikey|token|secret|password|passwd|pwd)"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9/+_.\-]{8,})['\"]?"
        ),
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
    ),
    (
        "private-key-block",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.+?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    ),
]


def redact(text: str) -> str:
    """Return *text* with detected secret values replaced by placeholders.

    The generic key=value rule keeps the key name visible so context stays
    useful while the value is masked.
    """
    for name, pattern in _SECRET_PATTERNS:
        if name == "generic-api-key":
            # Keep the captured key name (group 1) visible, mask the value.
            text = pattern.sub(r"\1=[REDACTED:generic-api-key]", text)
        else:
            text = pattern.sub(f"[REDACTED:{name}]", text)
    return text


def contains_secret(text: str) -> bool:
    """Return True if *text* still contains something that looks like a secret."""
    redacted = redact(text)
    return redacted != text
