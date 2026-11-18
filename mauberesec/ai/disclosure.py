"""Cloud data disclosure shown before any model request."""

from __future__ import annotations

DISCLOSURE_TEXT = """\
Cloud AI disclosure:
  MaubereSec AI sends the following data to your selected cloud
  provider ({provider}, model {model}): your prompt, selected code
  excerpts, sanitized scanner output, and finding summaries.
  Secrets are redacted before submission. Complete repositories or
  APK contents are never sent by default. Provider retention and data
  handling are governed by the provider's terms — do not submit data
  you cannot share with {provider}.
"""


def disclosure_text(provider: str, model: str) -> str:
    return DISCLOSURE_TEXT.format(provider=provider, model=model)
