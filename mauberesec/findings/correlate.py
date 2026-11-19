"""Evidence correlation and deduplication across tools (v0.11, REP-002/REP-004).

Two findings correlate when they share a normalized key: same title
signature and same primary locator. Correlated findings merge into a single
reportable finding whose evidence list contains every contributor — so
reports show one issue with multiple proofs instead of duplicates.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from ..records import Confidence
from .schema import EvidenceItem, FindingV1

_WS = re.compile(r"\s+")


def _title_signature(title: str) -> str:
    text = _WS.sub(" ", title.strip().lower())
    # Strip volatile identifiers (hashes, CVE/GHSA ids) before comparing.
    text = re.sub(r"\b(ghsa|CVE)-[\w-]+", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\b[0-9a-f]{8,}\b", "", text)
    return _WS.sub(" ", text).strip(" :-")


def _primary_locator(finding: FindingV1) -> str:
    if not finding.evidence:
        return ""
    first = finding.evidence[0]
    return f"{first.kind}:{first.locator}"


def correlation_key(finding: FindingV1) -> str:
    return f"{_title_signature(finding.title)}|{_primary_locator(finding)}"


def correlate(findings: Iterable[FindingV1]) -> list[FindingV1]:
    """Merge duplicate/correlated findings deterministically (order-stable)."""
    merged: dict[str, FindingV1] = {}
    order: list[str] = []
    for finding in findings:
        key = correlation_key(finding)
        if key not in merged:
            merged[key] = finding
            order.append(key)
            continue
        existing = merged[key]
        merged[key] = _merge(existing, finding)
    return [merged[key] for key in order]


def _merge(primary: FindingV1, duplicate: FindingV1) -> FindingV1:
    evidence: list[EvidenceItem] = list(primary.evidence)
    seen = {(e.kind, e.locator) for e in evidence}
    for item in duplicate.evidence:
        if (item.kind, item.locator) not in seen:
            evidence.append(item)
            seen.add((item.kind, item.locator))

    # Highest severity and confidence win: more conservative reporting.
    severity = max((primary.severity, duplicate.severity), key=_severity_rank)
    confidence = max((primary.confidence, duplicate.confidence), key=_confidence_rank)
    tools = {t for t in (primary.tool_name, duplicate.tool_name) if t}

    return primary.model_copy(
        update={
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence,
            "tool_name": ", ".join(sorted(tools)) or primary.tool_name,
        }
    )


_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


def _severity_rank(value: Any) -> int:
    return _SEVERITY_ORDER.get(str(getattr(value, "value", value)), 0)


def _confidence_rank(value: Any) -> int:
    return _CONFIDENCE_ORDER.get(str(getattr(value, "value", value)), 0)


def confidence_from_sources(count: int) -> Confidence:
    """More independent contributors ⇒ higher confidence (deterministic rule)."""
    if count >= 3:
        return Confidence.HIGH
    if count == 2:
        return Confidence.MEDIUM
    return Confidence.LOW
