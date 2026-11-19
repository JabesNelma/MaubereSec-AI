"""Verification engine (v0.11, PRD REP-003/REP-007).

The single hard rule: **no LLM-only claim can ever become confirmed.**
Promotion requires deterministic, tool- or human-backed evidence with a
reproducible locator. Everything else lands in needs-review.

Statuses (from records.VerificationStatus):
- CONFIRMED          evidence from a tool/human AND a reproducible locator
- NEEDS_REVIEW       insufficient or ambiguous evidence (default for LLM)
- FALSE_POSITIVE     explicitly refuted by deterministic evidence
- NOT_REPRODUCIBLE   evidence exists but could not be reproduced
- UNVERIFIED         no verification attempt made yet
"""

from __future__ import annotations

from dataclasses import dataclass

from ..records import VerificationStatus
from .schema import EvidenceItem, FindingSource, FindingV1


class VerificationError(Exception):
    """The verification request is invalid."""


@dataclass(frozen=True)
class VerificationVerdict:
    status: VerificationStatus
    reason: str
    reproduced: bool = False


def verify_finding(
    finding: FindingV1,
    *,
    reproduced: bool | None = None,
    refuted: bool = False,
    refutation_evidence: list[EvidenceItem] | None = None,
) -> VerificationVerdict:
    """Compute the verification verdict for *finding*.

    ``reproduced``/``refuted`` come from deterministic re-execution of the
    check (or a human reviewer), never from model output.
    """
    if refuted:
        if not refutation_evidence:
            raise VerificationError(
                "Refutation requires deterministic evidence (refutation_evidence)."
            )
        return VerificationVerdict(
            VerificationStatus.FALSE_POSITIVE,
            "Refuted by deterministic evidence.",
            reproduced=False,
        )

    has_deterministic_evidence = any(item.locator for item in finding.evidence)
    tool_backed = finding.source in (FindingSource.TOOL, FindingSource.HUMAN)

    if finding.source == FindingSource.LLM and tool_backed is False:
        # An LLM claim, even with quoted text, cannot self-confirm.
        return VerificationVerdict(
            VerificationStatus.NEEDS_REVIEW,
            "LLM-only claim: confirmation requires independent tool/human evidence.",
        )

    if reproduced is True and tool_backed and has_deterministic_evidence:
        return VerificationVerdict(
            VerificationStatus.CONFIRMED,
            "Reproduced with deterministic tool/human evidence.",
            reproduced=True,
        )
    if reproduced is False and tool_backed:
        return VerificationVerdict(
            VerificationStatus.NOT_REPRODUCIBLE,
            "Evidence present but the check did not reproduce.",
        )
    if not has_deterministic_evidence:
        return VerificationVerdict(
            VerificationStatus.NEEDS_REVIEW,
            "No reproducible locator in evidence.",
        )
    return VerificationVerdict(
        VerificationStatus.NEEDS_REVIEW,
        "Deterministic evidence present but no reproduction attempt yet.",
    )


def apply_verdict(finding: FindingV1, verdict: VerificationVerdict) -> FindingV1:
    return finding.model_copy(update={"verification": verdict.status})


def is_confirmable(finding: FindingV1) -> bool:
    """True when the finding *could* be confirmed: tool-backed + located."""
    return finding.source in (FindingSource.TOOL, FindingSource.HUMAN) and bool(finding.evidence)
