"""Versioned finding schema (v0.11, PRD REP-001..REP-004).

Separations that matter:
- severity (impact) vs confidence (believability) are independent fields;
- verification status is driven by *deterministic evidence*, never by an LLM
  claim: findings carry an explicit `source` and an `evidence` list, and
  promotion to CONFIRMED requires tool-backed evidence;
- every finding must carry remediation text to be report-ready.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..records import Confidence, Severity, VerificationStatus

FINDING_SCHEMA_VERSION = "1.0"


class FindingSource(StrEnum):
    TOOL = "tool"
    LLM = "llm"
    HUMAN = "human"


class EvidenceItem(BaseModel):
    """One reproducible artifact or observation backing a finding."""

    model_config = ConfigDict(frozen=True)

    kind: str = Field(min_length=1, max_length=60)  # e.g. file-line, http, artifact
    locator: str = Field(min_length=1, max_length=1000)
    detail: str = Field(default="", max_length=2000)


class FindingV1(BaseModel):
    """The reportable finding record."""

    schema_version: str = FINDING_SCHEMA_VERSION
    id: str = Field(min_length=1, max_length=80)
    run_id: str = Field(default="", max_length=80)
    title: str = Field(min_length=1, max_length=300)
    severity: Severity
    confidence: Confidence
    verification: VerificationStatus = VerificationStatus.UNVERIFIED
    source: FindingSource = FindingSource.TOOL
    tool_name: str | None = None
    evidence: list[EvidenceItem] = Field(default_factory=list, max_length=50)
    impact: str = Field(default="", max_length=2000)
    remediation: str = ""
    cwe: list[str] = Field(default_factory=list, max_length=20)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("remediation")
    @classmethod
    def _remediation_required_for_report(cls, v: str) -> str:
        # Not enforced here (partial findings exist), but report generation
        # marks missing remediation explicitly. Kept as a string for fidelity.
        return v

    @property
    def report_ready(self) -> bool:
        return bool(self.evidence) and bool(self.remediation.strip())

    def evidence_locators(self) -> list[str]:
        return [f"{item.kind}:{item.locator}" for item in self.evidence]
