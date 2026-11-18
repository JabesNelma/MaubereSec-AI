"""Core record schemas: mode, scope, authorization, budgets, findings, audit.

All persistence and policy decisions flow through these typed models.
Timestamps are UTC ISO-8601 strings. No secrets may appear in any record.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


# --- Modes and targets -------------------------------------------------------


class Mode(StrEnum):
    LOCAL_LAB = "local_lab"
    LIVE_WHITE_HAT = "live_white_hat"
    LOCAL_FILE = "local_file"


class TargetKind(StrEnum):
    WEBSITE = "website"
    REPO = "repo"
    APK = "apk"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class VerificationStatus(StrEnum):
    UNVERIFIED = "unverified"
    NEEDS_REVIEW = "needs_review"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    NOT_REPRODUCIBLE = "not_reproducible"


# --- Scope --------------------------------------------------------------------


class ScopeTarget(BaseModel):
    """One exact target entry inside an assessment scope."""

    model_config = ConfigDict(frozen=True)

    kind: TargetKind
    value: str = Field(min_length=1)
    allowed_ports: frozenset[int] = frozenset()
    allowed_paths: frozenset[str] = frozenset()
    allowed_methods: frozenset[str] = frozenset()

    @field_validator("value")
    @classmethod
    def _no_whitespace(cls, v: str) -> str:
        if any(ch.isspace() for ch in v):
            raise ValueError("scope target value must not contain whitespace")
        return v


class Scope(BaseModel):
    """Exact, explicit assessment scope. Comparison is by hash."""

    model_config = ConfigDict(frozen=True)

    mode: Mode
    targets: tuple[ScopeTarget, ...] = Field(min_length=1)

    def sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude_none=True)
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def contains(self, kind: TargetKind, value: str) -> bool:
        return any(t.kind == kind and t.value == value for t in self.targets)


class AuthorizationRecord(BaseModel):
    """User-supplied written authorization for a live assessment."""

    model_config = ConfigDict(frozen=True)

    reference: str = Field(min_length=1, description="Ticket/contract/doc reference")
    scope_sha256: str = Field(min_length=64, max_length=64)
    authorized_by: str = Field(min_length=1)
    valid_until: datetime
    contact: str | None = None

    def is_valid_at(self, when: datetime | None = None) -> bool:
        when = when or utc_now()
        return when <= self.valid_until


def default_valid_until(days: int = 7) -> datetime:
    return utc_now() + timedelta(days=days)


# --- Budgets ------------------------------------------------------------------


class ResourceBudget(BaseModel):
    """Hard execution budgets. Exhaustion must stop a run."""

    model_config = ConfigDict(frozen=True)

    max_steps: int = Field(default=25, ge=1)
    max_requests: int = Field(default=100, ge=1)
    max_runtime_seconds: int = Field(default=900, ge=1)
    max_concurrency: int = Field(default=4, ge=1)
    max_output_bytes: int = Field(default=10 * 1024 * 1024, ge=1)
    max_model_tokens: int = Field(default=200_000, ge=1)


LIVE_BUDGET = ResourceBudget(
    max_steps=15,
    max_requests=50,
    max_runtime_seconds=600,
    max_concurrency=2,
)
LAB_BUDGET = ResourceBudget()


# --- Records -------------------------------------------------------------------


class AssessmentRecord(BaseModel):
    id: str = Field(default_factory=lambda: new_id("asm"))
    mode: Mode
    scope: Scope
    status: str = "created"  # created|running|completed|failed|cancelled
    created_at: datetime = Field(default_factory=utc_now)
    authorization_reference: str | None = None
    budget: ResourceBudget = Field(default_factory=ResourceBudget)


class ToolRunRecord(BaseModel):
    id: str = Field(default_factory=lambda: new_id("run"))
    assessment_id: str
    tool_name: str
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    exit_code: int | None = None
    redacted_summary: str | None = None


class FindingRecord(BaseModel):
    id: str = Field(default_factory=lambda: new_id("fnd"))
    assessment_id: str
    title: str = Field(min_length=1)
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.LOW
    verification: VerificationStatus = VerificationStatus.UNVERIFIED
    evidence: str = ""
    remediation: str = ""
    tool_name: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class AuditEventRecord(BaseModel):
    id: str = Field(default_factory=lambda: new_id("evt"))
    assessment_id: str | None = None
    timestamp: datetime = Field(default_factory=utc_now)
    category: str = Field(min_length=1)
    decision: str = Field(min_length=1)  # allow|deny|info|error
    details: str = ""

    @field_validator("details")
    @classmethod
    def _details_not_secret_heavy(cls, v: str) -> str:
        # Defense in depth: records must not carry obvious secrets.
        from .redaction import redact

        return redact(v)
