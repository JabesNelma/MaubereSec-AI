"""Lab test profiles: safe checks and state-changing checks (v0.8).

Roadmap exclusions enforced by construction: this module only defines
GET-based reconnaissance and a synthetic-credential authentication probe.
No malware, persistence, stealth, DoS, credential theft, or escape logic
exists anywhere in the lab tooling.

Checks:
- safe (read-only, always allowed once the lab is verified):
  service_info, security_headers, common_paths
- state-changing (require explicit per-run confirmation):
  synthetic_login — POSTs SYNTHETIC credentials to common login endpoints
  and reports whether authentication is enforced. It never tries real or
  default credential lists.
"""

from __future__ import annotations

import json

from pydantic import BaseModel, Field

# Fixed synthetic credentials — never real, never default vendor creds.
SYNTHETIC_USERNAME = "msai-synth-user"
SYNTHETIC_PASSWORD = "msai-synth-pass-7c1f"  # noqa: S105 - synthetic, not a real secret

SAFE_CHECKS = ("service_info", "security_headers", "common_paths")
STATE_CHANGING_CHECKS = ("synthetic_login",)
ALL_CHECKS = (*SAFE_CHECKS, *STATE_CHANGING_CHECKS)

COMMON_PATHS = (
    "/robots.txt",
    "/admin",
    "/administrator",
    "/phpmyadmin",
    "/wp-admin",
    "/.git/HEAD",
    "/.env",
    "/backup.zip",
    "/server-status",
)

LOGIN_PATHS = ("/login", "/signin", "/auth", "/wp-login.php", "/user/login")

MAX_PATHS_PER_CHECK = 50


class LabTestProfile(BaseModel):
    """The check set applied to a lab target."""

    lab_name: str = Field(min_length=1)
    base_url: str = Field(min_length=1)
    checks: tuple[str, ...] = Field(default_factory=lambda: tuple(ALL_CHECKS))
    request_timeout: float = Field(default=5.0, gt=0, le=30)
    max_requests: int = Field(default=40, ge=1, le=200)

    def validate_checks(self) -> None:
        unknown = [c for c in self.checks if c not in ALL_CHECKS]
        if unknown:
            raise ValueError(f"Unknown lab checks: {', '.join(unknown)}")

    def safe_checks(self) -> tuple[str, ...]:
        return tuple(c for c in self.checks if c in SAFE_CHECKS)

    def state_changing_checks(self) -> tuple[str, ...]:
        return tuple(c for c in self.checks if c in STATE_CHANGING_CHECKS)


def default_profile(lab_name: str, base_url: str) -> LabTestProfile:
    return LabTestProfile(lab_name=lab_name, base_url=base_url)


def build_probe_payload(profile: LabTestProfile, include_state_changing: bool) -> str:
    """Serialize the fixed check payload handed to the container probe."""
    profile.validate_checks()
    checks = list(profile.safe_checks())
    if include_state_changing:
        checks.extend(profile.state_changing_checks())
    payload = {
        "base_url": profile.base_url,
        "timeout": profile.request_timeout,
        "max_requests": profile.max_requests,
        "checks": checks,
        "common_paths": list(COMMON_PATHS)[:MAX_PATHS_PER_CHECK],
        "login_paths": list(LOGIN_PATHS)[:MAX_PATHS_PER_CHECK],
        # Synthetic-only credentials (roadmap: controlled PoC with synthetic
        # accounts/data). Real credential lists are never used.
        "synthetic_username": SYNTHETIC_USERNAME,
        "synthetic_password": SYNTHETIC_PASSWORD,
    }
    return json.dumps(payload)
