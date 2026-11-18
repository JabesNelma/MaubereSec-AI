"""Passive website assessment: HTTP metadata, security headers, cookies.

Conservative by construction:
- GET requests only, no cookies or credentials sent, no form posts.
- Manual redirect following — every hop is revalidated against scope and
  destination rules before the request is made (redirects cannot escape).
- Rate limiting, request-count budget, per-request timeout, and a response
  size cap enforced while streaming.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

from ...records import FindingRecord, Severity
from ...scope.urlcheck import (
    DestinationError,
    NormalizedUrl,
    normalize_url,
)


class BudgetExhaustedError(Exception):
    """The request/time budget for the run is exhausted."""


@dataclass
class Budget:
    max_requests: int = 10
    request_timeout: float = 10.0
    min_interval_seconds: float = 1.0
    max_response_bytes: int = 512 * 1024
    max_redirects: int = 5

    def __post_init__(self) -> None:
        if self.max_requests < 1:
            raise ValueError("max_requests must be >= 1")


@dataclass
class Evidence:
    url: str
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[dict[str, str]] = field(default_factory=list)
    redirect_chain: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"GET {self.url} -> {self.status_code}"]
        for hop in self.redirect_chain:
            lines.append(f"redirect: {hop}")
        for name, value in sorted(self.headers.items()):
            lines.append(f"header {name}: {value[:200]}")
        for cookie in self.cookies:
            lines.append(f"cookie {cookie.get('name', '?')}: {cookie}")
        return "\n".join(lines)


# DestinationValidator: raises DestinationError when the URL is not allowed.
DestinationValidator = Callable[[NormalizedUrl], list[str]]

SECURITY_HEADERS = {
    "strict-transport-security": "Strict-Transport-Security (HSTS)",
    "content-security-policy": "Content-Security-Policy (CSP)",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
}


class PassiveHttpChecker:
    """Fetches and reviews passive HTTP/TLS metadata for one scope entry."""

    def __init__(
        self,
        budget: Budget | None = None,
        validate_destination: DestinationValidator | None = None,
        transport: httpx.Client | None = None,
    ) -> None:
        self.budget = budget or Budget()
        self._validate = validate_destination
        self._requests_used = 0
        self._last_request_at = 0.0
        self._client = transport or httpx.Client(follow_redirects=False)

    @property
    def requests_used(self) -> int:
        return self._requests_used

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> PassiveHttpChecker:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- request plumbing ----------------------------------------------------

    def _reserve_request(self) -> None:
        if self._requests_used >= self.budget.max_requests:
            raise BudgetExhaustedError(f"Request budget exhausted ({self.budget.max_requests}).")
        wait = self.budget.min_interval_seconds - (time.monotonic() - self._last_request_at)
        if wait > 0:
            time.sleep(wait)
        self._requests_used += 1
        self._last_request_at = time.monotonic()

    def _validated(self, url: str) -> NormalizedUrl:
        normalized = normalize_url(url)
        if self._validate is not None:
            self._validate(normalized)
        return normalized

    def _get(self, url: str) -> httpx.Response:
        """GET with validated destination and capped response body."""
        self._validated(url)
        self._reserve_request()
        response = self._client.get(url, timeout=self.budget.request_timeout)
        # Enforce the response size cap by reading at most max+1 bytes.
        content = b""
        for chunk in response.iter_bytes(8192):
            content += chunk
            if len(content) > self.budget.max_response_bytes:
                response.close()
                raise BudgetExhaustedError(
                    f"Response exceeds the size cap ({self.budget.max_response_bytes} bytes)."
                )
            if len(content) >= self.budget.max_response_bytes:
                break
        return response

    def fetch(self, url: str) -> Evidence:
        """Fetch *url*, following redirects with per-hop revalidation."""
        evidence = Evidence(url=str(self._validated(url)))
        current = url
        for _ in range(self.budget.max_redirects + 1):
            response = self._get(current)
            evidence.redirect_chain.append(current)
            evidence.status_code = response.status_code
            evidence.headers = {k.lower(): v for k, v in response.headers.items()}
            evidence.cookies = _extract_cookies(response)
            if response.is_redirect:
                location = response.headers.get("location", "")
                if not location:
                    break
                current = str(_join_redirect(current, location))
                # Revalidate before following; raises on escape.
                self._validated(current)
                continue
            break
        else:
            evidence.notes.append("Redirect limit reached; stopped following.")
        return evidence

    # -- passive checks ---------------------------------------------------------

    def check(self, url: str) -> tuple[Evidence, list[FindingRecord]]:
        """Fetch and run passive security checks; returns evidence + findings."""
        evidence = self.fetch(url)
        findings: list[FindingRecord] = []
        tool = "passive.http_headers"

        for header, label in SECURITY_HEADERS.items():
            if header not in evidence.headers:
                findings.append(
                    FindingRecord(
                        title=f"Missing security header: {label}",
                        severity=Severity.LOW,
                        evidence=f"No {header} header on GET {evidence.url} "
                        f"(status {evidence.status_code}).",
                        remediation=f"Add the {label} header with an appropriate policy.",
                        tool_name=tool,
                    )
                )

        for cookie in evidence.cookies:
            missing = []
            if cookie.get("secure") != "true":
                missing.append("Secure")
            if cookie.get("httponly") != "true":
                missing.append("HttpOnly")
            if not cookie.get("samesite"):
                missing.append("SameSite")
            if missing:
                findings.append(
                    FindingRecord(
                        title=(f"Cookie '{cookie.get('name', '?')}' missing: {', '.join(missing)}"),
                        severity=Severity.MEDIUM,
                        evidence=f"Set-Cookie attributes on GET {evidence.url}: "
                        f"{ {k: v for k, v in cookie.items() if k != 'value'} }",
                        remediation="Set Secure, HttpOnly, and SameSite on all cookies.",
                        tool_name=tool,
                    )
                )

        if evidence.status_code is not None and evidence.status_code >= 400:
            evidence.notes.append(f"Target responded with HTTP {evidence.status_code}.")

        return evidence, findings


def _extract_cookies(response: httpx.Response) -> list[dict[str, str]]:
    """Parse Set-Cookie headers into attribute dicts (values are not kept)."""
    from http.cookies import SimpleCookie

    cookies: list[dict[str, str]] = []
    for raw in response.headers.get_list("set-cookie"):
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:  # malformed cookie: record the fact, not the value
            cookies.append({"name": "<malformed>", "parse": "failed"})
            continue
        for name, morsel in jar.items():
            cookies.append(
                {
                    "name": name,
                    "path": morsel["path"],
                    "secure": str(bool(morsel["secure"])).lower(),
                    "httponly": str(bool(morsel["httponly"])).lower(),
                    "samesite": morsel["samesite"] or "",
                }
            )
    return cookies


def _join_redirect(base_url: str, location: str) -> str:
    parts = urlsplit(location)
    if parts.scheme:
        if parts.scheme.lower() not in ("http", "https"):
            raise DestinationError(f"Redirect to non-HTTP scheme '{parts.scheme}'.")
        return location
    base = urlsplit(base_url)
    scheme = base.scheme
    netloc = base.netloc
    if location.startswith("//"):
        return f"{scheme}:{location}"
    if location.startswith("/"):
        return f"{scheme}://{netloc}{location}"
    # Relative path: merge with the base path directory.
    dir_path = base.path.rsplit("/", 1)[0] or ""
    return f"{scheme}://{netloc}{dir_path}/{location}"
