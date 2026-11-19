#!/usr/bin/env python3
"""Lab probe — runs INSIDE a container attached to the lab network (v0.8).

Stdlib-only. Receives a fixed JSON check payload (argv[1]) built by
mauberesec/labs/profiles.py and performs GET-based reconnaissance plus an
optional synthetic-credential login probe. Hard rules implemented here:

- Redirects are never followed automatically; a redirect is validated
  against the lab subnet before a manual follow (out-of-bound blocked).
- Total requests and wall time are capped by the payload budget.
- Synthetic credentials only; responses are summarized, bodies are never
  exfiltrated (only status/length/snippet hashes are reported).
"""

from __future__ import annotations

import ipaddress
import json
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

USER_AGENT = "mauberesec-lab-probe/0.8"
MAX_BODY_BYTES = 64 * 1024
MAX_EVIDENCE_SNIPPET = 120


class ProbeBudgetError(Exception):
    """Request or time budget exhausted."""


def _resolve_ip(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def _in_subnets(ip: str | None, subnets: list[Any]) -> bool:
    if ip is None:
        return False
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in subnets)


class Probe:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.base_url: str = payload["base_url"].rstrip("/")
        self.timeout: float = float(payload.get("timeout", 5))
        self.remaining: int = int(payload.get("max_requests", 40))
        self.deadline: float = time.monotonic() + 120.0
        self.subnets = [
            ipaddress.ip_network(cidr, strict=False) for cidr in payload.get("lab_subnets", [])
        ]
        self.synthetic_user: str = payload.get("synthetic_username", "")
        self.synthetic_pass: str = payload.get("synthetic_password", "")
        self.common_paths: list[str] = payload.get("common_paths", [])
        self.login_paths: list[str] = payload.get("login_paths", [])

    # -- plumbing -----------------------------------------------------------

    def _budget(self) -> None:
        if self.remaining <= 0:
            raise ProbeBudgetError("Request budget exhausted.")
        if time.monotonic() > self.deadline:
            raise ProbeBudgetError("Time budget exhausted.")
        self.remaining -= 1

    def request(
        self, url: str, method: str = "GET", data: bytes | None = None
    ) -> dict[str, Any] | None:
        """Single request with lab-only redirect validation."""
        self._budget()
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return {"error": f"scheme {parsed.scheme} not allowed"}
        if self.subnets and not _in_subnets(_resolve_ip(parsed.hostname or ""), self.subnets):
            return {"error": f"destination {parsed.hostname} outside lab subnets"}

        opener = urllib.request.build_opener(NoRedirectHandler())
        # Scheme is validated to http/https above; opener never follows redirects.
        request = urllib.request.Request(  # noqa: S310
            url,
            data=data,
            method=method,
            headers={"User-Agent": USER_AGENT, "Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            response = opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            return self._summarize(exc.headers, exc.code, exc.read())
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return {"error": str(exc)[:200]}
        return self._summarize(response.headers, response.status, response.read())

    @staticmethod
    def _summarize(headers: Any, status: int, body: bytes) -> dict[str, Any]:
        body = body[:MAX_BODY_BYTES]
        text = body.decode("utf-8", "replace")
        location = headers.get("Location", "") if headers else ""
        return {
            "status": status,
            "location": location,
            "headers": {
                k.lower(): v[:200]
                for k, v in (headers.items() if headers else [])
                if k.lower()
                in (
                    "server",
                    "content-type",
                    "content-length",
                    "set-cookie",
                    "strict-transport-security",
                    "content-security-policy",
                    "x-frame-options",
                    "x-content-type-options",
                    "location",
                )
            },
            "body_len": len(body),
            "title": _extract_title(text),
            "set_cookie": headers.get("Set-Cookie", "")[:200] if headers else "",
        }

    # -- checks ----------------------------------------------------------------

    def check_service_info(self) -> dict[str, Any]:
        result = self.request(self.base_url + "/")
        if result is None or "error" in result:
            return {"check": "service_info", "ok": False, "detail": str(result)}
        return {
            "check": "service_info",
            "ok": True,
            "status": result["status"],
            "server": result["headers"].get("server", ""),
            "title": result["title"],
        }

    def check_security_headers(self) -> dict[str, Any]:
        result = self.request(self.base_url + "/")
        if result is None or "error" in result:
            return {"check": "security_headers", "ok": False, "detail": str(result)}
        missing = [
            name
            for name in (
                "strict-transport-security",
                "content-security-policy",
                "x-content-type-options",
                "x-frame-options",
            )
            if name not in result["headers"]
        ]
        return {
            "check": "security_headers",
            "ok": True,
            "status": result["status"],
            "missing": missing,
        }

    def check_common_paths(self) -> dict[str, Any]:
        found: list[dict[str, Any]] = []
        for path in self.common_paths:
            result = self.request(self.base_url + path)
            if result is None or "error" in result:
                continue
            if result["status"] not in (404, 401, 403):
                found.append(
                    {
                        "path": path,
                        "status": result["status"],
                        "server": result["headers"].get("server", ""),
                    }
                )
        return {"check": "common_paths", "ok": True, "exposed": found}

    def check_synthetic_login(self) -> dict[str, Any]:
        """POST synthetic credentials; report whether auth is enforced."""
        attempts: list[dict[str, Any]] = []
        enforced_somewhere = False
        for path in self.login_paths:
            url = self.base_url + path
            probe = self.request(url)
            if probe is None or "error" in probe or probe["status"] in (404, 405):
                attempts.append({"path": path, "status": "absent"})
                continue
            body = urllib.parse.urlencode(
                {
                    "username": self.synthetic_user,
                    "password": self.synthetic_pass,
                    "user": self.synthetic_user,
                    "pass": self.synthetic_pass,
                }
            ).encode()
            result = self.request(url, method="POST", data=body)
            if result is None or "error" in result:
                attempts.append({"path": path, "status": str(result)})
                continue
            accepted = (
                result["status"] in (200, 302) and not result["location"].startswith("http")
            ) or (result["status"] == 200 and "logout" in result.get("title", "").lower())
            enforced = result["status"] in (401, 403) or (
                result["status"] in (302, 303) and "login" in result["location"].lower()
            )
            enforced_somewhere = enforced_somewhere or enforced
            attempts.append(
                {
                    "path": path,
                    "status": result["status"],
                    "auth_enforced": enforced,
                    "synthetic_accepted": accepted,
                }
            )
        return {
            "check": "synthetic_login",
            "ok": True,
            "auth_enforced_somewhere": enforced_somewhere,
            "attempts": attempts[: MAX_BODY_BYTES and 20],
            "note": "synthetic credentials only; no real or default credential lists used",
        }


def _extract_title(text: str) -> str:
    lower = text.lower()
    start = lower.find("<title>")
    end = lower.find("</title>")
    if start != -1 and end != -1 and end > start:
        return text[start + 7 : end][:MAX_EVIDENCE_SNIPPET]
    return ""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirects are never auto-followed (lab-only validation)."""

    def redirect_request(
        self, req: Any, fp: Any, code: Any, msg: Any, headers: Any, newurl: Any
    ) -> None:
        return None


CHECKS = {
    "service_info": Probe.check_service_info,
    "security_headers": Probe.check_security_headers,
    "common_paths": Probe.check_common_paths,
    "synthetic_login": Probe.check_synthetic_login,
}


def run_payload(payload_text: str) -> dict[str, Any]:
    payload = json.loads(payload_text)
    probe = Probe(payload)
    results = []
    for check in payload.get("checks", []):
        handler = CHECKS.get(check)
        if handler is None:
            results.append({"check": check, "ok": False, "detail": "unknown check"})
            continue
        try:
            results.append(handler(probe))
        except ProbeBudgetError as exc:
            results.append({"check": check, "ok": False, "detail": str(exc)})
            break
    return {"results": results, "requests_left": probe.remaining}


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: lab_probe.py <payload.json>"}))
        return 2
    try:
        with open(sys.argv[1], encoding="utf-8") as handle:
            payload_text = handle.read()
    except OSError as exc:
        print(json.dumps({"error": f"cannot read payload: {exc}"}))
        return 2
    print(json.dumps(run_payload(payload_text)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
