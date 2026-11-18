"""Integration tests for the passive HTTP checker against a mocked server."""

import httpx
import pytest
import respx

from mauberesec.scope.urlcheck import DestinationError
from mauberesec.tools.website.passive import (
    Budget,
    BudgetExhaustedError,
    PassiveHttpChecker,
)

pytestmark = pytest.mark.integration

HOST = "example.com"


def checker(**budget_kwargs) -> PassiveHttpChecker:
    return PassiveHttpChecker(budget=Budget(min_interval_seconds=0.0, **budget_kwargs))


@respx.mock
def test_fetch_collects_headers_and_cookies():
    respx.get(f"https://{HOST}/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Set-Cookie": "sid=abc; Path=/; Secure; HttpOnly; SameSite=Strict",
            },
            json={"ok": True},
        )
    )
    with checker() as c:
        evidence, findings = c.check(f"https://{HOST}/")
    assert evidence.status_code == 200
    titles = [f.title for f in findings]
    # HSTS present -> not flagged; other headers missing -> flagged.
    assert not any("Strict-Transport-Security" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)
    # Cookie fully hardened -> not flagged.
    assert not any("Cookie" in t for t in titles)


@respx.mock
def test_weak_cookie_flagged():
    respx.get(f"https://{HOST}/").mock(
        return_value=httpx.Response(
            200,
            headers=[
                ("Set-Cookie", "session=xyz; Path=/"),
                ("Strict-Transport-Security", "max-age=1"),
                ("Content-Security-Policy", "default-src 'self'"),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Referrer-Policy", "no-referrer"),
            ],
        )
    )
    with checker() as c:
        _, findings = c.check(f"https://{HOST}/")
    cookie_findings = [f for f in findings if "Cookie" in f.title]
    assert len(cookie_findings) == 1
    assert "Secure" in cookie_findings[0].title


@respx.mock
def test_redirect_followed_and_revalidated():
    route = respx.get(f"https://{HOST}/old").mock(
        return_value=httpx.Response(302, headers={"Location": f"https://{HOST}/new"})
    )
    respx.get(f"https://{HOST}/new").mock(return_value=httpx.Response(200))
    with checker() as c:
        evidence = c.fetch(f"https://{HOST}/old")
    assert len(evidence.redirect_chain) == 2
    assert route.called


@respx.mock
def test_redirect_to_private_ip_blocked():
    from mauberesec.scope.urlcheck import validate_live_destination

    respx.get(f"https://{HOST}/hop").mock(
        return_value=httpx.Response(302, headers={"Location": "http://10.0.0.5/admin"})
    )
    with PassiveHttpChecker(
        budget=Budget(min_interval_seconds=0.0),
        validate_destination=validate_live_destination,
    ) as c:
        with pytest.raises(DestinationError, match="forbidden address"):
            c.fetch(f"https://{HOST}/hop")


@respx.mock
def test_relative_redirect_resolved():
    respx.get(f"https://{HOST}/a/page").mock(
        return_value=httpx.Response(301, headers={"Location": "other"})
    )
    respx.get(f"https://{HOST}/a/other").mock(return_value=httpx.Response(200))
    with checker() as c:
        evidence = c.fetch(f"https://{HOST}/a/page")
    assert evidence.status_code == 200


@respx.mock
def test_redirect_limit_stops():
    respx.route().mock(
        return_value=httpx.Response(302, headers={"Location": f"https://{HOST}/loop"})
    )
    with checker(max_redirects=2) as c:
        evidence = c.fetch(f"https://{HOST}/start")
    assert any("Redirect limit" in n for n in evidence.notes)


@respx.mock
def test_request_budget_enforced():
    respx.get(f"https://{HOST}/a").mock(
        return_value=httpx.Response(302, headers={"Location": f"https://{HOST}/b"})
    )
    respx.get(f"https://{HOST}/b").mock(
        return_value=httpx.Response(302, headers={"Location": f"https://{HOST}/a"})
    )
    with checker(max_requests=2) as c:
        with pytest.raises(BudgetExhaustedError, match="Request budget"):
            c.fetch(f"https://{HOST}/a")


@respx.mock
def test_response_size_cap_enforced():
    respx.get(f"https://{HOST}/").mock(
        return_value=httpx.Response(200, content=b"x" * (512 * 1024 + 10))
    )
    with checker(max_response_bytes=1024) as c:
        with pytest.raises(BudgetExhaustedError, match="size cap"):
            c.fetch(f"https://{HOST}/")


@respx.mock
def test_validator_applied_to_initial_url():
    respx.get("https://10.0.0.5/").mock(return_value=httpx.Response(200))
    from mauberesec.scope.urlcheck import validate_live_destination

    with PassiveHttpChecker(
        budget=Budget(min_interval_seconds=0.0),
        validate_destination=validate_live_destination,
    ) as c:
        with pytest.raises(DestinationError):
            c.fetch("https://10.0.0.5/")
