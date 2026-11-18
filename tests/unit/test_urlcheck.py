"""Unit tests for URL normalization and destination validation."""

import pytest

from mauberesec.scope.urlcheck import (
    DestinationError,
    UrlError,
    normalize_url,
    validate_lab_destination,
    validate_live_destination,
)


def norm(url: str):
    return normalize_url(url)


def test_normalize_basic():
    u = norm("HTTPS://Example.COM/path")
    assert u.scheme == "https"
    assert u.host == "example.com"
    assert u.port == 443
    assert str(u) == "https://example.com/path"


def test_normalize_adds_scheme():
    assert norm("example.com").scheme == "https"


def test_normalize_rejects_bad_scheme():
    with pytest.raises(UrlError, match="not allowed"):
        norm("ftp://example.com")


def test_normalize_rejects_credentials():
    with pytest.raises(UrlError, match="Credentials"):
        norm("https://user:pw@example.com/")


def test_normalize_rejects_query_fragment():
    with pytest.raises(UrlError):
        norm("https://example.com/?x=1")
    with pytest.raises(UrlError):
        norm("https://example.com/#frag")


def test_normalize_rejects_empty_and_huge():
    with pytest.raises(UrlError):
        norm("")
    with pytest.raises(UrlError):
        norm("https://example.com/" + "a" * 3000)


def test_normalize_custom_port():
    u = norm("http://example.com:8080/app")
    assert u.port == 8080
    assert u.host_port == "example.com:8080"


# --- destination validation ------------------------------------------------------


def test_live_rejects_private_ip():
    with pytest.raises(DestinationError, match="forbidden address"):
        validate_live_destination(norm("http://10.0.0.5/"))


def test_live_rejects_loopback():
    with pytest.raises(DestinationError):
        validate_live_destination(norm("http://127.0.0.1/"))


def test_live_rejects_link_local_and_metadata():
    with pytest.raises(DestinationError):
        validate_live_destination(norm("http://169.254.169.254/latest/meta-data/"))
    with pytest.raises(DestinationError, match="metadata"):
        validate_live_destination(norm("http://metadata.google.internal/"))


def test_live_rejects_multicast_reserved():
    with pytest.raises(DestinationError):
        validate_live_destination(norm("http://224.0.0.1/"))
    with pytest.raises(DestinationError):
        validate_live_destination(norm("http://240.0.0.1/"))


def test_live_accepts_public_ip():
    ips = validate_live_destination(norm("http://93.184.216.34/"))
    assert ips == ["93.184.216.34"]


def test_live_resolves_hostname(monkeypatch):
    import mauberesec.scope.urlcheck as uc

    monkeypatch.setattr(uc, "resolve_ips", lambda host: ["93.184.216.34", "10.0.0.9"])
    with pytest.raises(DestinationError, match="forbidden"):
        validate_live_destination(norm("https://example.com/"))


def test_live_rejects_unresolvable(monkeypatch):
    import mauberesec.scope.urlcheck as uc

    def boom(host):
        raise DestinationError("dns")

    monkeypatch.setattr(uc, "resolve_ips", boom)
    with pytest.raises(DestinationError, match="dns"):
        validate_live_destination(norm("https://no-such-host.invalid/"))


def test_lab_requires_registered_subnet():
    with pytest.raises(DestinationError, match="outside every registered lab subnet"):
        validate_lab_destination(norm("http://10.66.7.10/"), ["10.99.0.0/24"])


def test_lab_accepts_registered_subnet():
    ips = validate_lab_destination(norm("http://10.66.7.10/"), ["10.66.7.0/24"])
    assert ips == ["10.66.7.10"]


def test_lab_requires_any_subnet():
    with pytest.raises(DestinationError, match="No lab subnets"):
        validate_lab_destination(norm("http://10.66.7.10/"), [])
