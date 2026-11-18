"""URL normalization and destination validation for live targets.

Live White-Hat rules: the resolved destination must be a public, unicast,
non-reserved address. Private, loopback, link-local (which covers cloud
metadata endpoints), multicast, reserved, and unspecified addresses are
rejected — fail closed.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

ALLOWED_SCHEMES = ("http", "https")
MAX_URL_LENGTH = 2048
# Hostnames that must never be treated as live targets.
DENIED_METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata.goog"})


class UrlError(Exception):
    """URL is malformed or not acceptable for assessment."""


@dataclass(frozen=True)
class NormalizedUrl:
    scheme: str
    host: str
    port: int
    path: str

    def __str__(self) -> str:
        netloc = self.host if self.port in (80, 443) else f"{self.host}:{self.port}"
        return urlunsplit((self.scheme, netloc, self.path or "/", "", ""))

    @property
    def host_port(self) -> str:
        return self.host if self.port in (80, 443) else f"{self.host}:{self.port}"


def normalize_url(url: str) -> NormalizedUrl:
    """Normalize an assessment URL; only http/https with a host is valid."""
    url = url.strip()
    if not url or len(url) > MAX_URL_LENGTH:
        raise UrlError("URL is empty or exceeds the maximum length.")
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise UrlError(f"Scheme '{parts.scheme}' is not allowed (http/https only).")
    if not parts.hostname:
        raise UrlError("URL has no hostname.")
    if parts.username or parts.password:
        raise UrlError("Credentials in URL are not allowed.")
    if parts.query or parts.fragment:
        raise UrlError("Query strings and fragments are not accepted in scope values.")

    scheme = parts.scheme.lower()
    host = parts.hostname.rstrip(".").lower()
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise UrlError("Invalid port.") from exc
    if not 1 <= port <= 65535:
        raise UrlError("Port out of range.")

    return NormalizedUrl(scheme=scheme, host=host, port=port, path=parts.path or "/")


# --- destination validation -----------------------------------------------------


class DestinationError(Exception):
    """The destination is not permitted for the requested mode."""


def resolve_ips(host: str) -> list[str]:
    """Resolve *host* to IP address strings (no DNS rebinding tricks here —
    every returned address must pass validation)."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise DestinationError(f"Cannot resolve host '{host}': {exc}") from exc
    return sorted({str(info[4][0]) for info in infos})


def _ip_is_live_safe(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        addr.is_global
        and not addr.is_private
        and not addr.is_loopback
        and not addr.is_link_local
        and not addr.is_multicast
        and not addr.is_reserved
        and not addr.is_unspecified
    )


def validate_live_destination(url: NormalizedUrl) -> list[str]:
    """Validate the destination for a Live White-Hat request.

    Every resolved address must be public; a single bad address rejects
    the whole destination (fail closed).
    """
    if url.host in DENIED_METADATA_HOSTS:
        raise DestinationError(f"'{url.host}' is a metadata endpoint and is forbidden.")
    try:
        ipaddress.ip_address(url.host)
        ips = [url.host]
    except ValueError:
        ips = resolve_ips(url.host)

    if not ips:
        raise DestinationError(f"Host '{url.host}' did not resolve to any address.")
    for ip_str in ips:
        addr = ipaddress.ip_address(ip_str)
        if not _ip_is_live_safe(addr):
            raise DestinationError(
                f"Live target resolves to forbidden address '{ip_str}' "
                "(private/loopback/link-local/multicast/reserved)."
            )
    return ips


def validate_lab_destination(url: NormalizedUrl, lab_subnets: list[str]) -> list[str]:
    """Validate the destination for a Local Lab request.

    Every resolved address must fall inside one of the registered lab
    subnets.
    """
    networks = [ipaddress.ip_network(cidr, strict=False) for cidr in lab_subnets]
    if not networks:
        raise DestinationError("No lab subnets are registered.")
    try:
        ipaddress.ip_address(url.host)
        ips = [url.host]
    except ValueError:
        ips = resolve_ips(url.host)
    if not ips:
        raise DestinationError(f"Host '{url.host}' did not resolve to any address.")
    for ip_str in ips:
        addr = ipaddress.ip_address(ip_str)
        if not any(addr in net for net in networks):
            raise DestinationError(
                f"Lab target resolves to '{ip_str}', outside every registered lab subnet."
            )
    return ips
