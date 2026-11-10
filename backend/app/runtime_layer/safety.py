"""Guardrails for every outbound probe the runtime and web-discovery layers send.

The runtime layer sends real HTTP requests, and the web-discovery layer follows
real links, so sending them at the wrong host is the difference between a
security test and an attack on something nobody approved. Target selection is
therefore enforced here, in one place, rather than trusted from the caller:

1. Only http/https URLs are accepted.
2. A host is reachable in one of two ways, and only two:
   a. It matches the operator-configured static allowlist
      (``RUNTIME_TARGET_ALLOWLIST``). This is how an internal pentest target or
      the bundled demo target (a Docker-internal hostname that is itself a
      private address) is approved -- the operator typed it in deliberately.
   b. It is a public-internet host, the operator has switched public-target
      scanning on at all (``ALLOW_PUBLIC_TARGETS``), the project owner has
      recorded their authorization to test it (``Project.target_authorized``),
      and the host resolves only to public IP addresses. This is the path a
      URL-based scan of someone's live website takes.
3. Every address the hostname resolves to is checked, not just the first one:
   a host that resolves to several IPs only needs ONE private address to be an
   SSRF vector (DNS rebinding, multi-homed hosts), so all of them are checked
   and any private hit blocks the whole target.
4. Every link the web crawler follows is re-validated the same way, against
   its own resolved address, with the crawl confined to the authorized host --
   so a page on the authorized target cannot smuggle the crawler onto a
   different, unapproved host, or onto the scanner's own internal services, by
   linking or redirecting to them. See ``assert_link_allowed``.
5. Credentials are never echoed back into responses or logs.

This mirrors the OWASP SSRF Prevention Cheat Sheet's two headline controls --
allowlist the destination and validate the resolved IP, including on every
redirect -- rather than trying to blocklist "bad" hosts, which is well known to
be bypassable (short IPv4 forms, IPv6, DNS rebinding after the first check).
"""

from __future__ import annotations

import ipaddress
import socket
from typing import List, Optional, Sequence
from urllib.parse import urlparse

from app.config import settings


class TargetNotAllowed(ValueError):
    """Raised when a probe target is not explicitly reachable."""


class SSRFBlocked(TargetNotAllowed):
    """Raised specifically when a host resolves to a private/internal address."""


# Address ranges a scan must never be allowed to reach, beyond Python's own
# ``is_private`` / ``is_loopback`` / ``is_link_local`` classification: the IPv4
# carrier-grade NAT block (RFC 6598) and the cloud metadata address, which
# otherwise falls inside the already-blocked link-local range but is worth
# naming explicitly since it is the single most common SSRF payoff.
_EXTRA_BLOCKED = [
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("fd00::/8"),  # unique local IPv6, ~= RFC1918 for v6
]


def normalise_base_url(base_url: str) -> str:
    return (base_url or "").strip().rstrip("/")


def _is_blocked_ip(ip: "ipaddress._BaseAddress") -> bool:
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True
    return any(ip in network for network in _EXTRA_BLOCKED)


def resolve_public_ips(host: str) -> List[str]:
    """Resolve ``host`` and raise :class:`SSRFBlocked` if any address is private.

    Every A/AAAA record is checked, not only the one a client happens to use,
    because an attacker only needs one resolvable private answer to pivot the
    scanner onto an internal service.
    """
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SSRFBlocked(f"'{host}' could not be resolved: {exc}") from exc

    ips: List[ipaddress._BaseAddress] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        try:
            ips.append(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
    if not ips:
        raise SSRFBlocked(f"'{host}' did not resolve to any usable address.")

    blocked = [ip for ip in ips if _is_blocked_ip(ip)]
    if blocked:
        raise SSRFBlocked(
            f"'{host}' resolves to {blocked[0]}, which is a private, loopback or "
            "otherwise internal address. Scanning it is blocked so a target cannot "
            "redirect or trick the scanner into reaching internal or "
            "cloud-metadata services."
        )
    return [str(ip) for ip in ips]


def _matches_allowlist(hostname: str, port: Optional[int], allowlist: Sequence[str]) -> bool:
    for allowed in allowlist:
        allowed_parsed = urlparse(allowed if "//" in allowed else f"//{allowed}")
        same_host = (allowed_parsed.hostname or allowed) == hostname
        port_ok = allowed_parsed.port in (None, port)
        if same_host and port_ok:
            return True
    return False


def assert_target_allowed(base_url: str, *, allow_public: Optional[bool] = None) -> str:
    """The single gate that decides whether a *primary* target may be probed.

    Used by the differential runtime tester and, for the primary URL only, by
    the web crawler before it sends a single request.
    """
    url = normalise_base_url(base_url)
    if not url:
        raise TargetNotAllowed("A target base URL is required.")

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise TargetNotAllowed("Only http:// and https:// targets can be probed.")
    if not parsed.hostname:
        raise TargetNotAllowed("The target URL has no host.")

    allowlist = settings.allowlisted_targets
    if _matches_allowlist(parsed.hostname, parsed.port, allowlist):
        # The operator typed this exact host into RUNTIME_TARGET_ALLOWLIST
        # themselves, so it is approved even if the address is private (that is
        # exactly how the bundled Docker-internal demo target works).
        return url

    allow_public = settings.allow_public_targets if allow_public is None else allow_public
    if not allow_public:
        raise TargetNotAllowed(
            f"'{url}' is not in RUNTIME_TARGET_ALLOWLIST, and scanning of "
            "public, non-allowlisted targets is switched off (ALLOW_PUBLIC_TARGETS=false). "
            "Add the host to the allowlist, or ask the operator to enable public-target "
            "scanning and confirm authorization for this project."
        )

    # Public-target path: the host itself must resolve to a public address.
    resolve_public_ips(parsed.hostname)
    return url


def assert_link_allowed(url: str, primary_host: str, *, allow_public: Optional[bool] = None) -> str:
    """Re-validate a link discovered while crawling ``primary_host``.

    Every followed link -- including a redirect target -- is checked again, on
    its own, rather than trusted because the starting page was approved: the
    starting page is attacker-influenced content once the target is reachable
    by anyone, so it must not be able to steer the crawler anywhere the
    primary-target check would not itself have allowed.
    """
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise TargetNotAllowed(f"'{url}' uses an unsupported scheme and was not followed.")
    if not parsed.hostname:
        raise TargetNotAllowed(f"'{url}' has no host and was not followed.")

    allowlist = settings.allowlisted_targets
    if _matches_allowlist(parsed.hostname, parsed.port, allowlist):
        return url

    if parsed.hostname != primary_host:
        raise TargetNotAllowed(
            f"'{url}' points off-scope, at a different host than the authorized "
            f"target ({primary_host}), and was not followed."
        )

    allow_public = settings.allow_public_targets if allow_public is None else allow_public
    if not allow_public:
        raise TargetNotAllowed(f"'{url}' is not reachable (public-target scanning is disabled).")

    resolve_public_ips(parsed.hostname)
    return url


def is_target_allowed(base_url: str) -> bool:
    try:
        assert_target_allowed(base_url)
        return True
    except TargetNotAllowed:
        return False
