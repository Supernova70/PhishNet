"""Pluggable DNSBL checks (SpamCop by default).

Disabled unless `DNSBL_ENABLED=True` — DNSBL zones rate-limit and some
(like Spamhaus ZEN) forbid bulk/unauthenticated use, so tests and CI
never query them: the resolver is injectable.

Query format: `<reversed-ip>.<zone>` — an A record means listed,
NXDOMAIN/empty means clean. IPv4 only (IPv6 has no canonical free zone
we would query by default).
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Callable, Dict, List, Optional

from app.engines.headers.common import is_routable_ipv4

logger = logging.getLogger(__name__)

# resolver(name, "A") -> list of A-record strings; empty = not listed
Resolver = Callable[[str, str], List[str]]

DEFAULT_ZONES = ("bl.spamcop.net",)


def _default_resolver(name: str, rdtype: str) -> List[str]:
    import dns.resolver  # lazy: tests inject their own resolver

    try:
        answers = dns.resolver.resolve(name, rdtype, lifetime=5.0)
    except dns.resolver.NXDOMAIN:
        return []
    return [r.to_text() for r in answers]


def reverse_ipv4(ip: str) -> Optional[str]:
    """203.0.113.5 → 5.113.0.203; None for non-public IPv4/IPv6."""
    if not is_routable_ipv4(ip):
        return None
    return ".".join(reversed(str(ipaddress.ip_address(ip)).split(".")))


def check_dnsbl(
    ip: str,
    zones: Optional[List[str]] = None,
    resolver: Optional[Resolver] = None,
) -> Dict[str, str]:
    """
    Returns {zone: "listed" | "clean" | "skipped" | "error"}.

    Never raises: a DNSBL outage degrades to "error" entries that the
    caller records without failing the enrichment.
    """
    zones = list(zones if zones is not None else DEFAULT_ZONES)
    resolve = resolver or _default_resolver

    rev = reverse_ipv4(ip)
    if rev is None:
        return {zone: "skipped" for zone in zones}

    results: Dict[str, str] = {}
    for zone in zones:
        try:
            records = resolve(f"{rev}.{zone}", "A")
            results[zone] = "listed" if records else "clean"
        except Exception as exc:
            logger.debug("DNSBL %s query failed for %s: %s", zone, ip, exc)
            results[zone] = "error"
    return results
