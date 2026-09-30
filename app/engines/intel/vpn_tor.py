"""VPN / proxy / Tor signals for an origin IP.

Tor exit-node list is fetched from check.torproject.org (plain text,
one IP per line) and cached in-process for the calendar day. The fetch
is injectable so tests never touch the network.

VPN/proxy flags come from two best-effort sources:
  1. Provider payload threat fields (paid tiers expose these; the free
     ipwhois.io response does not — field exists for future providers)
  2. Org/ISP name heuristics from `asn_rdap`
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timezone
from typing import Callable, Optional, Set

logger = logging.getLogger(__name__)

TOR_BULK_EXITLIST_URL = "https://check.torproject.org/torbulkexitlist"

# fetch_text(url) -> raw body
FetchText = Callable[[str], str]


def _default_fetch_text(url: str) -> str:
    import httpx  # lazy by design

    resp = httpx.get(url, timeout=10.0)
    resp.raise_for_status()
    return resp.text


def parse_tor_exitlist(body: str) -> Set[str]:
    import ipaddress

    ips: Set[str] = set()
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ips.add(str(ipaddress.ip_address(line)))
        except ValueError:
            continue
    return ips


class TorExitCache:
    """Daily-cached Tor exit-node set."""

    def __init__(self, fetch_text: Optional[FetchText] = None):
        self._fetch_text = fetch_text
        self._ips: Set[str] = set()
        self._fetched_on: Optional[date] = None

    def ips(self, today: Optional[date] = None) -> Set[str]:
        today = today or datetime.now(timezone.utc).date()
        if self._fetched_on == today:
            return self._ips
        fetch = self._fetch_text or _default_fetch_text
        try:
            self._ips = parse_tor_exitlist(fetch(TOR_BULK_EXITLIST_URL))
            self._fetched_on = today
        except Exception as exc:
            # Keep yesterday's list rather than failing the scan.
            logger.warning("Tor exit list refresh failed: %s", exc)
        return self._ips

    def is_exit(self, ip: str) -> bool:
        return ip in self.ips()


def classify_anonymization(
    ip: str,
    *,
    tor_ips: Set[str],
    org_is_vpn: bool = False,
    provider_threat: Optional[dict] = None,
) -> dict:
    """Merge all anonymization signals into flags for the IpIntel row."""
    threat = provider_threat or {}
    is_tor = ip in tor_ips or bool(threat.get("tor"))
    is_vpn = org_is_vpn or bool(threat.get("vpn"))
    is_proxy = bool(threat.get("proxy"))
    return {"is_vpn": is_vpn, "is_tor": is_tor, "is_proxy": is_proxy}
