"""Received-header chain parsing (RFC 5321 trace reconstruction).

The `Received:` header list, as stored by an MTA, is newest-first: the
topmost entry was added by the receiving MTA. We reverse it to obtain
chronological order (hop 0 = earliest, closest to the origin).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import List, Optional

# from host (bracketed-ip) / from host (helo=...) [ip] / from [ip]
_FROM_RE = re.compile(
    r"\bfrom\s+(?:\((?P<paren>[^()]*)\)\s*)?(?P<host>[^\s();]+)?", re.IGNORECASE
)
_FROM_PAREN_RE = re.compile(
    r"from\s+(?P<host1>[^\s();]+)\s+\((?P<inner>[^()]*)\)", re.IGNORECASE
)
_HELO_RE = re.compile(r"\b(?:helo|ehlo)=(?P<helo>[^\s);]+)", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+(?P<by>[^\s();]+)", re.IGNORECASE)
_VIA_RE = re.compile(r"\bvia\s+(?P<via>[^\s;]+)", re.IGNORECASE)
_WITH_RE = re.compile(r"\bwith\s+(?P<proto>[A-Za-z0-9._/-]+)", re.IGNORECASE)
_IPV4_RE = re.compile(r"(?<![\d.])(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
_IPV6_BRACKET_RE = re.compile(r"\[(?P<ip>[0-9a-fA-F:]{2,45})\]")
_HOSTNAMES_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z]{2,}")

_INTERNAL_HOSTS = {
    "localhost", "localhost.localdomain", "ip6-localhost",
    "127.0.0.1", "::1", "0.0.0.0",
}

# Ranges that never leave an organization. Deliberately NOT ipaddress's
# is_private/is_global: those also classify documentation ranges
# (TEST-NET-1/2/3) as private, and a forged header carrying a TEST-NET
# address is not "internal" — it is suspicious but external.
_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8",
        "fc00::/7", "fe80::/10", "::1/128",
    )
)


@dataclass
class ParsedHop:
    """One parsed Received header."""

    raw: str
    from_host: Optional[str] = None
    from_ip: Optional[str] = None
    helo: Optional[str] = None
    by_host: Optional[str] = None
    via: Optional[str] = None
    protocol: Optional[str] = None
    timestamp_raw: Optional[str] = None
    timestamp_utc: Optional[datetime] = None
    is_internal: bool = False
    parse_confidence: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp_utc"] = (
            self.timestamp_utc.isoformat() if self.timestamp_utc else None
        )
        return d


def _is_internal(ip_str: Optional[str], host: Optional[str]) -> bool:
    """True when the hop stays inside a private/machine-local network."""
    if host and host.lower().rstrip(".") in _INTERNAL_HOSTS:
        return True
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return True
    return any(addr in net for net in _INTERNAL_NETWORKS)


def _extract_ip(text: str) -> Optional[str]:
    m = _IPV6_BRACKET_RE.search(text)
    if m:
        candidate = m.group("ip")
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            pass
    m = _IPV4_RE.search(text)
    if m:
        candidate = m.group("ip")
        try:
            return str(ipaddress.ip_address(candidate))  # validates octets
        except ValueError:
            return None
    return None


def _extract_timestamp(received_value: str) -> tuple[Optional[str], Optional[datetime]]:
    """
    The timestamp of a Received header is the date-time after the final
    semicolon: '... for <a@b>; Mon, 01 Jan 2026 12:00:00 +0000'.
    """
    if ";" not in received_value:
        return None, None
    tail = received_value.rsplit(";", 1)[1].strip()
    if not tail:
        return None, None
    try:
        dt = parsedate_to_datetime(tail)
    except (TypeError, ValueError, IndexError):
        return tail[:256], None
    if dt is None:
        return tail[:256], None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return tail[:256], dt.astimezone(timezone.utc).replace(tzinfo=None)


def parse_received_hop(received_value: str) -> ParsedHop:
    """Parse a single raw Received header value into a ParsedHop."""
    raw = received_value.strip()
    collapsed = re.sub(r"\s+", " ", raw)
    hop = ParsedHop(raw=raw)

    # ── from host / ip ────────────────────────────────────────────────
    m = _FROM_PAREN_RE.search(collapsed)
    if m:
        hop.from_host = m.group("host1").strip("()[]")
        inner = m.group("inner")
        ip = _extract_ip(inner)
        if ip is None:
            # inner may hold 'helo=x [ip]' or a bare hostname
            hm = _HOSTNAMES_RE.search(inner)
            if hm and "." in hm.group(0):
                hop.from_host = hm.group(0)
        else:
            hop.from_ip = ip
    else:
        m2 = _FROM_RE.search(collapsed)
        if m2 and m2.group("host"):
            token = m2.group("host").strip("()[]")
            ip_check = _extract_ip(token)
            if ip_check and _IPV4_RE.fullmatch(token.strip("[]")):
                hop.from_ip = ip_check
            elif token and not token.lower().startswith(("from", "with")):
                hop.from_host = token
        # IP may appear in brackets without a 'from' (rare): 'by ... [ip]'
        if hop.from_ip is None:
            bracketed = re.search(
                r"\((?:[^()]*\s)?\[?(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\]?\)", collapsed
            )
            if bracketed and hop.from_ip is None:
                ip_check = _extract_ip(bracketed.group("ip"))
                if ip_check:
                    hop.from_ip = ip_check

    # Some forgery-prone forms: 'from unknown (EHLO host) [1.2.3.4]'
    if hop.from_ip is None:
        bare_bracket = re.search(r"\[(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\]", collapsed)
        if bare_bracket:
            ip_check = _extract_ip(bare_bracket.group("ip"))
            if ip_check:
                hop.from_ip = ip_check

    # ── helo / by / via / with ────────────────────────────────────────
    m = _HELO_RE.search(collapsed)
    if m:
        hop.helo = m.group("helo").strip("()[]")
    else:
        # Forged-but-common form: 'from unknown (EHLO host) [1.2.3.4]'
        m = re.search(
            r"\(\s*(?:ehlo|helo)\s+(?P<helo>[^\s)]+)\s*\)", collapsed, re.IGNORECASE
        )
        if m:
            hop.helo = m.group("helo").strip("()[]")
    m = _BY_RE.search(collapsed)
    if m:
        hop.by_host = m.group("by").strip("()[]")
    m = _VIA_RE.search(collapsed)
    if m:
        hop.via = m.group("via").strip("()[]")
    m = _WITH_RE.search(collapsed)
    if m:
        hop.protocol = m.group("proto")

    # ── timestamp ─────────────────────────────────────────────────────
    hop.timestamp_raw, hop.timestamp_utc = _extract_timestamp(collapsed)

    # ── internal flag + confidence ────────────────────────────────────
    host_for_internal = hop.from_host or hop.by_host
    hop.is_internal = _is_internal(hop.from_ip, host_for_internal)

    confidence = 0.0
    if hop.from_ip:
        confidence += 0.5
    if hop.timestamp_utc:
        confidence += 0.3
    if hop.from_host or hop.by_host:
        confidence += 0.2
    hop.parse_confidence = round(min(confidence, 1.0), 2)
    return hop


def parse_received_chain(received_headers: List[str]) -> List[ParsedHop]:
    """
    Parse all Received headers into chronological order.

    Input is header order (newest first); output is reversed so hop 0 is
    the earliest hop and the last hop is the one adjacent to the
    receiving MTA. Callers enumerate for hop_index when persisting.
    """
    hops = [parse_received_hop(v) for v in received_headers if v and v.strip()]
    hops.reverse()  # newest-first → chronological
    return hops


def origin_hop(hops: List[ParsedHop]) -> Optional[ParsedHop]:
    """
    Earliest *reliable external* hop: first chronological hop carrying a
    global IP. Falls back to first hop with any parseable IP, else None.
    """
    for hop in hops:
        if hop.from_ip and not hop.is_internal:
            return hop
    for hop in hops:
        if hop.from_ip:
            return hop
    return None


def chain_is_monotonic(hops: List[ParsedHop]) -> bool:
    """
    True when timestamps never go backwards along the chain.

    Legitimate chains are strictly increasing in time toward the
    receiver; a decreasing pair indicates a forged or replayed header.
    Missing timestamps are ignored (they cannot prove or disprove
    monotonicity) — the anomaly rule for missing timestamps is separate.
    """
    times = [h.timestamp_utc for h in hops if h.timestamp_utc]
    return all(a <= b for a, b in zip(times, times[1:]))
