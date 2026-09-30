"""Shared helpers for header-forensics modules."""

from __future__ import annotations

import ipaddress

import tldextract

_extract = tldextract.TLDExtract(suffix_list_urls=())


def domain_of(value: str | None) -> str | None:
    """
    Extract the lowercased domain from an address-like string.

    Accepts full mailbox addresses ("a@example.com"), display addresses
    ("John Doe <a@example.com>"), bare domains ("example.com"), and URLs.
    Returns None when no dot-host can be found.
    """
    if not value:
        return None
    text = value.strip()

    if "<" in text and ">" in text:
        text = text[text.find("<") + 1: text.find(">")]
    elif "@" in text and (" " in text or "," in text):
        # Unbracketed "Name a@example.com" style — take the last @ token.
        tokens = [
            t for t in text.replace(",", " ").split() if "@" in t
        ]
        if tokens:
            text = tokens[-1]

    text = text.strip().strip("<>").strip()
    if "@" in text:
        text = text.rsplit("@", 1)[-1]
    text = text.strip().strip("[]")

    if "://" in text:
        text = text.split("://", 1)[1]
    for sep in ("/", ":", " "):
        if sep in text:
            text = text.split(sep, 1)[0]
    text = text.lower().strip(".")
    if not text or "." not in text:
        return None
    return text


def display_name_of(value: str | None) -> str:
    """Return the display-name part of a From/Reply-To value ('' if none)."""
    if not value:
        return ""
    text = value.strip()
    if "<" in text:
        text = text[: text.find("<")]
    if "@" in text:
        return ""
    return text.strip().strip('"').strip()


def registrable_domain(host: str | None) -> str | None:
    """
    Public-suffix-aware registered domain for a bare host or address.
    Uses the bundled suffix list (no network).
    """
    dom = domain_of(host)
    if not dom:
        return None
    result = _extract(dom)
    return result.top_domain_under_public_suffix or dom


def same_registrable_domain(a: str | None, b: str | None) -> bool:
    """True when both values resolve to the same registered domain."""
    ra, rb = registrable_domain(a), registrable_domain(b)
    return bool(ra and rb and ra == rb)


# Non-routable ranges (mirrors received_parser's internal list). Uses
# explicit networks rather than ipaddress.is_global because Python
# classifies documentation ranges (TEST-NET-1/2/3) as non-global and
# those must remain valid test/forensic inputs.
_NON_ROUTABLE_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8",
        "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",
        "fc00::/7", "fe80::/10", "::1/128", "ff00::/8",
    )
)


def is_routable_ipv4(ip: str) -> bool:
    """
    True for IPv4 addresses worth querying on public services (DNSBL,
    geo lookups): syntactically valid AND outside private/loopback/
    link-local/multicast ranges. IPv6 returns False (no default zone).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not isinstance(addr, ipaddress.IPv4Address):
        return False
    return not any(addr in net for net in _NON_ROUTABLE_NETWORKS)


# Minimal display-name spoof watchlist — the dedicated lookalike engine
# (Week 2) does full homoglyph/typosquat detection; here we only need
# brand-vs-domain mismatch for the header anomaly score.
KNOWN_BRANDS = (
    "paypal", "google", "amazon", "apple", "microsoft", "netflix",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
    "citibank", "hsbc", "sbi", "hdfc", "icici", "axisbank",
    "dropbox", "docusign", "linkedin", "whatsapp", "telegram",
    "appleid", "icloud", "outlook", "office365", "github",
)
