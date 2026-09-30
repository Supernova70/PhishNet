"""ASN / org enrichment and hosting-infrastructure detection.

The free ipwhois.io response already carries `connection.asn/org/isp/
domain`, so no RDAP client or `ipwhois` PyPI package is required for
the baseline feature set (deliberate deviation from the original plan —
one HTTP round-trip instead of a second library + query).

Hosting detection is a curated org/ASN-hint list: attacker infrastructure
rented from VPS providers is a strong anonymization signal for the
attribution engine.
"""

from __future__ import annotations

from typing import Optional, Sequence

# Curated provider hints, matched case-insensitively as substrings.
HOSTING_ORG_HINTS: tuple[str, ...] = (
    "amazon", "aws", "digitalocean", "ovh", "ovhcloud", "hetzner",
    "vultr", "linode", "akamai", "choopa", "m247", "leaseweb",
    "microsoft azure", "azure", "google cloud", "alibaba", "tencent",
    "contabo", "scaleway", "colocrossing", "psychz", "serverius",
    "datacamp", "crowdstream", "hostwinds", "interversity", "sharktech",
    "constant", "liquid web", "liquidweb", "ionos", "godaddy",
    "unified layer", "bluehost", "hostgator", "dreamhost",
    "choopa llc", "quadranet", "gvh", "frantech", "deliboris",
    "ponynet", "bulwark", "multacom", "nodeseek",
    "hosting", "datacenter", "data centre", "colocation",
)

# Orgs that indicate a consumer VPN / anonymity service.
VPN_ORG_HINTS: tuple[str, ...] = (
    "vpn", "nordvpn", "expressvpn", "surfshark", "proton", "mullvad",
    "hideipvpn", "ipvanish", "cyberghost", "purevpn", "windscribe",
    "torguard", "private internet access", "airvpn", "ivpn",
)


def _norm(*values: Optional[str]) -> str:
    return " ".join(v.lower() for v in values if v)


def is_hosting(
    asn_org: Optional[str] = None,
    isp: Optional[str] = None,
    domain: Optional[str] = None,
) -> bool:
    """True when the IP belongs to a cloud/VPS/hosting provider."""
    haystack = _norm(asn_org, isp, domain)
    return any(hint in haystack for hint in HOSTING_ORG_HINTS)


def is_vpn_org(asn_org: Optional[str] = None, isp: Optional[str] = None) -> bool:
    """Crude VPN-provider signal from org/ISP names (best-effort)."""
    haystack = _norm(asn_org, isp)
    return any(hint in haystack for hint in VPN_ORG_HINTS)


def asn_summary(
    asn: Optional[int],
    asn_org: Optional[str],
    isp: Optional[str],
    domain: Optional[str] = None,
) -> dict:
    """Compact ASN block for API/forensic-report output."""
    return {
        "asn": asn,
        "asn_org": asn_org,
        "isp": isp,
        "domain": domain,
        "is_hosting": is_hosting(asn_org, isp, domain),
        "is_vpn_org": is_vpn_org(asn_org, isp),
    }
