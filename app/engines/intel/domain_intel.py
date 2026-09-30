"""Domain intelligence — DNS posture + registration age (plan §5, SDE-2).

Answers "who is this sending domain, and how trustworthy is it?" from
two sources:

  DNS  — MX / NS / TXT presence + counts, SPF record present, DMARC
         policy at ``_dmarc.<domain>`` (dnspython, same resolver
         contract as ``headers.dns_checks``).
  RDAP — registrar, creation / expiry dates → ``domain_age_days`` and
         ``is_young`` (< 30 days), via a plain HTTP JSON lookup.

Every network edge is injectable and individually guarded: offline
runs, missing DNS, timeouts or a failed RDAP fetch simply leave the
field ``None`` and append a short error — this module never raises for
network problems and never makes a call unless explicitly enabled.

Results are cached in-process (24 h TTL) so repeated scans / requests
for the same sender domain do not re-query the network.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

# resolver(domain, rdtype) -> list[str]   (headers.dns_checks contract)
Resolver = Callable[[str, str], List[str]]
# fetch(domain) -> RDAP JSON dict | None
RdapFetch = Callable[[str], Optional[dict]]

# Registrable-domain shape: labels + TLD, no scheme/path/junk.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)

YOUNG_DOMAIN_DAYS = 30
_CACHE_TTL_SECONDS = 24 * 3600

# (domain, fetched_at_epoch) -> DomainIntel
_cache: Dict[str, tuple] = {}
_cache_lock = threading.Lock()


@dataclass
class DomainIntel:
    """Intel for one domain. ``None`` means "unknown", not "absent"."""

    domain: str
    # DNS posture
    has_mx: Optional[bool] = None
    mx_count: int = 0
    has_ns: Optional[bool] = None
    ns_count: int = 0
    has_spf: Optional[bool] = None
    dmarc_present: Optional[bool] = None
    dmarc_policy: Optional[str] = None
    # Registration (RDAP)
    registrar: Optional[str] = None
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    domain_age_days: Optional[int] = None
    is_young: Optional[bool] = None
    # bookkeeping
    rdap_source: Optional[str] = None
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "has_mx": self.has_mx,
            "mx_count": self.mx_count,
            "has_ns": self.has_ns,
            "ns_count": self.ns_count,
            "has_spf": self.has_spf,
            "dmarc_present": self.dmarc_present,
            "dmarc_policy": self.dmarc_policy,
            "registrar": self.registrar,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "domain_age_days": self.domain_age_days,
            "is_young": self.is_young,
            "rdap_source": self.rdap_source,
            "errors": list(self.errors),
        }


def is_valid_domain(domain: str) -> bool:
    return bool(domain) and bool(_DOMAIN_RE.match(domain.strip()))


# ── network edges (defaults; injectable) ────────────────────────────────


def _default_dns_resolver(domain: str, rdtype: str) -> List[str]:
    """Live dnspython resolver. Imported lazily so tests never touch DNS."""
    from app.engines.headers.dns_checks import _default_resolver  # noqa: WPS433

    return _default_resolver(domain, rdtype)


def _default_rdap_fetch(domain: str) -> Optional[dict]:
    """RDAP lookup via rdap.org bootstrap (guarded by the caller)."""
    import httpx  # noqa: WPS433 (lazy: optional network path)

    resp = httpx.get(
        f"https://rdap.org/domain/{domain}",
        timeout=8.0,
        follow_redirects=True,
        headers={"Accept": "application/rdap+json, application/json"},
    )
    resp.raise_for_status()
    data = resp.json()
    return data if isinstance(data, dict) else None


# ── parsing helpers ─────────────────────────────────────────────────────


def _parse_rdap_events(data: dict) -> Dict[str, Optional[str]]:
    """Pull registrar / registration / expiry out of an RDAP payload."""
    registrar: Optional[str] = None
    created: Optional[str] = None
    expires: Optional[str] = None

    for event in data.get("events") or []:
        action = str(event.get("eventAction") or "").lower()
        date = event.get("eventDate")
        if not date:
            continue
        if action == "registration" and created is None:
            created = str(date)
        elif action == "expiration" and expires is None:
            expires = str(date)

    for entity in data.get("entities") or []:
        roles = [str(r).lower() for r in entity.get("roles") or []]
        if "registrar" not in roles:
            continue
        name = entity.get("handle")
        if not name:
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1:
                for entry in vcard[1]:
                    if isinstance(entry, (list, tuple)) and entry[:1] in (
                        ("fn",),
                        ("organization",),
                    ):
                        name = str(entry[3])
                        break
        if name:
            registrar = str(name)
            break

    return {"registrar": registrar, "created_at": created, "expires_at": expires}


def _age_days(created_at: Optional[str], now: datetime) -> Optional[int]:
    if not created_at:
        return None
    try:
        created = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return max(0, (now - created).days)
    except (TypeError, ValueError):
        return None


# ── core assessment ─────────────────────────────────────────────────────


def assess_domain(
    domain: str,
    *,
    resolver: Optional[Resolver] = None,
    rdap_fetch: Optional[RdapFetch] = None,
    use_dns: bool = True,
    use_rdap: bool = True,
    now: Optional[datetime] = None,
) -> DomainIntel:
    """Assess one domain. Network problems are recorded, never raised."""
    clean = (domain or "").strip().lower().rstrip(".")
    intel = DomainIntel(domain=clean)
    if not is_valid_domain(clean):
        intel.errors.append("invalid-domain")
        return intel

    now = now or datetime.now(timezone.utc)

    if use_dns:
        resolve = resolver or _default_dns_resolver

        def _lookup(rdtype: str, name: Optional[str] = None) -> Optional[List[str]]:
            try:
                return resolve(name or clean, rdtype)
            except Exception as exc:  # noqa: BLE001 — offline-safe by design
                intel.errors.append(f"{rdtype.lower()}:{type(exc).__name__}")
                return None

        mx = _lookup("MX")
        if mx is not None:
            intel.mx_count = len(mx)
            intel.has_mx = bool(mx)

        ns = _lookup("NS")
        if ns is not None:
            intel.ns_count = len(ns)
            intel.has_ns = bool(ns)

        txt = _lookup("TXT")
        if txt is not None:
            intel.has_spf = any(v.lower().startswith("v=spf1") for v in txt)

        dmarc_lookup = _lookup("TXT", f"_dmarc.{clean}")
        if dmarc_lookup is not None:
            intel.dmarc_present = False
            for rec in dmarc_lookup:
                try:
                    from app.engines.headers.dns_checks import (  # noqa: WPS433
                        parse_dmarc_record,
                    )

                    tags = parse_dmarc_record(rec)
                except Exception:  # noqa: BLE001
                    tags = None
                if tags:
                    intel.dmarc_present = True
                    intel.dmarc_policy = str(
                        tags.get("p") or tags.get("policy") or "none"
                    ).lower()
                    break

    if use_rdap:
        fetch = rdap_fetch or _default_rdap_fetch
        try:
            data = fetch(clean)
        except Exception as exc:  # noqa: BLE001 — timeouts, 404s, offline
            data = None
            intel.errors.append(f"rdap:{type(exc).__name__}")
        if data:
            parsed = _parse_rdap_events(data)
            intel.registrar = parsed["registrar"]
            intel.created_at = parsed["created_at"]
            intel.expires_at = parsed["expires_at"]
            intel.rdap_source = "rdap"
            intel.domain_age_days = _age_days(intel.created_at, now)
            if intel.domain_age_days is not None:
                intel.is_young = intel.domain_age_days < YOUNG_DOMAIN_DAYS

    return intel


def assess_domain_cached(
    domain: str,
    *,
    resolver: Optional[Resolver] = None,
    rdap_fetch: Optional[RdapFetch] = None,
    use_dns: bool = True,
    use_rdap: bool = True,
    now: Optional[datetime] = None,
) -> DomainIntel:
    """24 h in-process cache around :func:`assess_domain` (scan-path use)."""
    clean = (domain or "").strip().lower().rstrip(".")
    if not is_valid_domain(clean):
        return assess_domain(clean, use_dns=False, use_rdap=False)

    fresh = now or datetime.now(timezone.utc)
    with _cache_lock:
        hit = _cache.get(clean)
    if hit is not None:
        cached_at, intel = hit
        if time.time() - cached_at < _CACHE_TTL_SECONDS:
            return intel

    intel = assess_domain(
        clean,
        resolver=resolver,
        rdap_fetch=rdap_fetch,
        use_dns=use_dns,
        use_rdap=use_rdap,
        now=fresh,
    )
    with _cache_lock:
        _cache[clean] = (time.time(), intel)
    return intel


def sender_is_young(domain: str) -> bool:
    """True only when RDAP proves the sender domain is < 30 days old.

    Settings-gated and fully guarded: any disabled lookup, DNS/RDAP
    failure or parse error yields False (absent evidence is not risk).
    Never raises.
    """
    if not domain:
        return False
    try:
        from app.config import get_settings  # noqa: WPS433

        settings = get_settings()
        use_dns = bool(getattr(settings, "DOMAIN_INTEL_DNS_ENABLED", False))
        use_rdap = bool(getattr(settings, "DOMAIN_INTEL_RDAP_ENABLED", False))
        if not use_rdap:
            return False
        intel = assess_domain_cached(domain, use_dns=use_dns, use_rdap=use_rdap)
        return intel.is_young is True
    except Exception:  # noqa: BLE001 — attribution must never fail a scan
        return False
