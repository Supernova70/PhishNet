"""IpIntel caching service — read-through cache + provider enrichment.

Flow for `enrich(ip)`:
  1. Fresh DB row (expires_at > now) → return it (no network).
  2. Otherwise: GeoIP/ASN provider lookup → hosting/VPN heuristics →
     Tor exit-list membership → optional DNSBL query → upsert row with
     an expiry of IP_INTEL_CACHE_DAYS.

Every network edge is injectable (provider, tor fetch, dnsbl resolver)
so unit tests run offline. With GEOIP_PROVIDER=none and DNSBL disabled
the service performs no I/O at all.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Callable, Optional

from app.config import get_settings
from app.engines.intel.asn_rdap import asn_summary, is_hosting, is_vpn_org
from app.engines.intel.dnsbl import check_dnsbl
from app.engines.intel.geo_provider import GeoResult, IpIntelProvider, get_provider
from app.engines.intel.vpn_tor import TorExitCache, classify_anonymization
from app.models.ip_intel import IpIntel

logger = logging.getLogger(__name__)


class IpIntelService:
    def __init__(
        self,
        db,
        provider: Optional[IpIntelProvider] = None,
        tor_cache: Optional[TorExitCache] = None,
        dnsbl_resolver: Optional[Callable] = None,
        ptr_resolver: Optional[Callable] = None,
        settings_obj=None,
        now: Optional[Callable[[], datetime]] = None,
    ):
        self.db = db
        self.settings = settings_obj or get_settings()
        if provider is None:
            provider = get_provider(
                self.settings.GEOIP_PROVIDER,
                getattr(self.settings, "MAXMIND_DB_PATH", None),
            )
        self.provider = provider
        self.tor_cache = tor_cache if tor_cache is not None else TorExitCache()
        self._dnsbl_resolver = dnsbl_resolver
        self._ptr_resolver = ptr_resolver
        self._now = now or datetime.utcnow

    # ── public API ────────────────────────────────────────────────────

    def enrich(self, ip: str) -> Optional[IpIntel]:
        """Return a fresh IpIntel row for `ip`, or None when no intel applies."""
        if not ip:
            return None
        now = self._now()
        cached = self._cached(ip, now)
        if cached is not None:
            return cached

        geo: Optional[GeoResult] = self.provider.lookup(ip)
        dnsbl_on = bool(getattr(self.settings, "DNSBL_ENABLED", False))
        if geo is None and not dnsbl_on:
            # No geo and no DNSBL work to do: either GEOIP_PROVIDER=none or
            # a transient provider failure. Never write an empty row — a
            # negative cache entry would block re-enrichment for
            # IP_INTEL_CACHE_DAYS even after the provider recovers.
            return None

        row = self._upsert(ip, geo, now, dnsbl_on)
        return row

    def cached_only(self, ip: str) -> Optional[IpIntel]:
        """DB-only lookup (no network) — for read-only API responses."""
        if not ip:
            return None
        return self._cached(ip, self._now())

    # ── internals ─────────────────────────────────────────────────────

    def _cached(self, ip: str, now: datetime) -> Optional[IpIntel]:
        row = self.db.query(IpIntel).filter(IpIntel.ip == ip).first()
        if row is None:
            return None
        if row.expires_at is not None and row.expires_at <= now:
            return None
        return row

    def _upsert(
        self,
        ip: str,
        geo: Optional[GeoResult],
        now: datetime,
        dnsbl_on: bool,
    ) -> IpIntel:
        row = self.db.query(IpIntel).filter(IpIntel.ip == ip).first()
        if row is None:
            # Flags defaulted explicitly: SQLAlchemy applies column
            # defaults at flush, and callers read this object before it.
            row = IpIntel(
                ip=ip,
                fetched_at=now,
                is_vpn=False,
                is_tor=False,
                is_proxy=False,
                is_hosting=False,
                is_dnsbl_listed=False,
            )
            self.db.add(row)

        if geo is not None:
            row.country = geo.country
            row.country_code = geo.country_code
            row.region = geo.region
            row.city = geo.city
            row.lat = geo.lat
            row.lon = geo.lon
            row.asn = geo.asn
            row.asn_org = geo.asn_org
            row.isp = geo.isp
            row.raw_json = geo.raw or None
            row.source = geo.provider
            row.is_hosting = is_hosting(geo.asn_org, geo.isp, geo.domain)

        # VPN heuristic from org names + (future) provider threat fields
        if geo is not None:
            row.is_vpn = is_vpn_org(geo.asn_org, geo.isp)

        # Tor exit membership (daily-cached fetch; injectable in tests)
        try:
            tor_ips = self.tor_cache.ips()
        except Exception as exc:  # pragma: no cover - cache already guards
            logger.warning("tor exit list unavailable: %s", exc)
            tor_ips = set()
        flags = classify_anonymization(ip, tor_ips=tor_ips, org_is_vpn=row.is_vpn)
        row.is_tor = flags["is_tor"]

        if dnsbl_on:
            zones = [
                z.strip()
                for z in str(getattr(self.settings, "DNSBL_ZONES", "")).split(",")
                if z.strip()
            ]
            if zones:
                results = check_dnsbl(ip, zones, resolver=self._dnsbl_resolver)
                row.dnsbl_json = results
                row.is_dnsbl_listed = any(
                    v == "listed" for v in results.values()
                )

        if geo is not None:
            summary = asn_summary(geo.asn, geo.asn_org, geo.isp, geo.domain)
            raw = dict(row.raw_json or {})
            raw["asn_summary"] = summary
            row.raw_json = raw

        # Reverse DNS (only when the caller supplied a resolver — i.e.
        # live DNS is explicitly opted in)
        if self._ptr_resolver is not None and not row.ptr_host:
            from app.engines.headers.dns_checks import ptr_lookup

            try:
                row.ptr_host = ptr_lookup(ip, self._ptr_resolver)
            except Exception:
                row.ptr_host = None

        row.fetched_at = now
        cache_days = int(getattr(self.settings, "IP_INTEL_CACHE_DAYS", 30))
        row.expires_at = now + timedelta(days=max(cache_days, 0))
        return row
