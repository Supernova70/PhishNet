"""GeoIP / ASN providers.

Default: free `ipwho.is` JSON API (no key) which returns geo + ASN +
org + ISP in one response — so no separate `ipwhois` PyPI dependency or
RDAP client is needed for the baseline feature set. (The older
`api.ipwhois.io/json/{ip}` host was retired — NXDOMAIN — so we query
its successor endpoint, same schema.)

Optional: offline MaxMind GeoLite2 city database (`GEOIP_DB_PATH`,
`geoip2` import guarded). Set GEOIP_PROVIDER=none to disable lookups.

Providers must NEVER raise: a failed lookup returns None and the scan
or endpoint continues without geo evidence.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Protocol

logger = logging.getLogger(__name__)

# http_get(url) -> parsed JSON dict
HttpGet = Callable[[str], Dict[str, Any]]


@dataclass
class GeoResult:
    ip: str
    provider: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "provider": self.provider,
            "country": self.country,
            "country_code": self.country_code,
            "region": self.region,
            "city": self.city,
            "lat": self.lat,
            "lon": self.lon,
            "asn": self.asn,
            "asn_org": self.asn_org,
            "isp": self.isp,
            "domain": self.domain,
        }


class IpIntelProvider(Protocol):
    name: str

    def lookup(self, ip: str) -> Optional[GeoResult]: ...


def _default_http_get(url: str) -> Dict[str, Any]:
    import httpx  # lazy: keeps tests from needing a live client

    resp = httpx.get(url, timeout=3.0)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise ValueError("unexpected response type")
    return data


class NullProvider:
    """GEOIP_PROVIDER=none — lookups disabled, never touches the network."""

    name = "none"

    def lookup(self, ip: str) -> Optional[GeoResult]:
        return None


class IpWhoisIoProvider:
    """Free https://ipwho.is/{ip} (no API key; same schema as ipwhois.io)."""

    name = "ipwhois"
    BASE = "https://ipwho.is/{ip}"

    def __init__(self, http_get: Optional[HttpGet] = None, timeout: float = 3.0):
        self._timeout = timeout
        self._http_get = http_get or (
            lambda url: _default_http_get(url)
        )

    def lookup(self, ip: str) -> Optional[GeoResult]:
        try:
            data = self._http_get(self.BASE.format(ip=ip))
        except Exception as exc:  # network failure must never block a scan
            logger.warning("ipwhois lookup failed for %s: %s", ip, exc)
            return None
        if not data.get("success", True):
            message = str(data.get("message") or "").lower()
            if "reserved" in message or "invalid ip" in message:
                # Definitive answer: this IP will never have intel (e.g.
                # documentation ranges). Return an empty result so the
                # service caches the miss instead of retrying every view.
                return GeoResult(ip=ip, provider=self.name, raw=data)
            # Rate limits / unknown errors are transient — return None so
            # nothing is cached and the next request can retry.
            return None
        conn = data.get("connection") or {}
        asn_raw = conn.get("asn")
        try:
            asn = int(asn_raw) if asn_raw not in (None, "") else None
        except (TypeError, ValueError):
            asn = None
        return GeoResult(
            ip=ip,
            provider=self.name,
            country=data.get("country"),
            country_code=data.get("country_code"),
            region=data.get("region"),
            city=data.get("city"),
            lat=_float(data.get("latitude")),
            lon=_float(data.get("longitude")),
            asn=asn,
            asn_org=conn.get("org"),
            isp=conn.get("isp"),
            domain=conn.get("domain"),
            raw=data,
        )


class MaxMindGeoLite2Provider:
    """Offline GeoLite2-City database (optional: `pip install geoip2`)."""

    name = "maxmind"

    def __init__(self, db_path: Optional[str] = None):
        self._reader = None
        self.available = False
        if not db_path:
            return
        try:
            import geoip2.database  # noqa: PLC0415 (guarded optional dep)

            self._reader = geoip2.database.Reader(db_path)
            self.available = True
        except Exception as exc:
            logger.warning("GeoLite2 DB unavailable at %s: %s", db_path, exc)

    def lookup(self, ip: str) -> Optional[GeoResult]:
        if not self.available:
            return None
        try:
            resp = self._reader.city(ip)
        except Exception as exc:
            logger.debug("GeoLite2 lookup failed for %s: %s", ip, exc)
            return None
        return GeoResult(
            ip=ip,
            provider=self.name,
            country=resp.country.name,
            country_code=resp.country.iso_code,
            region=resp.subdivisions.most_specific.name,
            city=resp.city.name,
            lat=resp.location.latitude,
            lon=resp.location.longitude,
            raw={},
        )


def _float(value: Any) -> Optional[float]:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def get_provider(provider_id: str, db_path: Optional[str] = None) -> IpIntelProvider:
    """Factory driven by the GEOIP_PROVIDER setting."""
    pid = (provider_id or "none").lower()
    if pid == "ipwhois":
        return IpWhoisIoProvider()
    if pid == "maxmind":
        return MaxMindGeoLite2Provider(db_path)
    return NullProvider()
