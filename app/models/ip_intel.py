"""IpIntel ORM — cached geolocation / ASN / reputation for an IP address."""

from datetime import datetime
from typing import Optional, Any

from sqlalchemy import String, Float, Boolean, DateTime, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class IpIntel(Base):
    """
    Cached intelligence for a single IP address.

    Rows expire (expires_at) so slow-moving geo/ASN data refreshes, while
    per-request lookups stay cheap and demo/offline runs can pre-seed data.
    """

    __tablename__ = "ip_intel"

    ip: Mapped[str] = mapped_column(String(64), primary_key=True)

    country: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    country_code: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    region: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    lat: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    lon: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    asn: Mapped[Optional[int]] = mapped_column(nullable=True)
    asn_org: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    isp: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    ptr_host: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    is_vpn: Mapped[bool] = mapped_column(Boolean, default=False)
    is_tor: Mapped[bool] = mapped_column(Boolean, default=False)
    is_proxy: Mapped[bool] = mapped_column(Boolean, default=False)
    is_hosting: Mapped[bool] = mapped_column(Boolean, default=False)
    is_dnsbl_listed: Mapped[bool] = mapped_column(Boolean, default=False)

    # {"bl.spamcop.net": "listed", ...}
    dnsbl_json: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    # Full provider payload for debugging / future fields.
    raw_json: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)

    source: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "region": self.region,
            "city": self.city,
            "lat": self.lat,
            "lon": self.lon,
            "asn": self.asn,
            "asn_org": self.asn_org,
            "isp": self.isp,
            "ptr_host": self.ptr_host,
            "is_vpn": self.is_vpn,
            "is_tor": self.is_tor,
            "is_proxy": self.is_proxy,
            "is_hosting": self.is_hosting,
            "is_dnsbl_listed": self.is_dnsbl_listed,
            "dnsbl": self.dnsbl_json,
            "source": self.source,
            "fetched_at": self.fetched_at.isoformat() if self.fetched_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


Index("ix_ip_intel_expires_at", IpIntel.expires_at)
