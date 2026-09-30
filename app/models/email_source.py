"""Email evidence models — raw RFC822 retention, Received chain, auth results."""

from datetime import datetime
from typing import Optional, Any, List

from sqlalchemy import (
    String,
    Integer,
    Float,
    Boolean,
    ForeignKey,
    DateTime,
    JSON,
    Text,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models import Base


class EmailSource(Base):
    """
    Preserved raw source of an email: gzipped RFC822 bytes + full headers.

    One row per email (1:1). This is the evidentiary copy — the sha256 lets
    later viewers prove the stored bytes are unchanged (chain of custody).
    """

    __tablename__ = "email_sources"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("emails.id"), unique=True, index=True
    )

    raw_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    raw_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    # Full header block: {header_name: [value, ...]} preserving repeats
    # (Received appears N times — order preserved as received, newest first).
    headers_json: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)

    fetched_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    email: Mapped["Email"] = relationship(back_populates="source")  # type: ignore[name-defined]


class ReceivedHop(Base):
    """One parsed entry of the Received header chain (RFC 5321 trace)."""

    __tablename__ = "received_hops"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("emails.id"), index=True
    )

    # Position in the chain: 0 = earliest hop (closest to origin),
    # increasing toward the receiving MTA (matches display order for traces).
    hop_index: Mapped[int] = mapped_column(Integer, default=0)
    raw: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    from_host: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    from_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    helo: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    by_host: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    via: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    timestamp_raw: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    timestamp_utc: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    ptr_host: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    is_internal: Mapped[bool] = mapped_column(Boolean, default=False)
    # Parser confidence 0.0–1.0: did we get an IP? a timestamp? both?
    parse_confidence: Mapped[float] = mapped_column(Float, default=0.0)

    email: Mapped["Email"] = relationship(back_populates="hops")  # type: ignore[name-defined]


class AuthResult(Base):
    """
    Sender authentication outcome for one email (SPF / DKIM / DMARC).

    `source` is 'header' (parsed Authentication-Results, no network),
    'dns' (actively validated via DNS), or 'both'.
    """

    __tablename__ = "auth_results"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("emails.id"), unique=True, index=True
    )

    spf_result: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    spf_domain: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    dkim_result: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    dkim_domain: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    dkim_selector: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    dmarc_result: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    dmarc_domain: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    # Whether SPF/DKIM domains align with the From header domain (RFC 7489)
    alignment: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    source: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    detail_json: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    email: Mapped["Email"] = relationship(back_populates="auth_result")  # type: ignore[name-defined]

    def to_dict(self) -> dict:
        return {
            "spf_result": self.spf_result,
            "spf_domain": self.spf_domain,
            "dkim_result": self.dkim_result,
            "dkim_domain": self.dkim_domain,
            "dkim_selector": self.dkim_selector,
            "dmarc_result": self.dmarc_result,
            "dmarc_domain": self.dmarc_domain,
            "alignment": self.alignment,
            "source": self.source,
            "checked_at": (
                self.checked_at.isoformat() if self.checked_at else None
            ),
        }


Index("ix_received_hops_email_hop", ReceivedHop.email_id, ReceivedHop.hop_index)
