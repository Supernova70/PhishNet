"""Indicator ORM — per-scan IoCs for correlation.

One row per (scan, type, value): re-scanning the same email bumps
`sighting_count`, while different scans holding the same value each get
their own row. That per-scan linkage is what campaign clustering and
the attribution graph join on; `/indicators` aggregates across scans
(type, value) for search.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base

# type vocabulary (kept as data, not enum, so new indicator kinds can
# land without a migration):
#   sender_domain | replyto_domain | origin_ip | url_domain |
#   url_host_ip | attachment_hash | lookalike_brand
INDICATOR_TYPES = (
    "sender_domain",
    "replyto_domain",
    "origin_ip",
    "url_domain",
    "url_host_ip",
    "attachment_hash",
    "lookalike_brand",
)


class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint(
            "scan_id", "type", "value", name="uq_indicator_scan_type_value"
        ),
        Index("ix_indicators_scan_id", "scan_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True
    )
    scan_id: Mapped[Optional[int]] = mapped_column(nullable=True)
    type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(String(512))
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    sighting_count: Mapped[int] = mapped_column(Integer, default=1)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "type": self.type,
            "value": self.value,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "sighting_count": self.sighting_count,
        }
