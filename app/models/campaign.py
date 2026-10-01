"""Campaign ORM — clustered phishing runs across scans.

Campaign membership lives on `scans.campaign_id` (nullable FK added in
the same migration) so the join stays one hop and old rows remain
valid.
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, JSON, Index, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(256))
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    email_count: Mapped[int] = mapped_column(Integer, default=0)
    avg_score: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(32), default="open")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    # Shared IOCs that define the cluster + any labels
    summary_json: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    # Analyst case notes (B4) — free text, mutable via PATCH /campaigns/{id}
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "email_count": self.email_count,
            "avg_score": round(self.avg_score, 1),
            "status": self.status,
            "confidence": round(self.confidence, 2),
            "notes": self.notes,
            "summary": self.summary_json,
        }


Index("ix_campaigns_status", Campaign.status)
