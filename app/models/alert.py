"""Alert ORM — notification rows for terminal / high-risk scans.

Created at scan completion when at least one trigger fires:
score ≥ 70 (high_risk), spoofing evidence (spoof), or a BEC
category at ≥ 40 (bec). One row per scan; `reasons` records every
trigger that fired. Unread = `read_at IS NULL`.
"""

from datetime import datetime
from typing import Any, List, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scans.id"), unique=True, index=True
    )
    email_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("emails.id"), nullable=True, index=True
    )
    score: Mapped[float] = mapped_column(Float, default=0.0)
    classification: Mapped[str] = mapped_column(String(32), default="safe")
    # comma-free list stored as JSON: ["high_risk", "spoof", "bec"]
    reasons: Mapped[Optional[List]] = mapped_column(JSON, nullable=True)
    subject: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    sender: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    read_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "email_id": self.email_id,
            "score": round(self.score, 1),
            "classification": self.classification,
            "reasons": list(self.reasons or []),
            "subject": self.subject,
            "sender": self.sender,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "read": self.read_at is not None,
        }


Index("ix_alerts_read_at", Alert.read_at)
