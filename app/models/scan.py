"""Scan and Verdict ORM models."""

from datetime import datetime
from typing import Optional, Any, List

from sqlalchemy import String, Integer, Float, ForeignKey, DateTime, JSON, Enum
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum

from app.models import Base


class ScanStatus(str, enum.Enum):
    """Possible states of a scan."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    ERROR = "error"


class Classification(str, enum.Enum):
    """Verdict classification levels."""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"


class Scan(Base):
    """Represents a single analysis run on an email."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("emails.id"), index=True
    )
    status: Mapped[str] = mapped_column(
        String(32), default=ScanStatus.PENDING.value
    )

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Set by campaign clustering (nullable: unclustered scans have None)
    campaign_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("campaigns.id"), nullable=True, index=True
    )

    # ── Relationships ────────────────────────────────────
    email: Mapped["Email"] = relationship(back_populates="scans")  # type: ignore[name-defined]
    verdict: Mapped[Optional["Verdict"]] = relationship(
        back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )
    url_results: Mapped[List["UrlResult"]] = relationship(  # type: ignore[name-defined]
        back_populates="scan", cascade="all, delete-orphan"
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "email_id": self.email_id,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "verdict": self.verdict.to_dict() if self.verdict else None,
        }


class Verdict(Base):
    """
    The final analysis result for a scan.

    Stores individual engine scores + the combined final score.
    """

    __tablename__ = "verdicts"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scans.id"), unique=True, index=True
    )

    # ── Scores ───────────────────────────────────────────
    final_score: Mapped[float] = mapped_column(Float, default=0.0)
    classification: Mapped[str] = mapped_column(
        String(32), default=Classification.SAFE.value
    )

    # Individual engine scores (0–100)
    ai_score: Mapped[float] = mapped_column(Float, default=0.0)
    ai_label: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    url_score: Mapped[float] = mapped_column(Float, default=0.0)
    attachment_score: Mapped[float] = mapped_column(Float, default=0.0)
    # Header-forensics score (SPF/DKIM/DMARC + relay anomalies); 0 when no
    # header evidence exists (e.g. emails fetched before raw retention).
    header_score: Mapped[float] = mapped_column(Float, default=0.0)

    # Detailed breakdown stored as JSON
    breakdown: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    # ── Relationships ────────────────────────────────────
    scan: Mapped["Scan"] = relationship(back_populates="verdict")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "final_score": self.final_score,
            "classification": self.classification,
            "ai_score": self.ai_score,
            "ai_label": self.ai_label,
            "url_score": self.url_score,
            "attachment_score": self.attachment_score,
            "header_score": self.header_score,
            "breakdown": self.breakdown,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
