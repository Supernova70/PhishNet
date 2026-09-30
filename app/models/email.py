"""Email and Attachment ORM models."""

from datetime import datetime
from typing import Optional, List

from sqlalchemy import String, Text, Boolean, Integer, ForeignKey, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models import Base


class Email(Base):
    """Represents a fetched email from the user's inbox."""

    __tablename__ = "emails"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    message_id: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    sender: Mapped[str] = mapped_column(String(512), index=True)
    subject: Mapped[str] = mapped_column(String(1024), index=True)
    date: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    to_address: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    body_html: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    body_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    has_html: Mapped[bool] = mapped_column(Boolean, default=False)
    has_attachments: Mapped[bool] = mapped_column(Boolean, default=False)

    fetched_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )

    # ── Relationships ────────────────────────────────────
    attachments: Mapped[List["Attachment"]] = relationship(
        back_populates="email", cascade="all, delete-orphan"
    )
    scans: Mapped[List["Scan"]] = relationship(  # type: ignore[name-defined]
        back_populates="email"
    )
    source: Mapped[Optional["EmailSource"]] = relationship(  # type: ignore[name-defined]
        back_populates="email", uselist=False, cascade="all, delete-orphan"
    )
    hops: Mapped[List["ReceivedHop"]] = relationship(  # type: ignore[name-defined]
        back_populates="email", cascade="all, delete-orphan",
        order_by="ReceivedHop.hop_index",
    )
    auth_result: Mapped[Optional["AuthResult"]] = relationship(  # type: ignore[name-defined]
        back_populates="email", uselist=False, cascade="all, delete-orphan"
    )

    def to_dict(self) -> dict:
        latest_scan = max(self.scans, key=lambda s: s.id, default=None)
        latest_verdict = latest_scan.verdict if latest_scan else None
        return {
            "id": self.id,
            "message_id": self.message_id,
            "sender": self.sender,
            "subject": self.subject,
            "date": self.date,
            "to_address": self.to_address,
            "has_html": self.has_html,
            "has_attachments": self.has_attachments,
            "fetched_at": self.fetched_at.isoformat() if self.fetched_at else None,
            "attachment_count": len(self.attachments),
            "scan_count": len(self.scans),
            "latest_scan_status": latest_scan.status if latest_scan else None,
            "latest_scan_classification": (
                latest_verdict.classification if latest_verdict else None
            ),
            "latest_scan_score": latest_verdict.final_score if latest_verdict else None,
        }


class Attachment(Base):
    """Represents a file attachment on an email."""

    __tablename__ = "attachments"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("emails.id"), index=True
    )

    filename: Mapped[str] = mapped_column(String(512))
    content_type: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    storage_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)

    # ── Relationships ────────────────────────────────────
    email: Mapped["Email"] = relationship(back_populates="attachments")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "email_id": self.email_id,
            "filename": self.filename,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "sha256_hash": self.sha256_hash,
        }
