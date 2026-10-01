"""FetchState ORM model — tracks last-fetched IMAP UID per mailbox."""

from datetime import datetime
from typing import Optional

from sqlalchemy import String, Integer, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class FetchState(Base):
    """
    Tracks the highest UID successfully fetched and stored for each mailbox.

    On each fetch call the email service reads last_uid, searches for
    UIDs > last_uid (incremental), then updates last_uid after storing.
    This eliminates full-inbox scans and the deduplication thrash caused
    by IMAP sequence number drift.
    """

    __tablename__ = "fetch_state"
    __table_args__ = (
        UniqueConstraint("user_id", "mailbox", name="uq_fetch_state_user_mailbox"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True
    )
    mailbox: Mapped[str] = mapped_column(String(256), default="INBOX")
    last_uid: Mapped[int] = mapped_column(Integer, default=0)
    last_fetched_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True
    )
