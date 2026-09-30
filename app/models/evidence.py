"""Evidence chain ORM — hash-chained custody log for scan artifacts.

Each row commits: the raw email SHA-256 captured at scan time and/or
the SHA-256 of an exported report. Rows are append-only and linked by
`prev_hash` → `row_hash`, so tampering with any row (or reordering the
chain) is detectable by `verify_evidence`. `report_sha256` is NULL for
the scanner-created row and set on rows appended at report export.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class EvidenceChain(Base):
    __tablename__ = "evidence_chain"

    id: Mapped[int] = mapped_column(primary_key=True)
    email_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("emails.id"), nullable=True, index=True
    )
    scan_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("scans.id"), nullable=True, index=True
    )
    raw_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    report_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    actor: Mapped[str] = mapped_column(String(64), default="system")
    prev_hash: Mapped[str] = mapped_column(String(64))
    row_hash: Mapped[str] = mapped_column(String(64))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "email_id": self.email_id,
            "scan_id": self.scan_id,
            "raw_sha256": self.raw_sha256,
            "report_sha256": self.report_sha256,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "actor": self.actor,
            "prev_hash": self.prev_hash,
            "row_hash": self.row_hash,
        }
