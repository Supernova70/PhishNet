"""Audit log ORM — append-only record of sensitive access.

Every raw-evidence view, report export, evidence download, and
compliance action appends one row. There are intentionally no update
or delete helpers on this model.
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base

# action vocabulary (data, not enum):
#   raw_view | report_export | evidence_download | evidence_verify |
#   retention_purge | evidence_append | permission_grant |
#   permission_revoke | role_change
AUDIT_ACTIONS = (
    "raw_view",
    "report_export",
    "evidence_download",
    "evidence_verify",
    "retention_purge",
    "evidence_append",
)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    actor: Mapped[str] = mapped_column(String(64), default="system")
    action: Mapped[str] = mapped_column(String(64))
    entity_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    entity_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    detail_json: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "actor": self.actor,
            "action": self.action,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "detail": self.detail_json,
        }


Index("ix_audit_log_action", AuditLog.action)
Index("ix_audit_log_created_at", AuditLog.created_at)
