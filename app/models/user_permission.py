"""user_permissions — RBAC capability grants (R1).

One row per granted capability. Effective permissions for a user are
``ROLE_DEFAULTS[role] ∪ {rows for user_id}``; ``role=admin`` implicitly
holds every registered permission and needs no rows.

Grants are read live from the DB on every permission check (one indexed
query) — never cached in the session JWT — so a revoke takes effect on the
next request without forcing a re-login.
"""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class UserPermission(Base):
    __tablename__ = "user_permissions"
    __table_args__ = (
        UniqueConstraint("user_id", "permission", name="uq_user_permissions_user_perm"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    permission: Mapped[str] = mapped_column(String(64), nullable=False)
    granted_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "permission": self.permission,
            "granted_by": self.granted_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
