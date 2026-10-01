"""users — multi-tenant identity (Google sign-in).

`google_sub` is the stable Google subject id and the unique login key;
`email` is informational (Google can reassign addresses over time).
`gmail_refresh_token_enc` holds the Fernet-encrypted OAuth refresh token
from the combined consent flow (Phase P3 consumes it).
"""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from app.models import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    google_sub = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    name = Column(String(255), nullable=True)
    picture = Column(String(512), nullable=True)
    role = Column(String(16), nullable=False, default="user")

    # ── Gmail linkage (combined consent) ─────────────────
    gmail_refresh_token_enc = Column(Text, nullable=True)
    gmail_connected = Column(Boolean, nullable=False, default=False)
    token_revoked_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "picture": self.picture,
            "role": self.role,
            "gmail_connected": bool(self.gmail_connected),
            "token_revoked_at": self.token_revoked_at.isoformat()
            if self.token_revoked_at
            else None,
        }
