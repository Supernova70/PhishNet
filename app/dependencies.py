"""
Phishing Guard V2 — Dependency Injection

Provides database sessions and service instances via FastAPI's Depends().
"""

from fastapi import Depends, HTTPException, Request
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator

from app.auth.session import COOKIE_NAME, SessionError, decode_session_token
from app.config import get_settings
from app.models.user import User

settings = get_settings()

_engine_kwargs: dict = {}
if settings.DATABASE_URL.startswith("postgresql"):
    # Postgres: two uvicorn workers × (pool_size + overflow) must stay
    # well under the server's max_connections (100). Default 5+10 was
    # exhausted by a burst of concurrent background scans (QueuePool
    # "connection timed out" failures under load).
    _engine_kwargs.update(pool_size=10, max_overflow=25, pool_timeout=60)

engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    **_engine_kwargs,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Yield a database session, auto-close on completion."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Resolve the signed-in user from the session cookie → 401 otherwise."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = decode_session_token(token)
    except SessionError:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    user = db.get(User, payload.get("uid"))
    if user is None:
        raise HTTPException(status_code=401, detail="Unknown user")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    """403 unless the signed-in user has the admin role."""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


def owned_or_404(obj, user: User):
    """Return obj only if it belongs to user; else 404 (never 403 — a 403
    would confirm the row exists, disclosing other tenants' activity)."""
    if obj is None or getattr(obj, "user_id", None) != user.id:
        raise HTTPException(status_code=404, detail="Not found")
    return obj
