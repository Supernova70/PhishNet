"""
Phishing Guard V2 — Dependency Injection

Provides database sessions and service instances via FastAPI's Depends().
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator

from app.config import get_settings

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
