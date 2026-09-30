"""
AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
— Database Models (SIH 26106)

Uses SQLAlchemy 2.0 declarative style with mapped_column.

All models are imported here so that:
  - Alembic can discover them via target_metadata = Base.metadata
  - SQLAlchemy resolves relationship() forward references correctly
  - app/main.py only needs to import this package
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


# Import all models — ORDER MATTERS for FK resolution
from app.models.email import Email, Attachment  # noqa: F401, E402
from app.models.scan import Scan, Verdict  # noqa: F401, E402
from app.models.fetch_state import FetchState  # noqa: F401, E402
from app.models.url_result import UrlResult  # noqa: F401, E402
from app.models.email_source import (  # noqa: F401, E402
    EmailSource,
    ReceivedHop,
    AuthResult,
)
from app.models.ip_intel import IpIntel  # noqa: F401, E402
from app.models.indicator import Indicator  # noqa: F401, E402
from app.models.campaign import Campaign  # noqa: F401, E402
from app.models.evidence import EvidenceChain  # noqa: F401, E402
from app.models.audit_log import AuditLog  # noqa: F401, E402
from app.models.alert import Alert  # noqa: F401, E402
