"""Pydantic schemas for email-related requests and responses."""

from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


# ── Response schemas ─────────────────────────────────────

class AttachmentOut(BaseModel):
    id: int
    email_id: int
    filename: str
    content_type: Optional[str] = None
    size_bytes: int
    sha256_hash: Optional[str] = None

    model_config = {"from_attributes": True}


class EmailOut(BaseModel):
    id: int
    number: Optional[int] = None
    message_id: str
    sender: str
    subject: str
    date: Optional[str] = None
    to_address: Optional[str] = None
    has_html: bool
    has_attachments: bool
    fetched_at: Optional[datetime] = None
    attachment_count: int = 0
    scan_count: int = 0
    latest_scan_status: Optional[str] = None
    latest_scan_classification: Optional[str] = None
    latest_scan_score: Optional[float] = None

    model_config = {"from_attributes": True}


class EmailDetailOut(EmailOut):
    """Full email detail including body text (for scan display)."""
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    attachments: List[AttachmentOut] = []

    model_config = {"from_attributes": True}


class FetchEmailsResponse(BaseModel):
    status: str
    new_emails: int
    total_fetched: int


class EmailListResponse(BaseModel):
    total: int
    emails: List[EmailOut]
