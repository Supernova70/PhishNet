"""Pydantic schemas for scan and verdict responses."""

from pydantic import BaseModel
from typing import Optional, Any
from datetime import datetime


class VerdictOut(BaseModel):
    id: int
    scan_id: int
    final_score: float
    classification: str
    ai_score: float
    ai_label: Optional[str] = None
    url_score: float
    attachment_score: float
    breakdown: Optional[Any] = None
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: int
    email_id: int
    email_number: Optional[int] = None
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    verdict: Optional[VerdictOut] = None

    model_config = {"from_attributes": True}


class ScanTriggerResponse(BaseModel):
    """Response when triggering a scan."""
    status: str
    scan_id: int
    email_id: int
    verdict: Optional[VerdictOut] = None


class ScanListResponse(BaseModel):
    total: int
    scans: list[ScanOut]
