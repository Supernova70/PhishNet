"""Scan API endpoints."""

import logging
from datetime import UTC, datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.dependencies import SessionLocal, get_db
from app.models.email import Email
from app.models.scan import Scan, ScanStatus
from app.schemas.scan import ScanListResponse, ScanOut, ScanTriggerResponse
from app.services.scan_service import ScanService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scans", tags=["Scans"])


def _run_scan_task(scan_id: int) -> None:
    """Run a scan after the HTTP response using a task-owned DB session."""
    db = SessionLocal()
    try:
        ScanService(db).run_scan_by_id(scan_id)
    except Exception:
        logger.exception("Background scan %s failed", scan_id)
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.ERROR.value
            scan.completed_at = datetime.now(UTC).replace(tzinfo=None)
            db.commit()
    finally:
        db.close()


@router.post(
    "/{email_id}",
    status_code=202,
    response_model=ScanTriggerResponse,
)
async def trigger_scan(
    email_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db)
):
    """
    Trigger a full analysis scan on an email.

    Creates a pending scan and returns immediately. The frontend polls
    GET /scans/{scan_id} until the scan is complete or errored.
    """
    # Verify email exists
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")

    # Create scan record
    scan = Scan(
        email_id=email_id,
        status=ScanStatus.PENDING.value,
        started_at=None,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(_run_scan_task, scan.id)
    return ScanTriggerResponse(
        status="queued",
        scan_id=scan.id,
        email_id=email_id,
        verdict=None,
    )


@router.get("", response_model=ScanListResponse)
async def list_scans(
    classification: str = Query(None),
    score_min: float = Query(None),
    score_max: float = Query(None),
    email_id: int = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """List all scans with pagination."""
    query = db.query(Scan)

    if email_id is not None:
        query = query.filter(Scan.email_id == email_id)

    if classification or score_min is not None or score_max is not None:
        from app.models.scan import Verdict

        query = query.join(Verdict)
        if classification:
            query = query.filter(Verdict.classification == classification)
        if score_min is not None:
            query = query.filter(Verdict.final_score >= score_min)
        if score_max is not None:
            query = query.filter(Verdict.final_score <= score_max)

    total = query.count()
    scans = query.order_by(Scan.id.desc()).offset(skip).limit(limit).all()
    return ScanListResponse(
        total=total,
        scans=[ScanOut(**s.to_dict()) for s in scans],
    )


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Get scan details including verdict."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanOut(**scan.to_dict())
