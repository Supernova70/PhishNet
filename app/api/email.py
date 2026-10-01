"""Email API endpoints."""

import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import UTC, datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.dependencies import SessionLocal, get_current_user, get_db, owned_or_404
from app.models.email import Email
from app.models.scan import Scan, ScanStatus
from app.schemas.email import (
    EmailOut,
    EmailDetailOut,
    FetchEmailsResponse,
    EmailListResponse,
)
from app.schemas.scan import ScanOut
from app.models.user import User
from app.services.email_service import EmailService
from app.services.gmail_fetch import GmailAuthFailed, GmailNotConnected

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/emails", tags=["Emails"])

SCAN_TIMEOUT_SECONDS = 240


@router.post("/fetch", response_model=FetchEmailsResponse)
async def fetch_emails(
    limit: int = Query(20, ge=1, le=100, description="Max emails to fetch"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Fetch recent emails from the configured IMAP inbox.

    Connects to the email server, downloads recent messages,
    parses them, and stores them in the database under the
    signed-in account (row-level tenancy).
    """
    try:
        service = EmailService(db, user_id=user.id)
        new_count, total_fetched = service.fetch_and_store(limit=limit)
        return FetchEmailsResponse(
            status="success",
            new_emails=new_count,
            total_fetched=total_fetched,
        )
    except GmailNotConnected as e:
        raise HTTPException(status_code=403, detail=str(e))
    except GmailAuthFailed:
        raise HTTPException(
            status_code=403,
            detail=(
                "Gmail access expired or was revoked — reconnect Gmail "
                "by signing in with Google again"
            ),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email fetch failed: {str(e)}")


@router.get("", response_model=EmailListResponse)
async def list_emails(
    sender: str = Query(None),
    has_attachments: bool = Query(None),
    date_from: str = Query(None),
    date_to: str = Query(None),
    scanned: bool = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List the signed-in account's fetched emails with pagination."""
    query = db.query(Email).filter(Email.user_id == user.id)
    
    if sender:
        query = query.filter(Email.sender.ilike(f"%{sender}%"))
    if has_attachments is not None:
        query = query.filter(Email.has_attachments == has_attachments)
    if date_from:
        query = query.filter(Email.fetched_at >= date_from)
    if date_to:
        query = query.filter(Email.fetched_at <= date_to)
    if scanned is not None:
        if scanned:
            query = query.filter(Email.scans.any())
        else:
            query = query.filter(~Email.scans.any())
            
    total = query.count()
    emails = (
        query
        .order_by(Email.fetched_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return EmailListResponse(
        total=total,
        emails=[EmailOut(**e.to_dict()) for e in emails],
    )


@router.get("/{email_id}", response_model=EmailDetailOut)
async def get_email(
    email_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get full email details by ID (own emails only)."""
    email = db.query(Email).filter(Email.id == email_id).first()
    owned_or_404(email, user)

    data = email.to_dict()
    data["body_text"] = email.body_text
    data["body_html"] = email.body_html
    data["attachments"] = [att.to_dict() for att in email.attachments]
    return EmailDetailOut(**data)


@router.get("/{email_id}/latest-scan")
async def get_latest_scan(
    email_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get the most recent scan result for a given email (own only)."""
    email = db.query(Email).filter(Email.id == email_id).first()
    owned_or_404(email, user)

    scan = (
        db.query(Scan)
        .filter(Scan.email_id == email_id)
        .order_by(Scan.id.desc())
        .first()
    )
    if scan:
        return ScanOut(**scan.to_dict())
    return {"scan": None}


# ── Bulk Scan ──────────────────────────────────────────────

def _mark_scan_error(scan_id: int) -> None:
    """Mark a scan as ERROR using a fresh short-lived session.

    Used on timeout, when the original session is still owned by the
    abandoned worker thread — touching it would race the thread's
    connection (and closing it could hand a live connection back to
    the pool for another scan to corrupt).
    """
    err_db = SessionLocal()
    try:
        scan = err_db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.ERROR.value
            scan.completed_at = datetime.now(UTC).replace(tzinfo=None)
            err_db.commit()
    except Exception:
        err_db.rollback()
        logger.exception("Failed to mark timed-out scan %s as error", scan_id)
    finally:
        err_db.close()


def _run_bulk_scan_task(scan_ids: list[int]) -> None:
    """Run multiple scans using task-owned DB sessions with per-scan timeout.

    Important: the executor must NOT be used as a context manager here.
    On timeout, `with ThreadPoolExecutor(...)` calls shutdown(wait=True),
    which blocks forever waiting for the hung worker thread — the timeout
    handler never ran, the current scan stayed RUNNING, and every scan
    after it stayed PENDING forever. shutdown(wait=False) lets the queue
    keep moving; startup recovery cleans up the abandoned RUNNING row.
    """
    from app.services.scan_service import ScanService

    for scan_id in scan_ids:
        db = SessionLocal()
        executor = ThreadPoolExecutor(max_workers=1)
        timed_out = False
        try:
            future = executor.submit(ScanService(db).run_scan_by_id, scan_id)
            future.result(timeout=SCAN_TIMEOUT_SECONDS)
        except FuturesTimeoutError:
            timed_out = True
            logger.error("Scan %s timed out after %ds — marking as error", scan_id, SCAN_TIMEOUT_SECONDS)
            _mark_scan_error(scan_id)
        except Exception:
            logger.exception("Background bulk scan %s failed", scan_id)
            db.rollback()
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.ERROR.value
                scan.completed_at = datetime.now(UTC).replace(tzinfo=None)
                db.commit()
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
            if not timed_out:
                db.close()   # on timeout the session belongs to the still-running thread


class BulkScanRequest(BaseModel):
    email_ids: list[int] = []


class BulkScanResponse(BaseModel):
    status: str
    total_queued: int
    scan_ids: list[int]


@router.post("/bulk-scan", response_model=BulkScanResponse)
async def bulk_scan(
    request: BulkScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Trigger scans on multiple of your emails at once.

    Pass email_ids in the body, or omit to scan all your unscanned emails.
    """
    if request.email_ids:
        emails = (
            db.query(Email)
            .filter(Email.user_id == user.id, Email.id.in_(request.email_ids))
            .all()
        )
    else:
        emails = (
            db.query(Email)
            .filter(Email.user_id == user.id, ~Email.scans.any())
            .all()
        )

    if not emails:
        raise HTTPException(status_code=404, detail="No unscanned emails found")

    scan_ids = []
    for email in emails:
        scan = Scan(
            user_id=email.user_id,
            email_id=email.id,
            status=ScanStatus.PENDING.value,
            started_at=None,
        )
        db.add(scan)
        db.flush()
        scan_ids.append(scan.id)

    db.commit()

    background_tasks.add_task(_run_bulk_scan_task, scan_ids)

    return BulkScanResponse(
        status="queued",
        total_queued=len(scan_ids),
        scan_ids=scan_ids,
    )
