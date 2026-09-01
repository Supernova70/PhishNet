"""Scan API endpoints."""

import json
import asyncio
import csv
import io
import logging
import threading
from collections import defaultdict
from datetime import UTC, datetime
from typing import AsyncGenerator

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.dependencies import SessionLocal, get_db
from app.models.email import Email
from app.models.scan import Scan, ScanStatus, Verdict
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


# ═══════════════════════════════════════════════════════════════════════════════
# Fixed-path routes (must come before parameterized routes)
# ═══════════════════════════════════════════════════════════════════════════════

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


@router.get("/export/csv")
async def export_scans_csv(
    classification: str = Query(None),
    db: Session = Depends(get_db),
):
    """Export all scan results as a downloadable CSV file."""
    query = db.query(Scan).filter(Scan.status == ScanStatus.COMPLETE.value)

    if classification:
        query = query.join(Verdict).filter(Verdict.classification == classification)

    scans = query.order_by(Scan.id.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Scan ID", "Email ID", "Subject", "Sender", "Date",
        "Final Score", "Classification", "AI Score", "URL Score",
        "Attachment Score", "AI Label", "Total URLs", "High Risk URLs",
        "Total Files", "High Risk Files",
    ])

    for scan in scans:
        verdict = scan.verdict
        email = scan.email
        bd = verdict.breakdown if verdict else {}
        url_data = bd.get("url", {})
        att_data = bd.get("attachment", {})

        writer.writerow([
            scan.id,
            scan.email_id,
            email.subject if email else "",
            email.sender if email else "",
            email.date if email else "",
            verdict.final_score if verdict else 0,
            verdict.classification if verdict else "",
            verdict.ai_score if verdict else 0,
            verdict.url_score if verdict else 0,
            verdict.attachment_score if verdict else 0,
            verdict.ai_label if verdict else "",
            url_data.get("total_urls", 0),
            len(url_data.get("high_risk_urls", [])),
            att_data.get("total_files", 0),
            len(att_data.get("high_risk_files", [])),
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishing_guard_scans.csv"},
    )


@router.post("/auto-scan")
async def trigger_auto_scan(background_tasks: BackgroundTasks):
    """Manually trigger an auto-scan cycle (fetch + scan new emails)."""
    background_tasks.add_task(_run_auto_scan)
    return {"status": "queued", "message": "Auto-scan started in background"}


# ═══════════════════════════════════════════════════════════════════════════════
# Parameterized routes
# ═══════════════════════════════════════════════════════════════════════════════

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


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Get scan details including verdict."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanOut(**scan.to_dict())


# ── AI Threat Summary ──────────────────────────────────────

class ThreatSummaryResponse(BaseModel):
    scan_id: int
    classification: str
    final_score: float
    summary: str
    key_findings: list[str]
    risk_factors: list[dict]


def _generate_threat_summary(scan: Scan) -> dict:
    """Generate a natural language threat summary from scan verdict data."""
    verdict = scan.verdict
    if not verdict:
        return {
            "summary": "No analysis results available.",
            "key_findings": [],
            "risk_factors": [],
        }

    bd = verdict.breakdown or {}
    classification = verdict.classification
    score = verdict.final_score

    findings = []
    risk_factors = []

    # AI Engine findings
    ai_data = bd.get("ai", {})
    if ai_data.get("is_phishing"):
        confidence = ai_data.get("score", 0)
        findings.append(
            f"AI model flagged this email as phishing with {confidence:.0f}% confidence "
            f"(detected urgency/social engineering language patterns)"
        )
        risk_factors.append({
            "engine": "ML Text Analysis",
            "severity": "high" if confidence > 70 else "medium",
            "detail": f"Phishing language detected ({confidence:.0f}% confidence)",
        })
    elif ai_data.get("score", 0) > 40:
        findings.append(
            f"AI model gave a moderate risk score of {ai_data['score']:.0f}% "
            f"(label: {ai_data.get('label', 'unknown')})"
        )

    # URL Engine findings
    url_data = bd.get("url", {})
    total_urls = url_data.get("total_urls", 0)
    high_risk_urls = url_data.get("high_risk_urls", [])
    per_url = url_data.get("per_url", [])

    if total_urls > 0:
        if high_risk_urls:
            findings.append(
                f"Found {len(high_risk_urls)} high-risk URL(s) out of {total_urls} total "
                f"(flagged for brand impersonation, IP-based hosting, or suspicious patterns)"
            )
            risk_factors.append({
                "engine": "URL Analysis",
                "severity": "high",
                "detail": f"{len(high_risk_urls)} high-risk URL(s) detected",
            })
        else:
            findings.append(f"Analyzed {total_urls} URL(s) — none flagged as high risk")

    # Per-URL details
    for url_entry in per_url[:3]:
        flags = url_entry.get("top_flags", [])
        vt_mal = url_entry.get("vt_malicious", 0)
        if vt_mal > 0:
            findings.append(
                f"URL \"{url_entry['url'][:60]}\" was flagged by VirusTotal "
                f"({vt_mal} malicious engine reports)"
            )
            risk_factors.append({
                "engine": "VirusTotal",
                "severity": "high",
                "detail": f"VT flagged: {url_entry['url'][:60]}",
            })
        elif flags:
            findings.append(
                f"URL \"{url_entry['url'][:60]}\" triggered heuristic flags: {', '.join(flags[:3])}"
            )

    # Attachment Engine findings
    att_data = bd.get("attachment", {})
    total_files = att_data.get("total_files", 0)
    high_risk_files = att_data.get("high_risk_files", [])
    per_file = att_data.get("per_file", [])

    if total_files > 0:
        if high_risk_files:
            findings.append(
                f"{len(high_risk_files)} of {total_files} attachment(s) flagged as high risk"
            )
            risk_factors.append({
                "engine": "Attachment Analysis",
                "severity": "high",
                "detail": f"{len(high_risk_files)} high-risk file(s) detected",
            })
        else:
            findings.append(f"Analyzed {total_files} attachment(s) — none flagged as high risk")

    for file_entry in per_file[:3]:
        yara = file_entry.get("yara_matches", [])
        if yara:
            rule_names = [m.get("rule", "unknown") for m in yara[:2]]
            findings.append(
                f"Attachment \"{file_entry.get('filename', 'unknown')}\" "
                f"matched YARA rules: {', '.join(rule_names)}"
            )
            risk_factors.append({
                "engine": "YARA",
                "severity": "high" if any(m.get("severity") in ("critical", "high") for m in yara) else "medium",
                "detail": f"YARA match: {', '.join(rule_names)}",
            })

    # Generate the summary paragraph
    if classification == "dangerous":
        severity_word = "DANGEROUS"
        action = "This email should be immediately quarantined and should not be opened or forwarded."
    elif classification == "suspicious":
        severity_word = "SUSPICIOUS"
        action = "This email shows suspicious characteristics and should be treated with caution."
    else:
        severity_word = "SAFE"
        action = "This email appears to be legitimate based on our analysis."

    summary_parts = [
        f"This email is classified as {severity_word} with an overall risk score of {score:.0f}/100.",
        action,
    ]

    if ai_data.get("is_phishing"):
        summary_parts.append(
            f"The AI text analysis engine detected phishing language patterns "
            f"with {ai_data.get('score', 0):.0f}% confidence."
        )

    if high_risk_urls:
        summary_parts.append(
            f"The URL analysis found {len(high_risk_urls)} suspicious link(s) "
            f"that may indicate phishing or credential theft."
        )

    if high_risk_files:
        summary_parts.append(
            f"Attachment analysis flagged {len(high_risk_files)} file(s) "
            f"as potentially malicious."
        )

    if not findings:
        summary_parts.append("No significant threats were detected across all analysis engines.")

    return {
        "summary": " ".join(summary_parts),
        "key_findings": findings,
        "risk_factors": risk_factors,
    }


@router.get("/{scan_id}/summary", response_model=ThreatSummaryResponse)
async def get_threat_summary(scan_id: int, db: Session = Depends(get_db)):
    """
    Generate an AI-powered natural language threat summary for a scan.

    Produces a human-readable explanation of why an email was classified
    a certain way, including key findings from each analysis engine.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != ScanStatus.COMPLETE.value:
        raise HTTPException(
            status_code=400,
            detail=f"Scan is not complete (status: {scan.status})",
        )

    verdict = scan.verdict
    if not verdict:
        raise HTTPException(status_code=404, detail="No verdict available")

    result = _generate_threat_summary(scan)

    return ThreatSummaryResponse(
        scan_id=scan.id,
        classification=verdict.classification,
        final_score=verdict.final_score,
        summary=result["summary"],
        key_findings=result["key_findings"],
        risk_factors=result["risk_factors"],
    )


# ═══════════════════════════════════════════════════════════════════════════════
# SSE (Server-Sent Events) for Real-Time Scan Progress
# ═══════════════════════════════════════════════════════════════════════════════

# In-memory subscriber registry: scan_id -> list of queues
_scan_subscribers: dict[int, list[asyncio.Queue]] = defaultdict(list)


def publish_scan_event(scan_id: int, event: dict):
    """Publish a scan event to all subscribers of that scan."""
    queues = _scan_subscribers.get(scan_id, [])
    for q in queues:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass


async def _scan_event_generator(scan_id: int, queue: asyncio.Queue) -> AsyncGenerator[str, None]:
    """Generate SSE events from a queue."""
    try:
        yield f"data: {json.dumps({'type': 'connected', 'scan_id': scan_id})}\n\n"

        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") in ("complete", "error"):
                    break
            except asyncio.TimeoutError:
                yield f": keepalive\n\n"
    finally:
        if scan_id in _scan_subscribers:
            try:
                _scan_subscribers[scan_id].remove(queue)
            except ValueError:
                pass
            if not _scan_subscribers[scan_id]:
                del _scan_subscribers[scan_id]


@router.get("/{scan_id}/events")
async def stream_scan_events(scan_id: int, db: Session = Depends(get_db)):
    """Subscribe to real-time scan progress via Server-Sent Events."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status == ScanStatus.COMPLETE.value:
        verdict = scan.verdict
        async def immediate_complete():
            yield f"data: {json.dumps({'type': 'connected', 'scan_id': scan_id})}\n\n"
            yield f"data: {json.dumps({'type': 'complete', 'scan_id': scan_id, 'classification': verdict.classification if verdict else 'unknown', 'final_score': verdict.final_score if verdict else 0})}\n\n"
        return StreamingResponse(immediate_complete(), media_type="text/event-stream")

    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    _scan_subscribers[scan_id].append(queue)

    return StreamingResponse(
        _scan_event_generator(scan_id, queue),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Auto-Scan Background Task
# ═══════════════════════════════════════════════════════════════════════════════

_auto_scan_running = False


def _run_auto_scan():
    """Background task: fetch new emails and auto-scan them."""
    global _auto_scan_running
    if _auto_scan_running:
        return
    _auto_scan_running = True
    try:
        db = SessionLocal()
        try:
            from app.services.email_service import EmailService
            email_service = EmailService(db)
            new_count = email_service.fetch_emails()

            if new_count > 0:
                from app.models.email import Email as EmailModel
                unsanned = (
                    db.query(EmailModel)
                    .outerjoin(Scan)
                    .filter(Scan.id.is_(None))
                    .all()
                )
                scan_service = ScanService(db)
                for email in unsanned:
                    try:
                        scan_service.trigger_scan(email.id)
                    except Exception as e:
                        logger.warning(f"Auto-scan failed for email {email.id}: {e}")

            logger.info(f"Auto-scan complete: {new_count} new emails fetched")
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Auto-scan error: {e}")
    finally:
        _auto_scan_running = False
