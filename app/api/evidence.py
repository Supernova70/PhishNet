"""Evidence custody API + audit trail.

- GET /emails/{id}/evidence/raw   stream retained raw message (audited)
- GET /evidence                   custody rows (filter by email/scan)
- GET /evidence/{id}/verify       row + link + full-chain verification
- GET /audit                      append-only access log
"""

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from app.config import get_settings
from sqlalchemy.orm import Session

from app.dependencies import get_current_user, get_db, owned_or_404
from app.models.audit_log import AuditLog
from app.models.user import User
from app.models.email import Email
from app.models.scan import Scan
from app.models.evidence import EvidenceChain
from app.services.evidence_service import audit, verify_evidence

router = APIRouter()


@router.get("/emails/{email_id}/evidence/raw")
async def download_raw_evidence(
    email_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Stream the retained raw message (gzipped, own emails only).
    Every access is written to the append-only audit log."""
    email = db.get(Email, email_id)
    owned_or_404(email, user)
    source = email.source
    if source is None or not source.raw_path:
        raise HTTPException(status_code=404, detail="Raw evidence not retained")
    path = Path(source.raw_path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Evidence file missing on disk")

    audit(
        db,
        "raw_view",
        actor=user.email,
        entity_type="email",
        entity_id=email.id,
        detail={"path": str(path), "sha256": source.raw_sha256},
        user_id=user.id,
    )
    return FileResponse(
        path,
        media_type="application/gzip",
        filename=f"evidence-{email.id}.eml.gz",
    )


@router.get("/evidence")
async def list_evidence(
    email_id: Optional[int] = Query(None),
    scan_id: Optional[int] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(EvidenceChain).filter(EvidenceChain.user_id == user.id)
    if email_id is not None:
        query = query.filter(EvidenceChain.email_id == email_id)
    if scan_id is not None:
        query = query.filter(EvidenceChain.scan_id == scan_id)
    rows = query.order_by(EvidenceChain.id.desc()).limit(limit).all()
    return {"count": len(rows), "evidence": [r.to_dict() for r in rows]}


@router.get("/evidence/{evidence_id}/verify")
async def verify_evidence_endpoint(
    evidence_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    row = db.get(EvidenceChain, evidence_id)
    owned_or_404(row, user)
    result = verify_evidence(db, evidence_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Evidence row not found")
    audit(
        db,
        "evidence_verify",
        actor=user.email,
        entity_type="evidence",
        entity_id=evidence_id,
        detail={"valid": result["valid"]},
        user_id=user.id,
    )
    return result


@router.get("/artifacts/url-screenshots/{scan_id}/{filename}")
async def url_screenshot(
    scan_id: int,
    filename: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Serve a stored URL screenshot (own scans only, no traversal)."""
    scan = db.get(Scan, scan_id)
    owned_or_404(scan, user)
    if Path(filename).name != filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=404, detail="Not found")
    base = Path(get_settings().DYNAMIC_URL_SCREENSHOT_DIR) / str(scan_id)
    path = (base / filename).resolve()
    if not path.is_file() or base.resolve() not in path.parents:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return FileResponse(path, media_type="image/png")


@router.get("/audit")
async def list_audit(
    action: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(AuditLog).filter(AuditLog.user_id == user.id)
    if action:
        query = query.filter(AuditLog.action == action)
    rows = query.order_by(AuditLog.id.desc()).limit(limit).all()
    return {"count": len(rows), "entries": [r.to_dict() for r in rows]}
