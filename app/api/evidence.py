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
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.models.audit_log import AuditLog
from app.models.email import Email
from app.models.evidence import EvidenceChain
from app.services.evidence_service import audit, verify_evidence

router = APIRouter()


@router.get("/emails/{email_id}/evidence/raw")
async def download_raw_evidence(email_id: int, db: Session = Depends(get_db)):
    """Stream the retained raw message (gzipped). Every access is
    written to the append-only audit log."""
    email = db.get(Email, email_id)
    if email is None:
        raise HTTPException(status_code=404, detail="Email not found")
    source = email.source
    if source is None or not source.raw_path:
        raise HTTPException(status_code=404, detail="Raw evidence not retained")
    path = Path(source.raw_path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Evidence file missing on disk")

    audit(
        db,
        "raw_view",
        actor="api",
        entity_type="email",
        entity_id=email.id,
        detail={"path": str(path), "sha256": source.raw_sha256},
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
):
    query = db.query(EvidenceChain)
    if email_id is not None:
        query = query.filter(EvidenceChain.email_id == email_id)
    if scan_id is not None:
        query = query.filter(EvidenceChain.scan_id == scan_id)
    rows = query.order_by(EvidenceChain.id.desc()).limit(limit).all()
    return {"count": len(rows), "evidence": [r.to_dict() for r in rows]}


@router.get("/evidence/{evidence_id}/verify")
async def verify_evidence_endpoint(evidence_id: int, db: Session = Depends(get_db)):
    result = verify_evidence(db, evidence_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Evidence row not found")
    audit(
        db,
        "evidence_verify",
        actor="api",
        entity_type="evidence",
        entity_id=evidence_id,
        detail={"valid": result["valid"]},
    )
    return result


@router.get("/audit")
async def list_audit(
    action: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)
    rows = query.order_by(AuditLog.id.desc()).limit(limit).all()
    return {"count": len(rows), "entries": [r.to_dict() for r in rows]}
