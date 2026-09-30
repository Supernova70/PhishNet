"""Evidence custody: append-only hash chain + verification.

Chain rules
-----------
- Rows are append-only (no update/delete helpers exist).
- `prev_hash` of row N is `row_hash` of row N-1; the genesis row
  chains from GENESIS_HASH.
- `row_hash = sha256(canonical payload over the row's own fields)`,
  so any field edit breaks recomputation, and any row deletion or
  reordering breaks the prev/row link.
"""

import hashlib
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.models.evidence import EvidenceChain

GENESIS_HASH = "0" * 64

# ── audit helpers (kept here so compliance writes live together) ──────
from app.models.audit_log import AuditLog  # noqa: E402


def _row_payload(
    *,
    email_id: Optional[int],
    scan_id: Optional[int],
    raw_sha256: Optional[str],
    report_sha256: Optional[str],
    created_at: datetime,
    actor: str,
    prev_hash: str,
) -> str:
    return "\n".join(
        [
            str(email_id or ""),
            str(scan_id or ""),
            raw_sha256 or "",
            report_sha256 or "",
            created_at.isoformat(timespec="microseconds"),
            actor,
            prev_hash,
        ]
    )


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def chain_tip_hash(db: Session) -> str:
    last = (
        db.query(EvidenceChain)
        .order_by(EvidenceChain.id.desc())
        .first()
    )
    return last.row_hash if last else GENESIS_HASH


def append_evidence(
    db: Session,
    *,
    email_id: Optional[int],
    scan_id: Optional[int],
    raw_sha256: Optional[str] = None,
    report_sha256: Optional[str] = None,
    actor: str = "system",
    now: Optional[datetime] = None,
) -> EvidenceChain:
    """Append one row to the custody chain and flush (caller commits)."""
    now = now or datetime.utcnow()
    prev = chain_tip_hash(db)
    row = EvidenceChain(
        email_id=email_id,
        scan_id=scan_id,
        raw_sha256=raw_sha256,
        report_sha256=report_sha256,
        created_at=now,
        actor=actor,
        prev_hash=prev,
        row_hash="",  # filled below once created_at is final
    )
    db.add(row)
    db.flush()
    row.row_hash = _sha256(
        _row_payload(
            email_id=row.email_id,
            scan_id=row.scan_id,
            raw_sha256=row.raw_sha256,
            report_sha256=row.report_sha256,
            created_at=row.created_at,
            actor=row.actor,
            prev_hash=row.prev_hash,
        )
    )
    db.flush()
    return row


def _recompute(row: EvidenceChain) -> str:
    return _sha256(
        _row_payload(
            email_id=row.email_id,
            scan_id=row.scan_id,
            raw_sha256=row.raw_sha256,
            report_sha256=row.report_sha256,
            created_at=row.created_at,
            actor=row.actor,
            prev_hash=row.prev_hash,
        )
    )


def verify_chain(db: Session) -> dict:
    """Walk every row from genesis; report the first broken link."""
    rows = db.query(EvidenceChain).order_by(EvidenceChain.id.asc()).all()
    prev = GENESIS_HASH
    for row in rows:
        if row.prev_hash != prev:
            return {
                "valid": False,
                "checked": len(rows),
                "broken_id": row.id,
                "reason": "prev_hash does not match previous row_hash",
            }
        if _recompute(row) != row.row_hash:
            return {
                "valid": False,
                "checked": len(rows),
                "broken_id": row.id,
                "reason": "row_hash does not match row contents",
            }
        prev = row.row_hash
    return {"valid": True, "checked": len(rows), "broken_id": None, "reason": None}


def verify_evidence(db: Session, evidence_id: int) -> Optional[dict]:
    """Verify one row (contents + link) plus the integrity of the whole chain."""
    row = db.query(EvidenceChain).filter(EvidenceChain.id == evidence_id).first()
    if row is None:
        return None
    row_ok = _recompute(row) == row.row_hash
    predecessor = (
        db.query(EvidenceChain)
        .filter(EvidenceChain.id < row.id)
        .order_by(EvidenceChain.id.desc())
        .first()
    )
    expected_prev = predecessor.row_hash if predecessor else GENESIS_HASH
    link_ok = row.prev_hash == expected_prev
    chain = verify_chain(db)
    return {
        "evidence": row.to_dict(),
        "row_hash_ok": row_ok,
        "link_ok": link_ok,
        "chain": chain,
        "valid": bool(row_ok and link_ok and chain["valid"]),
    }


def audit(
    db: Session,
    action: str,
    *,
    actor: str = "system",
    entity_type: Optional[str] = None,
    entity_id: Optional[int] = None,
    detail: Optional[dict] = None,
    commit: bool = True,
) -> AuditLog:
    """Append an audit row (committed immediately — access is recorded
    even if the surrounding request later fails)."""
    entry = AuditLog(
        actor=actor,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        detail_json=detail,
    )
    db.add(entry)
    if commit:
        db.commit()
        db.refresh(entry)
    return entry
