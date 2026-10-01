"""Global alert feed API.

`GET /alerts` powers the bell dropdown and `/alerts` page;
`POST /alerts/{id}/read` and `POST /alerts/read-all` persist read
state so unread counts survive reloads.
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.dependencies import get_current_user, get_db, owned_or_404
from app.models.alert import Alert
from app.models.user import User

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("")
async def list_alerts(
    unread: bool = Query(False, description="Only unread alerts"),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(Alert).filter(Alert.user_id == user.id)
    total = query.count()
    unread_count = query.filter(Alert.read_at.is_(None)).count()
    if unread:
        query = query.filter(Alert.read_at.is_(None))
    rows = query.order_by(Alert.created_at.desc()).limit(limit).all()
    return {
        "count": len(rows),
        "total": total,
        "unread": unread_count,
        "alerts": [r.to_dict() for r in rows],
    }


@router.post("/{alert_id}/read")
async def mark_read(
    alert_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    alert = db.get(Alert, alert_id)
    owned_or_404(alert, user)
    if alert.read_at is None:
        alert.read_at = datetime.utcnow()
        db.commit()
    return alert.to_dict()


@router.post("/read-all")
async def mark_all_read(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    updated = (
        db.query(Alert)
        .filter(Alert.user_id == user.id, Alert.read_at.is_(None))
        .update({Alert.read_at: datetime.utcnow()}, synchronize_session=False)
    )
    db.commit()
    return {"marked": updated}
