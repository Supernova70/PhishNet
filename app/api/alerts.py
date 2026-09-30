"""Global alert feed API.

`GET /alerts` powers the bell dropdown and `/alerts` page;
`POST /alerts/{id}/read` and `POST /alerts/read-all` persist read
state so unread counts survive reloads.
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.models.alert import Alert

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("")
async def list_alerts(
    unread: bool = Query(False, description="Only unread alerts"),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    query = db.query(Alert)
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
async def mark_read(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.read_at is None:
        alert.read_at = datetime.utcnow()
        db.commit()
    return alert.to_dict()


@router.post("/read-all")
async def mark_all_read(db: Session = Depends(get_db)):
    updated = (
        db.query(Alert)
        .filter(Alert.read_at.is_(None))
        .update({Alert.read_at: datetime.utcnow()}, synchronize_session=False)
    )
    db.commit()
    return {"marked": updated}
