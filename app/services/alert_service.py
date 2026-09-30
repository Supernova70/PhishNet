"""Alert creation: decides whether a finished scan raises a feed entry."""

from datetime import datetime
from typing import List, Optional

from app.models.alert import Alert

HIGH_RISK_SCORE = 70.0
BEC_CATEGORY_SCORE = 40.0


def alert_reasons(score: float, breakdown: Optional[dict]) -> List[str]:
    """Every trigger that fired for this scan (empty → no alert)."""
    breakdown = breakdown or {}
    reasons: List[str] = []

    if score >= HIGH_RISK_SCORE:
        reasons.append("high_risk")

    header = breakdown.get("header") or {}
    auth = header.get("auth") or {}
    flags = [str(f).lower() for f in (header.get("flags") or [])]
    spoofed = (
        auth.get("spf_result") == "fail"
        or auth.get("dmarc_result") == "fail"
        or any("display name" in f or "spoof" in f for f in flags)
    )
    if spoofed:
        reasons.append("spoof")

    bec = ((breakdown.get("ai") or {}).get("bec")) or {}
    top = max(
        (c.get("confidence", 0) for c in bec.get("categories", [])),
        default=0.0,
    )
    if top >= BEC_CATEGORY_SCORE:
        reasons.append("bec")

    return reasons


def build_alert(
    *,
    scan_id: int,
    email_id: Optional[int],
    score: float,
    classification: str,
    breakdown: Optional[dict],
    subject: Optional[str],
    sender: Optional[str],
    now: Optional[datetime] = None,
) -> Optional[Alert]:
    """Return an Alert row when a trigger fired, else None."""
    reasons = alert_reasons(score, breakdown)
    if not reasons:
        return None
    return Alert(
        scan_id=scan_id,
        email_id=email_id,
        score=score,
        classification=classification,
        reasons=reasons,
        subject=subject,
        sender=sender,
        created_at=now or datetime.utcnow(),
    )
