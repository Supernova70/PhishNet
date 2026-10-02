"""Health check endpoint for storage and analysis-engine configuration."""

import time
import logging
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dependencies import engine, get_db
from app.integrations.virustotal import VirusTotalClient
from app.permissions import optional_permissions

logger = logging.getLogger(__name__)
router = APIRouter(tags=["System"])


@router.get("/health")
async def health_check(request: Request, db: Session = Depends(get_db)):
    """System health check — always 200 for LB probes.

    Anonymous / unpermitted callers get the slim contract
    ``{status, version, response_time_ms}`` (enough for probes and the
    backend-offline banner). The ``components`` block (VT rotation stats,
    key counts, model path, DB detail) is revealed only to holders of the
    ``system.health`` permission.
    """
    settings = get_settings()
    overall = "ok"
    start = time.time()

    # ── 1. Database Check ─────────────────────────────────────────────
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        db_status = "connected"
        db_detail = "PostgreSQL connection successful"
    except Exception as e:
        db_status = "error"
        db_detail = str(e)[:100]
        overall = "degraded"
        logger.warning(f"Health check — DB error: {e}")

    # ── 2. ML Model Check ─────────────────────────────────────────────
    try:
        model_path = Path(settings.MODEL_PATH)
        if model_path.exists():
            ml_status = "loaded"
            ml_detail = f"Model loaded at {model_path}"
        else:
            ml_status = "not_loaded"
            ml_detail = f"Model file not found at {model_path}"
            overall = "degraded"
    except Exception as e:
        ml_status = "not_loaded"
        ml_detail = str(e)[:100]
        overall = "degraded"
        logger.warning(f"Health check — ML model error: {e}")

    # ── 3. VirusTotal detail (system.health only) ──────────────────────
    detailed = "system.health" in optional_permissions(request, db)
    response_time_ms = round((time.time() - start) * 1000)
    body: dict = {
        "status": overall,
        "version": settings.APP_VERSION,
        "response_time_ms": response_time_ms,
    }
    if not detailed:
        return body

    vt_keys = settings.vt_api_keys
    vt_status = "configured" if vt_keys else "not_configured"
    vt_detail = (
        f"{len(vt_keys)} API key(s) loaded; credentials are validated on lookup"
        if vt_keys
        else "No API keys — set VIRUSTOTAL_API_KEYS in .env"
    )
    vt_rotation = VirusTotalClient(keys=vt_keys).status() if vt_keys else None
    if vt_rotation:
        vt_detail = (
            f"{vt_rotation['available']}/{vt_rotation['key_count']} key(s) ready"
            + (f", {vt_rotation['cooling_down']} cooling down" if vt_rotation["cooling_down"] else "")
            + (f", {vt_rotation['invalid']} invalid" if vt_rotation["invalid"] else "")
        )

    body["components"] = {
        "database": {
            "status": db_status,
            "detail": db_detail,
        },
        "ml_model": {
            "status": ml_status,
            "detail": ml_detail,
        },
        "virustotal": {
            "status": vt_status,
            "key_count": len(vt_keys),
            "rotation": vt_rotation,
            "detail": vt_detail,
        },
        "dynamic_url": {
            "status": "enabled" if settings.DYNAMIC_URL_ENABLED else "disabled",
            "max_per_scan": settings.DYNAMIC_URL_MAX_PER_SCAN,
            "screenshot_dir": settings.DYNAMIC_URL_SCREENSHOT_DIR,
            "detail": (
                "Policy-gated Chromium analysis is enabled"
                if settings.DYNAMIC_URL_ENABLED
                else "Static URL analysis only; set DYNAMIC_URL_ENABLED=true to opt in"
            ),
        },
    }
    return body
