"""Settings & configuration API endpoints."""

import os
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.dependencies import get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/settings", tags=["Settings"])


# ── Schemas ────────────────────────────────────────────────

class SystemConfig(BaseModel):
    vt_configured: bool
    vt_key_preview: str
    gs_browsing_configured: bool
    dynamic_url_analysis_enabled: bool
    auto_scan_enabled: bool
    scan_threshold: int
    max_concurrent_scans: int
    yara_enabled: bool
    ml_model_loaded: bool


class UpdateSettingsRequest(BaseModel):
    auto_scan_enabled: Optional[bool] = None
    scan_threshold: Optional[int] = None
    max_concurrent_scans: Optional[int] = None
    dynamic_url_analysis_enabled: Optional[bool] = None


class ApiKeyUpdate(BaseModel):
    provider: str  # "virustotal" or "gsbrowsing"
    api_key: str


class ApiKeyResponse(BaseModel):
    provider: str
    configured: bool
    preview: str
    message: str


# ── Endpoints ──────────────────────────────────────────────

@router.get("", response_model=SystemConfig)
async def get_settings():
    """Get current system configuration."""
    vt_key = os.environ.get("VT_API_KEY", "")
    gsb_key = os.environ.get("GSBROWSING_API_KEY", "")
    ml_path = os.environ.get("ML_MODEL_PATH", "")

    return SystemConfig(
        vt_configured=bool(vt_key and vt_key != "YOUR_VT_API_KEY"),
        vt_key_preview=f"{vt_key[:4]}...{vt_key[-4:]}" if len(vt_key) > 8 else "Not set",
        gs_browsing_configured=bool(gsb_key and gsb_key != "YOUR_GSBROWSING_API_KEY"),
        dynamic_url_analysis_enabled=os.environ.get("DYNAMIC_URL_ANALYSIS_ENABLED", "false").lower() == "true",
        auto_scan_enabled=os.environ.get("AUTO_SCAN_ENABLED", "true").lower() == "true",
        scan_threshold=int(os.environ.get("SCAN_THRESHOLD", "40")),
        max_concurrent_scans=int(os.environ.get("MAX_CONCURRENT_SCANS", "3")),
        yara_enabled=os.environ.get("YARA_ENABLED", "true").lower() == "true",
        ml_model_loaded=bool(ml_path and os.path.exists(ml_path)),
    )


@router.put("", response_model=SystemConfig)
async def update_settings(req: UpdateSettingsRequest):
    """Update runtime settings (persisted to .env file)."""
    env_path = os.path.join(os.path.dirname(__file__), "..", "..", ".env")

    updates = {}
    if req.auto_scan_enabled is not None:
        updates["AUTO_SCAN_ENABLED"] = str(req.auto_scan_enabled).lower()
        os.environ["AUTO_SCAN_ENABLED"] = str(req.auto_scan_enabled).lower()
    if req.scan_threshold is not None:
        updates["SCAN_THRESHOLD"] = str(req.scan_threshold)
        os.environ["SCAN_THRESHOLD"] = str(req.scan_threshold)
    if req.max_concurrent_scans is not None:
        updates["MAX_CONCURRENT_SCANS"] = str(req.max_concurrent_scans)
        os.environ["MAX_CONCURRENT_SCANS"] = str(req.max_concurrent_scans)
    if req.dynamic_url_analysis_enabled is not None:
        updates["DYNAMIC_URL_ANALYSIS_ENABLED"] = str(req.dynamic_url_analysis_enabled).lower()
        os.environ["DYNAMIC_URL_ANALYSIS_ENABLED"] = str(req.dynamic_url_analysis_enabled).lower()

    if updates:
        try:
            if os.path.exists(env_path):
                with open(env_path, "r") as f:
                    lines = f.readlines()
                with open(env_path, "w") as f:
                    written_keys = set()
                    for line in lines:
                        key = line.split("=")[0].strip()
                        if key in updates:
                            f.write(f"{key}={updates[key]}\n")
                            written_keys.add(key)
                        else:
                            f.write(line)
                    for key, val in updates.items():
                        if key not in written_keys:
                            f.write(f"{key}={val}\n")
        except Exception as e:
            logger.warning(f"Failed to persist settings to .env: {e}")

    return await get_settings()


@router.post("/api-keys", response_model=ApiKeyResponse)
async def update_api_key(req: ApiKeyUpdate):
    """Update an API key for an external service."""
    env_path = os.path.join(os.path.dirname(__file__), "..", "..", ".env")

    env_key_map = {
        "virustotal": "VT_API_KEY",
        "gsbrowsing": "GSBROWSING_API_KEY",
    }

    if req.provider not in env_key_map:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {req.provider}")

    env_var = env_key_map[req.provider]
    os.environ[env_var] = req.api_key

    # Persist to .env
    try:
        if os.path.exists(env_path):
            with open(env_path, "r") as f:
                lines = f.readlines()
            found = False
            with open(env_path, "w") as f:
                for line in lines:
                    if line.startswith(f"{env_var}="):
                        f.write(f"{env_var}={req.api_key}\n")
                        found = True
                    else:
                        f.write(line)
                if not found:
                    f.write(f"{env_var}={req.api_key}\n")
        else:
            with open(env_path, "w") as f:
                f.write(f"{env_var}={req.api_key}\n")
    except Exception as e:
        logger.warning(f"Failed to persist API key to .env: {e}")

    preview = f"{req.api_key[:4]}...{req.api_key[-4:]}" if len(req.api_key) > 8 else "Set"

    return ApiKeyResponse(
        provider=req.provider,
        configured=True,
        preview=preview,
        message=f"{req.provider} API key updated successfully",
    )
