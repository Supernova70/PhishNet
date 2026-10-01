"""
Phishing Guard V2 — Application Factory

Creates and configures the FastAPI application.
"""

import logging
import threading
from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.config import get_settings
from app.api.router import api_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    settings = get_settings()
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info("Schema managed by Alembic — run: alembic upgrade head")

    # Recover from a previous crash/restart:
    #   1. RUNNING rows are orphans (their thread died with the old process)
    #      → mark them ERROR.  (This block previously crashed with
    #      NameError: datetime is not defined, so stuck scans never reset.)
    #   2. PENDING rows were queued by bulk-scan but their background task
    #      died with the old process → requeue them, otherwise they sit
    #      "pending" forever. run_scan_by_id's atomic claim keeps the two
    #      uvicorn workers from processing the same scan twice.
    try:
        from app.dependencies import SessionLocal
        from app.models.scan import Scan, ScanStatus
        db = SessionLocal()
        stuck = (
            db.query(Scan)
            .filter(Scan.status == ScanStatus.RUNNING.value)
            .all()
        )
        if stuck:
            for scan in stuck:
                scan.status = ScanStatus.ERROR.value
                scan.completed_at = datetime.utcnow()
            db.commit()
            logger.warning("Reset %d stuck RUNNING scan(s) to ERROR on startup", len(stuck))

        orphaned = [
            sid
            for (sid,) in db.query(Scan.id)
            .filter(Scan.status == ScanStatus.PENDING.value)
            .order_by(Scan.id)
            .limit(500)
            .all()
        ]
        db.close()
        if orphaned:
            logger.warning("Requeueing %d orphaned PENDING scan(s) on startup", len(orphaned))
            from app.api.email import _run_bulk_scan_task
            threading.Thread(
                target=_run_bulk_scan_task,
                args=(orphaned,),
                daemon=True,
                name="startup-scan-requeue",
            ).start()
    except Exception as e:
        logger.error("Failed to recover stuck/pending scans: %s", e)

    yield
    logger.info("Shutting down")


def create_app() -> FastAPI:
    """Build and return the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="Email phishing detection system with ML-based analysis",
        lifespan=lifespan,
    )

    # CORS — allow Vite dev server and any localhost origin
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # API key auth — active only when API_KEYS is configured
    if settings.API_KEYS:
        from app.middleware.auth import ApiKeyMiddleware

        app.add_middleware(ApiKeyMiddleware)
        logger.info("ApiKeyMiddleware enabled (%d key(s))",
                    len([k for k in settings.API_KEYS.split(",") if k.strip()]))

    # Mount API routes
    app.include_router(api_router)

    return app


# Create the app instance (used by uvicorn)
app = create_app()
