"""
Phishing Guard V2 — Application Factory

Creates and configures the FastAPI application.
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
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

    # Reset any scans stuck in RUNNING state from a previous crash/restart
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
        db.close()
    except Exception as e:
        logger.error("Failed to reset stuck scans: %s", e)

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

    # Mount API routes
    app.include_router(api_router)

    # Browser evidence is read-only and lives outside the frontend bundle.
    app.mount(
        "/artifacts/url-screenshots",
        StaticFiles(directory=settings.DYNAMIC_URL_SCREENSHOT_DIR, check_dir=False),
        name="url-screenshots",
    )

    return app


# Create the app instance (used by uvicorn)
app = create_app()
