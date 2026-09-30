"""Platform hardening tests: retention purge, global SSE feed,
ApiKeyMiddleware. Offline."""

import asyncio
import json
import os
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch

from app.api.scan import (
    _global_event_generator,
    _global_subscribers,
    publish_scan_event,
)
from app.config import get_settings
from app.dependencies import get_db
from app.middleware.auth import ApiKeyMiddleware
from app.models import Base
from app.models.audit_log import AuditLog
from app.models.email import Email
from app.models.email_source import EmailSource
from app.models.ip_intel import IpIntel
from app.models.scan import Scan, Verdict
from app.services.retention import purge


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/ret.db")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _settings_for(retention_days=90, screenshot_dir="."):
    return type("S", (), {
        "RETENTION_DAYS": retention_days,
        "DYNAMIC_URL_SCREENSHOT_DIR": str(screenshot_dir),
    })()


def _seed_email(db, *, fetched_at, raw_path=None):
    email = Email(
        message_id=f"<r-{fetched_at.timestamp()}>",
        sender="a@b.co", subject="s",
        fetched_at=fetched_at,
    )
    db.add(email)
    db.flush()
    if raw_path is not None:
        db.add(EmailSource(
            email_id=email.id, raw_path=str(raw_path),
            raw_sha256="ab" * 32, size_bytes=10, headers_json={},
        ))
    scan = Scan(email_id=email.id, status="complete",
                completed_at=fetched_at)
    db.add(scan)
    db.flush()
    db.add(Verdict(scan_id=scan.id, final_score=90.0, classification="dangerous"))
    db.commit()
    return email


# ── retention ─────────────────────────────────────────────────────────

class TestRetentionPurge:
    def test_old_raw_file_deleted_verdict_kept(self, db, tmp_path):
        old = datetime.utcnow() - timedelta(days=120)
        raw = tmp_path / "old.eml.gz"
        raw.write_bytes(b"gz")
        email = _seed_email(db, fetched_at=old, raw_path=raw)
        shot_dir = tmp_path / "shots"
        shot_dir.mkdir()

        with patch("app.services.retention.get_settings",
                   return_value=_settings_for(90, shot_dir)):
            summary = purge(db)

        assert summary["raw_files_deleted"] == 1
        assert summary["raw_paths_cleared"] == 1
        assert not raw.exists()
        assert email.source.raw_path is None          # headers JSON retained
        assert email.source.raw_sha256 == "ab" * 32
        # verdicts untouched by default
        assert db.query(Verdict).count() == 1
        # audit row written
        entry = db.query(AuditLog).filter_by(action="retention_purge").one()
        assert entry.actor == "retention"

    def test_fresh_email_untouched(self, db, tmp_path):
        fresh = datetime.utcnow() - timedelta(days=2)
        raw = tmp_path / "fresh.eml.gz"
        raw.write_bytes(b"gz")
        _seed_email(db, fetched_at=fresh, raw_path=raw)
        with patch("app.services.retention.get_settings",
                   return_value=_settings_for(90, tmp_path / "none")):
            summary = purge(db)
        assert summary["raw_files_deleted"] == 0
        assert raw.exists()
        assert db.query(AuditLog).count() == 0

    def test_dry_run_deletes_nothing(self, db, tmp_path):
        old = datetime.utcnow() - timedelta(days=120)
        raw = tmp_path / "old.eml.gz"
        raw.write_bytes(b"gz")
        _seed_email(db, fetched_at=old, raw_path=raw)
        with patch("app.services.retention.get_settings",
                   return_value=_settings_for(90, tmp_path / "none")):
            summary = purge(db, dry_run=True)
        assert summary["dry_run"] is True
        assert summary["raw_files_deleted"] == 1  # counted…
        assert raw.exists()                        # …but not deleted
        assert db.query(AuditLog).count() == 0

    def test_include_verdicts_deletes_verdicts(self, db, tmp_path):
        old = datetime.utcnow() - timedelta(days=120)
        _seed_email(db, fetched_at=old)
        with patch("app.services.retention.get_settings",
                   return_value=_settings_for(90, tmp_path / "none")):
            summary = purge(db, include_verdicts=True)
        assert summary["verdicts_deleted"] == 1
        assert db.query(Verdict).count() == 0

    def test_expired_ip_intel_cache_purged(self, db, tmp_path):
        db.add(IpIntel(ip="203.0.113.9", country="X",
                       fetched_at=datetime(2020, 1, 1),
                       expires_at=datetime(2021, 1, 1)))
        db.add(IpIntel(ip="203.0.113.8", country="Y",
                       fetched_at=datetime.utcnow(),
                       expires_at=datetime.utcnow() + timedelta(days=30)))
        db.commit()
        with patch("app.services.retention.get_settings",
                   return_value=_settings_for(90, tmp_path / "none")):
            summary = purge(db)
        assert summary["ip_intel_rows_deleted"] == 1
        assert db.query(IpIntel).count() == 1

    def test_old_screenshots_deleted(self, db, tmp_path):
        shot_dir = tmp_path / "shots"
        (shot_dir / "7").mkdir(parents=True)
        old_shot = shot_dir / "7" / "a.png"
        old_shot.write_bytes(b"png")
        os.utime(old_shot, (datetime(2020, 1, 1).timestamp(),) * 2)
        with patch("app.services.retention.get_settings",
                   return_value=_settings_for(90, shot_dir)):
            summary = purge(db)
        assert summary["screenshots_deleted"] == 1
        assert not old_shot.exists()


# ── global SSE feed ───────────────────────────────────────────────────

class TestGlobalSse:
    def test_terminal_event_reaches_global_subscribers(self):
        q = asyncio.Queue(maxsize=10)
        _global_subscribers.append(q)
        try:
            publish_scan_event(1, {"type": "complete", "scan_id": 1,
                                   "final_score": 55.0})
            assert q.get_nowait()["type"] == "complete"
        finally:
            _global_subscribers.remove(q)

    def test_incomplete_low_risk_not_broadcast(self):
        q = asyncio.Queue(maxsize=10)
        _global_subscribers.append(q)
        try:
            publish_scan_event(1, {"type": "started", "scan_id": 1,
                                   "final_score": 0})
            assert q.empty()
        finally:
            _global_subscribers.remove(q)

    def test_error_event_broadcast(self):
        q = asyncio.Queue(maxsize=10)
        _global_subscribers.append(q)
        try:
            publish_scan_event(3, {"type": "error", "scan_id": 3})
            assert q.get_nowait()["type"] == "error"
        finally:
            _global_subscribers.remove(q)

    def test_generator_emits_connected_then_events(self):
        async def run():
            q = asyncio.Queue(maxsize=10)
            gen = _global_event_generator(q)
            first = await gen.__anext__()
            assert '"scope": "global"' in first
            q.put_nowait({"type": "complete", "scan_id": 9, "final_score": 80})
            second = await gen.__anext__()
            await gen.aclose()
            return second

        second = asyncio.run(run())
        payload = json.loads(second.removeprefix("data: ").strip())
        assert payload["scan_id"] == 9

    def test_route_registered(self):
        from app.main import app as main_app

        client = TestClient(main_app)
        paths = client.get("/openapi.json").json()["paths"]
        assert "/scans/events" in paths
        assert "/scans/{scan_id}/events" in paths


# ── API key middleware ────────────────────────────────────────────────

def _mw_names(app) -> list:
    """Middleware class names from Starlette's user_middleware."""
    names = []
    for m in app.user_middleware:
        cls = getattr(m, "cls", None)
        names.append(cls.__name__ if isinstance(cls, type) else type(m).__name__)
    return names


def _build_protected_app():
    app = FastAPI()

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    @app.get("/health")
    async def health():
        return {"status": "up"}

    app.add_middleware(ApiKeyMiddleware)
    return app


class TestApiKeyMiddleware:
    def test_missing_key_rejected(self):
        client = TestClient(_build_protected_app())
        with patch("app.middleware.auth.get_settings",
                   return_value=type("S", (), {"API_KEYS": "k1,k2"})()):
            assert client.get("/ping").status_code == 401

    def test_valid_key_accepted(self):
        client = TestClient(_build_protected_app())
        with patch("app.middleware.auth.get_settings",
                   return_value=type("S", (), {"API_KEYS": "k1,k2"})()):
            resp = client.get("/ping", headers={"X-API-Key": "k2"})
            assert resp.status_code == 200

    def test_wrong_key_rejected(self):
        client = TestClient(_build_protected_app())
        with patch("app.middleware.auth.get_settings",
                   return_value=type("S", (), {"API_KEYS": "k1"})()):
            resp = client.get("/ping", headers={"X-API-Key": "nope"})
            assert resp.status_code == 401

    def test_health_exempt(self):
        client = TestClient(_build_protected_app())
        with patch("app.middleware.auth.get_settings",
                   return_value=type("S", (), {"API_KEYS": "k1"})()):
            assert client.get("/health").status_code == 200

    def test_no_keys_configured_passes_through(self):
        client = TestClient(_build_protected_app())
        with patch("app.middleware.auth.get_settings",
                   return_value=type("S", (), {"API_KEYS": ""})()):
            assert client.get("/ping").status_code == 200

    def test_registration_gated_on_api_keys(self):
        """create_app() adds the middleware only when API_KEYS is set."""
        from app.main import create_app

        os.environ["API_KEYS"] = "sekret"
        get_settings.cache_clear()
        try:
            app = create_app()
            assert "ApiKeyMiddleware" in _mw_names(app)
        finally:
            del os.environ["API_KEYS"]
            get_settings.cache_clear()

        app = create_app()  # restored default
        assert "ApiKeyMiddleware" not in _mw_names(app)
