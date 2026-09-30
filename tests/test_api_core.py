"""Core API tests: health, settings, emails, scans, attachments.
SQLite + isolated FastAPI apps, offline."""

from datetime import datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch

from app.api.attachments import router as attachments_router
from app.api.email import router as email_router
from app.api.health import router as health_router
from app.api.scan import router as scan_router
from app.api.settings import router as settings_router
from app.dependencies import get_db
from app.models import Base
from app.models.email import Attachment, Email
from app.models.scan import Scan, ScanStatus, Verdict

# ── shared fixture ────────────────────────────────────────────────────

@pytest.fixture()
def env(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/core.db")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    app = FastAPI()
    app.include_router(health_router)
    app.include_router(email_router)
    app.include_router(scan_router)
    app.include_router(attachments_router)
    app.include_router(settings_router)
    app.dependency_overrides[get_db] = lambda: session
    yield {"app": app, "client": TestClient(app), "db": session}
    session.close()


def seed(env):
    db = env["db"]
    email = Email(
        message_id="<core-1>",
        sender="a@example.org", subject="Quarterly report",
        body_text="body", fetched_at=datetime(2026, 1, 3, 8, 0),
    )
    db.add(email)
    db.flush()
    db.add(Attachment(
        email_id=email.id, filename="report.pdf",
        content_type="application/pdf", size_bytes=2048,
        sha256_hash="cd" * 32, storage_path=None,
    ))
    scan = Scan(email_id=email.id, status=ScanStatus.COMPLETE.value,
                completed_at=datetime(2026, 1, 3, 8, 5))
    db.add(scan)
    db.flush()
    db.add(Verdict(scan_id=scan.id, final_score=35.0,
                   classification="suspicious", ai_score=40.0))
    db.commit()
    return email, scan


# ── health ────────────────────────────────────────────────────────────

class TestHealth:
    def test_health_returns_200(self, env):
        resp = env["client"].get("/health")
        assert resp.status_code == 200
        assert "status" in resp.json()


# ── emails ────────────────────────────────────────────────────────────

class TestEmailEndpoints:
    def test_list_emails(self, env):
        seed(env)
        data = env["client"].get("/emails").json()
        assert data["total"] == 1
        assert data["emails"][0]["subject"] == "Quarterly report"

    def test_list_emails_includes_latest_scan_status(self, env):
        seed(env)
        data = env["client"].get("/emails").json()
        row = data["emails"][0]
        assert row["scan_count"] == 1
        assert row["latest_scan_status"] == "complete"
        assert row["latest_scan_classification"] == "suspicious"
        assert row["latest_scan_score"] == 35.0

    def test_list_emails_unscanned_has_null_status(self, env):
        db = env["db"]
        db.add(Email(
            message_id="<core-2>", sender="b@example.org",
            subject="No scan yet", fetched_at=datetime(2026, 1, 3, 9, 0),
        ))
        db.commit()
        data = env["client"].get("/emails").json()
        row = data["emails"][0]
        assert row["scan_count"] == 0
        assert row["latest_scan_status"] is None
        assert row["latest_scan_classification"] is None
        assert row["latest_scan_score"] is None

    def test_email_detail(self, env):
        email, _ = seed(env)
        data = env["client"].get(f"/emails/{email.id}").json()
        assert data["message_id"] == "<core-1>"
        assert data["body_text"] == "body"
        assert len(data["attachments"]) == 1

    def test_email_detail_404(self, env):
        assert env["client"].get("/emails/999").status_code == 404

    def test_latest_scan(self, env):
        email, scan = seed(env)
        data = env["client"].get(f"/emails/{email.id}/latest-scan").json()
        assert data["id"] == scan.id

    def test_latest_scan_none(self, env):
        email, scan = seed(env)
        db = env["db"]
        db.query(Scan).delete()
        db.commit()
        data = env["client"].get(f"/emails/{email.id}/latest-scan").json()
        assert data == {"scan": None}

    def test_latest_scan_404(self, env):
        assert (
            env["client"].get("/emails/999/latest-scan").status_code == 404
        )


# ── scans ─────────────────────────────────────────────────────────────

class TestScanEndpoints:
    def test_list_scans(self, env):
        _, scan = seed(env)
        data = env["client"].get("/scans").json()
        assert data["total"] == 1
        assert data["scans"][0]["id"] == scan.id

    def test_list_scans_filter_classification(self, env):
        seed(env)
        data = env["client"].get("/scans?classification=dangerous").json()
        assert data["total"] == 0
        data = env["client"].get("/scans?classification=suspicious").json()
        assert data["total"] == 1

    def test_scan_detail(self, env):
        _, scan = seed(env)
        data = env["client"].get(f"/scans/{scan.id}").json()
        assert data["id"] == scan.id
        assert data["status"] == "complete"

    def test_scan_detail_404(self, env):
        assert env["client"].get("/scans/999").status_code == 404

    def test_csv_export(self, env):
        _, scan = seed(env)
        resp = env["client"].get("/scans/export/csv")
        assert resp.status_code == 200
        body = resp.text
        assert "Quarterly report" in body
        assert "suspicious" in body

    def test_csv_export_filter(self, env):
        seed(env)
        body = env["client"].get("/scans/export/csv?classification=dangerous").text
        assert "Quarterly report" not in body


# ── attachments ───────────────────────────────────────────────────────

class TestAttachmentEndpoints:
    def test_list_attachments(self, env):
        email, _ = seed(env)
        data = env["client"].get(f"/attachments?email_id={email.id}").json()
        assert data["total"] == 1
        assert data["attachments"][0]["filename"] == "report.pdf"

    def test_attachment_detail_404(self, env):
        assert env["client"].get("/attachments/999").status_code == 404


# ── settings ──────────────────────────────────────────────────────────

class TestSettingsEndpoints:
    def test_get_settings(self, env):
        data = env["client"].get("/settings").json()
        assert "scan_threshold" in data
        assert "vt_configured" in data
        assert data["vt_key_preview"]

    def test_put_settings_updates_env_without_touching_dotenv(self, env,
                                                              monkeypatch):
        monkeypatch.setenv("SCAN_THRESHOLD", "40")
        with patch("app.api.settings.os.path.exists", return_value=False):
            data = env["client"].put(
                "/settings", json={"scan_threshold": 55}
            ).json()
        assert data["scan_threshold"] == 55
        assert env["client"].get("/settings").json()["scan_threshold"] == 55

    def test_api_key_update(self, env, monkeypatch):
        monkeypatch.delenv("VT_API_KEY", raising=False)
        with patch("app.api.settings.os.path.exists", return_value=False):
            data = env["client"].post(
                "/settings/api-keys",
                json={"provider": "virustotal", "api_key": "abcdefghijklmnop"},
            ).json()
        assert data["configured"] is True
        assert data["preview"] == "abcd...mnop"

    def test_api_key_unknown_provider_400(self, env):
        resp = env["client"].post(
            "/settings/api-keys",
            json={"provider": "nope", "api_key": "x"},
        )
        assert resp.status_code == 400
