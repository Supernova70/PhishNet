"""Alert tests: trigger rules, scan-time creation, feed API."""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.alerts import router as alerts_router
from app.dependencies import get_db
from app.engines.header_analyzer import HeaderAnalysisResult
from app.models import Base
from app.models.alert import Alert
from app.models.email import Email
from app.models.scan import Scan, Verdict
from app.services.alert_service import alert_reasons, build_alert
from app.services.scan_service import ScanService


# ── trigger rules (pure) ──────────────────────────────────────────────

class TestAlertReasons:
    def test_high_score_triggers(self):
        assert alert_reasons(75.0, {}) == ["high_risk"]

    def test_low_score_clean_no_alert(self):
        assert alert_reasons(10.0, {}) == []
        assert build_alert(
            scan_id=1, email_id=1, score=10.0, classification="safe",
            breakdown={}, subject="s", sender="f@x",
        ) is None

    def test_spf_fail_triggers_spoof(self):
        breakdown = {"header": {"auth": {"spf_result": "fail"}}}
        assert "spoof" in alert_reasons(20.0, breakdown)

    def test_dmarc_fail_triggers_spoof(self):
        breakdown = {"header": {"auth": {"dmarc_result": "fail"}}}
        assert "spoof" in alert_reasons(20.0, breakdown)

    def test_display_name_flag_triggers_spoof(self):
        breakdown = {"header": {"flags": ["Display name spoof: Bank"]}}
        assert "spoof" in alert_reasons(15.0, breakdown)

    def test_bec_category_triggers(self):
        breakdown = {"ai": {"bec": {"categories": [
            {"category": "payment_diversion", "confidence": 65.0},
        ]}}}
        assert "bec" in alert_reasons(30.0, breakdown)

    def test_subthreshold_bec_ignored(self):
        breakdown = {"ai": {"bec": {"categories": [
            {"category": "fake_invoice", "confidence": 30.0},
        ]}}}
        assert "bec" not in alert_reasons(30.0, breakdown)

    def test_multiple_reasons(self):
        breakdown = {
            "header": {"auth": {"spf_result": "fail"}},
            "ai": {"bec": {"categories": [
                {"category": "payment_diversion", "confidence": 70.0},
            ]}},
        }
        reasons = alert_reasons(90.0, breakdown)
        assert set(reasons) == {"high_risk", "spoof", "bec"}

    def test_build_alert_fields(self):
        alert = build_alert(
            scan_id=9, email_id=4, score=88.0, classification="dangerous",
            breakdown={"header": {"auth": {"spf_result": "fail"}}},
            subject="Urgent", sender="a@b.co",
        )
        assert alert is not None
        assert alert.scan_id == 9
        assert alert.reasons == ["high_risk", "spoof"]
        assert alert.subject == "Urgent"


# ── feed API ──────────────────────────────────────────────────────────

@pytest.fixture()
def env(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/alerts.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    app = FastAPI()
    app.include_router(alerts_router)
    app.dependency_overrides[get_db] = lambda: session
    yield {"client": TestClient(app), "db": session}
    session.close()


def seed(db, *, score, read=None, subject="hello"):
    email = Email(
        message_id=f"<a-{score}-{id(db)}-{subject}>",
        sender="x@y.co", subject=subject, fetched_at=datetime(2026, 1, 1),
    )
    db.add(email)
    db.flush()
    scan = Scan(email_id=email.id, status="complete",
                completed_at=datetime(2026, 1, 1))
    db.add(scan)
    db.flush()
    db.add(Alert(scan_id=scan.id, email_id=email.id, score=score,
                 classification="dangerous", reasons=["high_risk"],
                 subject=subject, sender="x@y.co", read_at=read))
    db.commit()
    return scan


class TestAlertsApi:
    def test_list_and_unread_count(self, env):
        seed(env["db"], score=90.0)
        seed(env["db"], score=80.0, read=datetime(2026, 1, 2))
        data = env["client"].get("/alerts").json()
        assert data["count"] == 2
        assert data["unread"] == 1

        unread = env["client"].get("/alerts?unread=true").json()
        assert unread["count"] == 1
        assert unread["alerts"][0]["read"] is False

    def test_empty(self, env):
        data = env["client"].get("/alerts").json()
        assert data == {"count": 0, "total": 0, "unread": 0, "alerts": []}

    def test_mark_read(self, env):
        scan = seed(env["db"], score=90.0)
        alert_id = env["client"].get("/alerts").json()["alerts"][0]["id"]
        resp = env["client"].post(f"/alerts/{alert_id}/read")
        assert resp.status_code == 200
        assert resp.json()["read"] is True
        # idempotent
        assert env["client"].post(f"/alerts/{alert_id}/read").json()["read"]
        assert env["client"].get("/alerts").json()["unread"] == 0

    def test_mark_read_404(self, env):
        assert env["client"].post("/alerts/999/read").status_code == 404

    def test_mark_all_read(self, env):
        seed(env["db"], score=90.0)
        seed(env["db"], score=75.0)
        data = env["client"].post("/alerts/read-all").json()
        assert data["marked"] == 2
        assert env["client"].get("/alerts").json()["unread"] == 0


# ── scan pipeline integration ─────────────────────────────────────────────

class TestScanCreatesAlert:
    @patch("app.services.scan_service.get_text_analyzer")
    @patch("app.services.scan_service.AttachmentAnalyzer")
    @patch("app.services.scan_service.UrlAnalyzer")
    def test_dangerous_scan_raises_alert(self, MockUrl, MockAtt, mock_get_text):
        db = MagicMock()

        mock_text = MagicMock()
        mock_text.analyze.return_value.confidence = 50.0
        mock_text.analyze.return_value.label = "Phishing"
        mock_text.analyze.return_value.is_phishing = True
        mock_get_text.return_value = mock_text

        mock_url = MagicMock()
        mock_url.analyze.return_value.url_score = 60.0
        mock_url.analyze.return_value.total_urls = 1
        mock_url.analyze.return_value.analyzed_urls = 1
        mock_url.analyze.return_value.vt_checked_urls = 0
        mock_url.analyze.return_value.high_risk_urls = []
        mock_url.analyze.return_value.per_url_results = []
        MockUrl.return_value = mock_url

        mock_att = MagicMock()
        mock_att.analyze.return_value.attachment_score = 10.0
        mock_att.analyze.return_value.total_files = 1
        mock_att.analyze.return_value.analyzed_files = 1
        mock_att.analyze.return_value.high_risk_files = []
        mock_att.analyze.return_value.per_file_results = []
        MockAtt.return_value = mock_att

        email = Email(id=1, body_text="Test", attachments=[])
        service = ScanService(db)
        header_result = HeaderAnalysisResult(present=True, score=0.0)
        with patch.object(
            ScanService, "_analyze_headers", return_value=header_result
        ):
            service._execute_pipeline(MagicMock(id=7), email)

        alerts = [
            c[0][0]
            for c in db.add.call_args_list
            if isinstance(c[0][0], Alert)
        ]
        assert len(alerts) == 1
        assert alerts[0].scan_id == 7
        assert alerts[0].reasons == ["high_risk"]  # 82.0 → dangerous

    @patch("app.services.scan_service.get_text_analyzer")
    @patch("app.services.scan_service.AttachmentAnalyzer")
    @patch("app.services.scan_service.UrlAnalyzer")
    def test_clean_scan_no_alert(self, MockUrl, MockAtt, mock_get_text):
        db = MagicMock()

        mock_text = MagicMock()
        mock_text.analyze.return_value.confidence = 5.0
        mock_text.analyze.return_value.label = "Legitimate"
        mock_text.analyze.return_value.is_phishing = False
        mock_get_text.return_value = mock_text

        mock_url = MagicMock()
        mock_url.analyze.return_value.url_score = 0.0
        mock_url.analyze.return_value.total_urls = 0
        mock_url.analyze.return_value.analyzed_urls = 0
        mock_url.analyze.return_value.vt_checked_urls = 0
        mock_url.analyze.return_value.high_risk_urls = []
        mock_url.analyze.return_value.per_url_results = []
        MockUrl.return_value = mock_url

        mock_att = MagicMock()
        mock_att.analyze.return_value.attachment_score = 0.0
        mock_att.analyze.return_value.total_files = 0
        mock_att.analyze.return_value.analyzed_files = 0
        mock_att.analyze.return_value.high_risk_files = []
        mock_att.analyze.return_value.per_file_results = []
        MockAtt.return_value = mock_att

        email = Email(id=2, body_text="Hello", attachments=[])
        service = ScanService(db)
        header_result = HeaderAnalysisResult(present=True, score=0.0)
        with patch.object(
            ScanService, "_analyze_headers", return_value=header_result
        ):
            service._execute_pipeline(MagicMock(id=8), email)

        alerts = [
            c[0][0]
            for c in db.add.call_args_list
            if isinstance(c[0][0], Alert)
        ]
        assert alerts == []
