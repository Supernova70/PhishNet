"""Row-level tenancy (plan P2) — two accounts must never see each other.

Account A (admin) and account B (user) each own one fully-populated
email + scan + alert + campaign + evidence + audit footprint. Every
content endpoint is exercised three ways: as A, as B, and anonymous.
"""

import gzip
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.router import api_router
from app.auth.session import COOKIE_NAME, create_session_token
from app.dependencies import get_db
from app.models import Base
from app.models.alert import Alert
from app.models.audit_log import AuditLog
from app.models.campaign import Campaign
from app.models.email import Attachment, Email
from app.models.email_source import EmailSource
from app.models.evidence import EvidenceChain
from app.models.indicator import Indicator
from app.models.scan import Scan, Verdict
from app.models.user import User
from app.services.evidence_service import append_evidence, audit

USER_A = 1  # admin
USER_B = 2  # regular user


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/tenancy.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    user_a = User(id=USER_A, google_sub="sub-a", email="a@example.com",
                  name="A", role="admin")
    user_b = User(id=USER_B, google_sub="sub-b", email="b@example.com",
                  name="B", role="user")
    session.add_all([user_a, user_b])
    session.commit()

    app = FastAPI()
    app.include_router(api_router)
    app.dependency_overrides[get_db] = lambda: session

    shots = tmp_path / "shots"
    shots.mkdir()
    (shots / "1").mkdir()  # A's scan screenshot dir (scan id fixed below)
    (shots / "1" / "shot.png").write_bytes(b"\x89PNG fake")

    raw = tmp_path / "raw-a.eml.gz"
    with gzip.open(raw, "wb") as fh:
        fh.write(b"From: a@example.com\r\nSubject: hi\r\n\r\nbody\r\n")

    footprint = {}
    for uid, tag in ((USER_A, "a"), (USER_B, "b")):
        email = Email(
            user_id=uid,
            message_id=f"<{tag}@example.com>",
            sender=f"sender-{tag}@evil.test",
            subject=f"subject {tag}",
            body_text="body",
            fetched_at=datetime(2026, 1, 1, 12, 0),
        )
        session.add(email)
        session.flush()
        session.add(EmailSource(
            email_id=email.id,
            raw_path=str(raw) if tag == "a" else str(tmp_path / "missing.eml.gz"),
            raw_sha256="aa" * 32,
            size_bytes=10,
            headers_json={"from": [f"sender-{tag}@evil.test"]},
        ))
        session.add(Attachment(
            email_id=email.id, filename=f"file-{tag}.pdf",
            content_type="application/pdf", size_bytes=3,
        ))
        scan = Scan(user_id=uid, email_id=email.id, status="complete",
                    started_at=datetime(2026, 1, 1, 12, 0),
                    completed_at=datetime(2026, 1, 1, 12, 5))
        session.add(scan)
        session.flush()
        session.add(Verdict(scan_id=scan.id, final_score=88.0,
                            classification="dangerous",
                            breakdown={"attribution": {"kind": "origin"}}))
        session.add(Alert(user_id=uid, scan_id=scan.id, email_id=email.id,
                          score=88.0, classification="dangerous",
                          reasons=["high_risk"], subject=f"subject {tag}",
                          sender=f"sender-{tag}@evil.test"))
        session.add(Indicator(user_id=uid, scan_id=scan.id, type="origin_ip",
                              value=f"203.0.113.{uid}",
                              first_seen=datetime(2026, 1, 1),
                              last_seen=datetime(2026, 1, 1),
                              sighting_count=1))
        session.add(Campaign(user_id=uid, name=f"campaign {tag}",
                             first_seen=datetime(2026, 1, 1),
                             last_seen=datetime(2026, 1, 1),
                             email_count=1, avg_score=88.0, status="open"))
        session.flush()
        scan.campaign_id = session.query(Campaign).filter_by(user_id=uid).one().id
        append_evidence(session, email_id=email.id, scan_id=scan.id,
                        raw_sha256="bb" * 32, actor="scanner", user_id=uid)
        audit(session, "raw_view", actor=f"user{uid}",
              entity_type="email", entity_id=email.id, user_id=uid)
        footprint[uid] = {"email": email.id, "scan": scan.id,
                          "alert": None, "attachment": None,
                          "campaign": scan.campaign_id}
        session.commit()

    for uid in (USER_A, USER_B):
        footprint[uid]["alert"] = session.query(Alert).filter_by(user_id=uid).one().id
        footprint[uid]["attachment"] = \
            session.query(Attachment).join(Email).filter(Email.user_id == uid).one().id
        footprint[uid]["evidence"] = \
            session.query(__import__("app.models.evidence", fromlist=["EvidenceChain"])
                          .EvidenceChain).filter_by(user_id=uid).one().id

    def client_for(user):
        client = TestClient(app)
        client.cookies.set(COOKIE_NAME, create_session_token(user))
        return client

    yield {
        "app": app,
        "db": session,
        "a": client_for(user_a),
        "b": client_for(user_b),
        "anon": TestClient(app),
        "ids": footprint,
        "shots": shots,
    }
    session.close()


# ── anonymous ──────────────────────────────────────────────────────────

ANON_PATHS = [
    "/emails", "/scans", "/alerts", "/campaigns", "/indicators",
    "/evidence", "/audit", "/scans/events", "/settings", "/users",
]  # RBAC (R1): settings + user management require a session too


class TestAnonymousRejected:
    @pytest.mark.parametrize("path", ANON_PATHS)
    def test_401_without_session(self, env, path):
        assert env["anon"].get(path).status_code == 401


# ── lists are scoped ───────────────────────────────────────────────────

class TestScopedLists:
    def test_emails_scoped(self, env):
        for who in ("a", "b"):
            rows = env[who].get("/emails").json()["emails"]
            assert len(rows) == 1
            uid = USER_A if who == "a" else USER_B
            assert rows[0]["id"] == env["ids"][uid]["email"]

    def test_scans_scoped(self, env):
        for who, uid in (("a", USER_A), ("b", USER_B)):
            data = env[who].get("/scans").json()
            assert data["total"] == 1
            assert data["scans"][0]["id"] == env["ids"][uid]["scan"]

    def test_alerts_scoped(self, env):
        for who, uid in (("a", USER_A), ("b", USER_B)):
            data = env[who].get("/alerts").json()
            assert data["count"] == 1
            assert data["alerts"][0]["id"] == env["ids"][uid]["alert"]

    def test_campaigns_scoped(self, env):
        for who, uid in (("a", USER_A), ("b", USER_B)):
            data = env[who].get("/campaigns").json()
            assert data["count"] == 1
            assert data["campaigns"][0]["id"] == env["ids"][uid]["campaign"]

    def test_indicators_scoped(self, env):
        data = env["a"].get("/indicators").json()
        assert data["count"] == 1
        assert data["indicators"][0]["value"] == "203.0.113.1"

    def test_evidence_scoped(self, env):
        for who, uid in (("a", USER_A), ("b", USER_B)):
            data = env[who].get("/evidence").json()
            assert data["count"] == 1
            assert data["evidence"][0]["id"] == env["ids"][uid]["evidence"]

    def test_audit_scoped(self, env):
        for who, uid in (("a", USER_A), ("b", USER_B)):
            data = env[who].get("/audit").json()
            assert data["count"] == 1
            assert data["entries"][0]["id"] is not None

    def test_attachments_scoped(self, env):
        for who, tag in (("a", "a"), ("b", "b")):
            data = env[who].get("/attachments").json()
            assert data["total"] == 1
            assert data["attachments"][0]["filename"] == f"file-{tag}.pdf"

    def test_csv_export_scoped(self, env):
        csv_text = env["a"].get("/scans/export/csv").text
        assert "subject a" in csv_text
        assert "subject b" not in csv_text

    def test_graph_scoped(self, env):
        node_labels = [n["label"] for n in env["a"].get("/graph").json()["nodes"]]
        assert not any("subject b" in str(lbl) for lbl in node_labels)


# ── cross-account reads → 404 (never 403, never content) ───────────────

class TestCrossAccountReads:
    def test_foreign_email_404(self, env):
        assert env["a"].get(f"/emails/{env['ids'][USER_B]['email']}").status_code == 404

    def test_foreign_scan_404(self, env):
        sid = env["ids"][USER_B]["scan"]
        for path in (f"/scans/{sid}", f"/scans/{sid}/summary",
                     f"/scans/{sid}/attribution", f"/scans/{sid}/indicators",
                     f"/scans/{sid}/report", f"/scans/{sid}/events"):
            resp = env["a"].get(path)
            assert resp.status_code == 404, path

    def test_foreign_headers_and_trace_404(self, env):
        eid = env["ids"][USER_B]["email"]
        for path in (f"/emails/{eid}/headers", f"/emails/{eid}/trace",
                     f"/emails/{eid}/evidence/raw",
                     f"/emails/{eid}/latest-scan"):
            resp = env["a"].get(path)
            assert resp.status_code == 404, path

    def test_foreign_alert_404(self, env):
        aid = env["ids"][USER_B]["alert"]
        assert env["a"].post(f"/alerts/{aid}/read").status_code == 404

    def test_foreign_campaign_404_and_unpatched(self, env):
        cid = env["ids"][USER_B]["campaign"]
        assert env["a"].get(f"/campaigns/{cid}").status_code == 404
        assert env["a"].patch(
            f"/campaigns/{cid}", json={"status": "closed"}
        ).status_code == 404
        still_open = env["b"].get(f"/campaigns/{cid}").json()["campaign"]["status"]
        assert still_open == "open"

    def test_foreign_evidence_404(self, env):
        eid = env["ids"][USER_B]["evidence"]
        assert env["a"].get(f"/evidence/{eid}/verify").status_code == 404

    def test_foreign_attachment_404(self, env):
        att = env["ids"][USER_B]["attachment"]
        assert env["a"].get(f"/attachments/{att}").status_code == 404

    def test_trigger_scan_on_foreign_email_404(self, env):
        resp = env["a"].post(f"/scans/{env['ids'][USER_B]['email']}")
        assert resp.status_code == 404


# ── writes stay on the owner ───────────────────────────────────────────

class TestScopedWrites:
    def test_mark_own_alert_read_only(self, env):
        assert env["a"].post(
            f"/alerts/{env['ids'][USER_A]['alert']}/read"
        ).status_code == 200
        assert env["a"].get("/alerts").json()["unread"] == 0
        assert env["b"].get("/alerts").json()["unread"] == 1

    def test_recluster_only_rebuilds_own_campaigns(self, env):
        resp = env["a"].post("/campaigns/recluster")
        assert resp.status_code == 200
        # B's campaign untouched
        assert env["b"].get("/campaigns").json()["count"] == 1
        assert env["a"].get("/campaigns").json()["count"] in (0, 1)

    def test_report_export_tags_own_evidence(self, env):
        resp = env["a"].get(
            f"/scans/{env['ids'][USER_A]['scan']}/report?export=true"
        )
        assert resp.status_code == 200
        rows = [r["id"] for r in resp.json()["report"]["evidence_chain"]]
        assert env["ids"][USER_A]["evidence"] in rows
        # A's export never surfaces B's custody rows
        assert env["ids"][USER_B]["evidence"] not in rows


# ── admin gating (settings mutations) ──────────────────────────────────

class TestAdminGate:
    def test_user_cannot_mutate_settings(self, env):
        resp = env["b"].put("/settings", json={"scan_threshold": 55})
        assert resp.status_code == 403

    def test_admin_can_mutate_settings(self, env):
        with patch("app.api.settings.os.path.exists", return_value=False):
            resp = env["a"].put("/settings", json={"scan_threshold": 55})
        assert resp.status_code == 200
        assert resp.json()["scan_threshold"] == 55


# ── artifacts (screenshot files) ───────────────────────────────────────

class TestArtifacts:
    def test_own_screenshot_served_foreign_404(self, env, tmp_path):
        with patch("app.api.evidence.get_settings") as gs:
            gs.return_value.DYNAMIC_URL_SCREENSHOT_DIR = str(env["shots"])
            own = env["a"].get(
                f"/artifacts/url-screenshots/{env['ids'][USER_A]['scan']}/shot.png"
            )
            assert own.status_code == 200
            foreign = env["a"].get(
                f"/artifacts/url-screenshots/{env['ids'][USER_B]['scan']}/shot.png"
            )
            assert foreign.status_code == 404
            anon = env["anon"].get(
                f"/artifacts/url-screenshots/{env['ids'][USER_A]['scan']}/shot.png"
            )
            assert anon.status_code == 401

    def test_traversal_blocked(self, env, tmp_path):
        with patch("app.api.evidence.get_settings") as gs:
            gs.return_value.DYNAMIC_URL_SCREENSHOT_DIR = str(env["shots"])
            resp = env["a"].get(
                f"/artifacts/url-screenshots/{env['ids'][USER_A]['scan']}/..%2F..%2Fsecret"
            )
            assert resp.status_code in (404, 400)
