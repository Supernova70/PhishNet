"""Backlog endpoints: per-scan attribution (B2) + indicators (B3)."""

from datetime import datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.scan import router as scan_router
from app.dependencies import get_db
from app.models import Base
from app.models.email import Email
from app.models.indicator import Indicator
from app.models.scan import Scan, Verdict


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/scan_api_test.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    app = FastAPI()
    app.include_router(scan_router)

    def override_get_db():
        return session

    app.dependency_overrides[get_db] = override_get_db

    yield {"client": TestClient(app), "db": session}
    session.close()


def seed(db, *, breakdown=None, indicators=()):
    email = Email(
        message_id="<b1@example.com>",
        sender="Ops <ops@corp.test>",
        subject="Invoice",
        body_text="body",
        fetched_at=datetime(2026, 1, 1, 12, 0),
    )
    db.add(email)
    db.flush()
    scan = Scan(
        email_id=email.id, status="complete",
        completed_at=datetime(2026, 1, 1, 12, 5),
    )
    db.add(scan)
    db.flush()
    db.add(
        Verdict(
            scan_id=scan.id,
            final_score=82.0,
            classification="dangerous",
            breakdown=breakdown or {},
        )
    )
    for kind, value in indicators:
        db.add(
            Indicator(
                scan_id=scan.id, type=kind, value=value,
                first_seen=datetime(2026, 1, 1),
                last_seen=datetime(2026, 1, 1),
                sighting_count=1,
            )
        )
    db.commit()
    return scan


ATTRIBUTION = {
    "kind": "spoofed_domain",
    "confidence": 0.72,
    "evidence": ["SPF returned fail (+25)"],
    "scores": {"spoofed_domain": 70.0},
}


class TestAttributionEndpoint:
    def test_returns_verdict_and_indicators(self, env):
        scan = seed(
            env["db"],
            breakdown={"attribution": ATTRIBUTION},
            indicators=[("sender_domain", "paypa1.example")],
        )
        resp = env["client"].get(f"/scans/{scan.id}/attribution")
        assert resp.status_code == 200
        body = resp.json()
        assert body["scan_id"] == scan.id
        assert body["attribution"]["kind"] == "spoofed_domain"
        assert body["attribution"]["evidence"] == ["SPF returned fail (+25)"]
        assert {i["type"] for i in body["indicators"]} == {"sender_domain"}

    def test_missing_scan_404(self, env):
        assert env["client"].get("/scans/42/attribution").status_code == 404

    def test_verdict_without_attribution_404(self, env):
        scan = seed(env["db"], breakdown={"ai": {"score": 10}})
        assert (
            env["client"].get(f"/scans/{scan.id}/attribution").status_code
            == 404
        )

    def test_scan_without_verdict_404(self, env):
        email = Email(
            message_id="<nov@x>", sender="a@b.test", subject="s",
            body_text="x", fetched_at=datetime(2026, 1, 1),
        )
        env["db"].add(email)
        env["db"].flush()
        scan = Scan(email_id=email.id, status="running")
        env["db"].add(scan)
        env["db"].commit()
        assert (
            env["client"].get(f"/scans/{scan.id}/attribution").status_code
            == 404
        )


class TestIndicatorsEndpoint:
    def test_lists_scan_iocs(self, env):
        scan = seed(
            env["db"],
            indicators=[
                ("sender_domain", "paypa1.example"),
                ("origin_ip", "203.0.113.50"),
                ("attachment_hash", "deadbeef" * 8),
            ],
        )
        resp = env["client"].get(f"/scans/{scan.id}/indicators")
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == 3
        assert {i["type"] for i in body["indicators"]} == {
            "sender_domain", "origin_ip", "attachment_hash",
        }

    def test_empty_is_valid(self, env):
        scan = seed(env["db"])
        body = env["client"].get(f"/scans/{scan.id}/indicators").json()
        assert body == {"count": 0, "indicators": []}

    def test_missing_scan_404(self, env):
        assert env["client"].get("/scans/42/indicators").status_code == 404
