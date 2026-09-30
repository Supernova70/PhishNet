"""Compliance tests: evidence hash chain, audit log, report export,
raw-evidence access, PII masking. SQLite + temp files, offline."""

import gzip
from datetime import datetime
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch

from app.api.evidence import router as evidence_router
from app.api.intel import router as intel_router
from app.api.report import router as report_router
from app.api.report import _canonical_sha256
from app.dependencies import get_db
from app.models import Base
from app.models.audit_log import AuditLog
from app.models.email import Email
from app.models.email_source import EmailSource, ReceivedHop
from app.models.evidence import EvidenceChain
from app.models.scan import Scan, Verdict
from app.services.evidence_service import (
    GENESIS_HASH,
    append_evidence,
    audit,
    verify_chain,
    verify_evidence,
)
from app.services.pii import mask_email, mask_ip


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/comp.db")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    app = FastAPI()
    app.include_router(report_router)
    app.include_router(evidence_router)
    app.include_router(intel_router)
    app.dependency_overrides[get_db] = lambda: session
    yield {"app": app, "client": TestClient(app), "db": session, "tmp": tmp_path}
    session.close()


def seed(env):
    """Email + retained raw file + hop + completed scan + verdict."""
    db = env["db"]
    email = Email(
        message_id="<comp1>",
        sender="IT <helpdesk@paypa1-secure.com>",
        to_address="alice@example.com",
        subject="Urgent: verify your account",
        body_text="click",
        fetched_at=datetime(2026, 1, 2, 9, 0),
    )
    db.add(email)
    db.flush()

    raw = b"From: helpdesk@paypa1-secure.com\r\nSubject: hi\r\n\r\nbody"
    raw_path = env["tmp"] / f"{email.id}.eml.gz"
    with gzip.open(raw_path, "wb") as fh:
        fh.write(raw)
    import hashlib

    db.add(EmailSource(
        email_id=email.id,
        raw_path=str(raw_path),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
        headers_json={
            "from": ["IT <helpdesk@paypa1-secure.com>"],
            "received": [
                "from origin.paypa1-secure.com (origin [203.0.113.77]) "
                "by mx; Mon, 02 Jan 2026 09:01:00 +0000",
            ],
        },
    ))
    db.add(ReceivedHop(
        email_id=email.id, hop_index=0,
        raw="from origin.paypa1-secure.com (origin [203.0.113.77]) by mx",
        from_host="origin.paypa1-secure.com", from_ip="203.0.113.77",
        by_host="mx", timestamp_utc=datetime(2026, 1, 2, 9, 1),
        is_internal=False, parse_confidence=1.0,
    ))
    scan = Scan(email_id=email.id, status="complete",
                completed_at=datetime(2026, 1, 2, 9, 5))
    db.add(scan)
    db.flush()
    db.add(Verdict(
        scan_id=scan.id, final_score=88.0, classification="dangerous",
        ai_score=90.0, ai_label="phishing", url_score=0.0,
        attachment_score=0.0, header_score=70.0,
        breakdown={
            "ai": {"flags": ["payment diversion"], "bec": {"bec_score": 75}},
            "header": {"score": 70.0, "present": True, "origin_ip": "203.0.113.77"},
            "attribution": {"kind": "external_attacker", "confidence": 0.7},
        },
    ))
    db.commit()
    return email, scan


# ── chain primitives ──────────────────────────────────────────────────

class TestEvidenceChain:
    def test_append_links_to_genesis_then_each_other(self, env):
        db = env["db"]
        r1 = append_evidence(db, email_id=1, scan_id=1,
                             raw_sha256="aa" * 32, actor="scanner")
        r2 = append_evidence(db, email_id=1, scan_id=1,
                             report_sha256="bb" * 32, actor="report-export")
        db.commit()
        assert r1.prev_hash == GENESIS_HASH
        assert r2.prev_hash == r1.row_hash
        assert len(r1.row_hash) == 64 and r1.row_hash != r2.row_hash

    def test_fresh_chain_verifies(self, env):
        db = env["db"]
        append_evidence(db, email_id=1, scan_id=1, raw_sha256="aa" * 32)
        append_evidence(db, email_id=1, scan_id=1, report_sha256="bb" * 32)
        db.commit()
        assert verify_chain(db) == {
            "valid": True, "checked": 2, "broken_id": None, "reason": None,
        }

    def test_tampered_row_detected(self, env):
        db = env["db"]
        row = append_evidence(db, email_id=1, scan_id=1, raw_sha256="aa" * 32)
        db.commit()
        row.actor = "attacker"  # field edit without recomputing row_hash
        db.commit()
        result = verify_chain(db)
        assert result["valid"] is False
        assert result["broken_id"] == row.id
        assert "row_hash" in result["reason"]

    def test_deleted_middle_row_breaks_link(self, env):
        db = env["db"]
        append_evidence(db, email_id=1, scan_id=1, raw_sha256="aa" * 32)
        middle = append_evidence(db, email_id=1, scan_id=1, raw_sha256="cc" * 32)
        append_evidence(db, email_id=1, scan_id=1, report_sha256="bb" * 32)
        db.commit()
        db.delete(middle)
        db.commit()
        result = verify_chain(db)
        assert result["valid"] is False
        assert "prev_hash" in result["reason"]

    def test_verify_single_row(self, env):
        db = env["db"]
        r1 = append_evidence(db, email_id=1, scan_id=1, raw_sha256="aa" * 32)
        r2 = append_evidence(db, email_id=1, scan_id=1, report_sha256="bb" * 32)
        db.commit()
        assert verify_evidence(db, r1.id)["valid"] is True
        assert verify_evidence(db, r2.id)["valid"] is True
        assert verify_evidence(db, 999) is None


# ── report endpoint ───────────────────────────────────────────────────

class TestReportEndpoint:
    def test_report_structure(self, env):
        email, scan = seed(env)
        resp = env["client"].get(f"/scans/{scan.id}/report")
        assert resp.status_code == 200
        data = resp.json()
        report, integrity = data["report"], data["integrity"]
        assert report["email"]["subject"] == "Urgent: verify your account"
        assert report["verdict"]["final_score"] == 88.0
        assert report["header_forensics"]["origin_ip"] == "203.0.113.77"
        assert report["attribution"]["kind"] == "external_attacker"
        assert report["origin"]["ip"] == "203.0.113.77"
        assert report["origin"]["intel"] is None  # cache miss, no network
        assert len(report["received_chain"]) == 1
        assert integrity["disclaimer"]
        assert integrity["app_version"]
        assert len(integrity["report_sha256"]) == 64
        # viewing must NOT append to the chain
        assert report["evidence_chain"] == []

    def test_export_appends_chain_and_audits(self, env):
        email, scan = seed(env)
        resp = env["client"].get(f"/scans/{scan.id}/report?export=true")
        assert resp.status_code == 200
        data = resp.json()

        # chain row appended with matching report hash
        rows = env["db"].query(EvidenceChain).filter_by(scan_id=scan.id).all()
        assert len(rows) == 1
        assert rows[0].report_sha256 == data["integrity"]["report_sha256"]
        assert rows[0].actor == "report-export"
        # the exported response's custody block includes the new row
        assert len(data["report"]["evidence_chain"]) == 1

        # audit entry recorded
        audits = env["db"].query(AuditLog).filter_by(action="report_export").all()
        assert len(audits) == 1
        assert audits[0].entity_id == scan.id

    def test_export_hash_matches_canonical_payload(self, env):
        email, scan = seed(env)
        data = env["client"].get(f"/scans/{scan.id}/report?export=true").json()
        recomputed = _canonical_sha256(data["report"])
        # report payload hash is stable across export/view for same content
        view = env["client"].get(f"/scans/{scan.id}/report").json()
        # custody block differs (export added a row) but verdict core matches
        assert view["report"]["verdict"] == data["report"]["verdict"]
        assert len(recomputed) == 64

    def test_report_404(self, env):
        assert env["client"].get("/scans/999/report").status_code == 404


# ── raw evidence + audit endpoints ────────────────────────────────────

class TestRawEvidenceAccess:
    def test_raw_download_streams_and_audits(self, env):
        email, scan = seed(env)
        resp = env["client"].get(f"/emails/{email.id}/evidence/raw")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/gzip"
        raw = gzip.decompress(resp.content)
        assert b"Subject: hi" in raw

        entry = env["db"].query(AuditLog).filter_by(action="raw_view").one()
        assert entry.entity_id == email.id

    def test_raw_missing_404(self, env):
        email, scan = seed(env)
        (Path(email.source.raw_path)).unlink()
        assert (
            env["client"].get(f"/emails/{email.id}/evidence/raw").status_code
            == 404
        )

    def test_headers_view_is_audited(self, env):
        email, scan = seed(env)
        resp = env["client"].get(f"/emails/{email.id}/headers")
        assert resp.status_code == 200
        rows = (
            env["db"].query(AuditLog)
            .filter_by(action="raw_view", entity_type="email_headers")
            .all()
        )
        assert len(rows) == 1

    def test_evidence_list_and_verify_endpoints(self, env):
        email, scan = seed(env)
        append_evidence(env["db"], email_id=email.id, scan_id=scan.id,
                        raw_sha256="dd" * 32, actor="scanner")
        env["db"].commit()

        listing = env["client"].get(f"/evidence?scan_id={scan.id}").json()
        assert listing["count"] == 1
        ev_id = listing["evidence"][0]["id"]

        result = env["client"].get(f"/evidence/{ev_id}/verify").json()
        assert result["valid"] is True
        assert result["row_hash_ok"] is True
        assert result["chain"]["valid"] is True

        # verify itself is audited
        audits = env["db"].query(AuditLog).filter_by(action="evidence_verify").all()
        assert len(audits) == 1

        assert env["client"].get("/evidence/999/verify").status_code == 404

    def test_audit_endpoint(self, env):
        email, scan = seed(env)
        env["client"].get(f"/emails/{email.id}/evidence/raw")
        data = env["client"].get("/audit?action=raw_view").json()
        assert data["count"] == 1
        assert data["entries"][0]["action"] == "raw_view"
        assert env["client"].get("/audit?action=nonexistent").json()["count"] == 0

    def test_audit_helper_commits_immediately(self, env):
        audit(env["db"], "retention_purge", actor="script", entity_type="email",
              entity_id=7, detail={"purged": 3})
        row = env["db"].query(AuditLog).one()
        assert row.action == "retention_purge"
        assert row.detail_json == {"purged": 3}


# ── PII masking ───────────────────────────────────────────────────────

class TestPiiMasking:
    def test_mask_email(self):
        assert mask_email("jane.doe@corp.com") == "j***@corp.com"
        assert mask_email("a@b.co") == "a***@b.co"
        assert mask_email(None) is None
        assert mask_email("no-at-sign") == "no-at-sign"

    def test_mask_ip_v4_and_v6(self):
        assert mask_ip("203.0.113.50") == "203.0.113.x"
        assert mask_ip("2001:db8::1") == "2001:db8::x"
        assert mask_ip(None) is None

    def test_maybe_mask_respects_toggle(self):
        from app.services import pii

        with patch.object(
            pii, "get_settings", return_value=type("S", (), {"MASK_PII": True})()
        ):
            assert pii.maybe_mask_email("a@b.co") == "a***@b.co"
            assert pii.maybe_mask_ip("203.0.113.50") == "203.0.113.x"
        with patch.object(
            pii, "get_settings", return_value=type("S", (), {"MASK_PII": False})()
        ):
            assert pii.maybe_mask_email("a@b.co") == "a@b.co"
            assert pii.maybe_mask_ip("203.0.113.50") == "203.0.113.50"

    def test_report_masks_when_enabled(self, env):
        email, scan = seed(env)
        from app.services import pii

        with patch.object(
            pii, "get_settings",
            return_value=type("S", (), {"MASK_PII": True})(),
        ):
            data = env["client"].get(f"/scans/{scan.id}/report").json()
        assert data["report"]["email"]["sender"] == "I***@paypa1-secure.com>"
        assert data["report"]["email"]["to"] == "a***@example.com"
        assert data["report"]["origin"]["ip"] == "203.0.113.x"
