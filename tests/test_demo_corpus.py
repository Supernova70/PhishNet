"""Demo corpus tests: import all fixture .eml files offline and assert
each scenario reaches the engine it was built for."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch

import app.services.email_service as email_service_mod
from app.engines.bec_analyzer import analyze_bec
from app.engines.intel.origin import build_origin_trace
from app.engines.lookalike import analyze_lookalike
from app.models import Base
from app.models.email import Email
from app.models.email_source import ReceivedHop
from app.services.email_service import EmailService

CORPUS_DIR = "tests/fixtures/eml"
EXPECTED_TOTAL = 24


class _SettingsStub:
    PRESERVE_RAW_EMAIL = True
    ATTACHMENT_DIR = ""
    raw_email_dir = ""

    def __init__(self, base):
        self.ATTACHMENT_DIR = str(base / "uploads")
        self.raw_email_dir = str(base / "raw")


@pytest.fixture()
def imported(tmp_path, monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    monkeypatch.setattr(
        email_service_mod, "settings", _SettingsStub(tmp_path)
    )
    summary = EmailService(db).import_eml_files(CORPUS_DIR)
    yield db, summary
    db.close()


class TestCorpusImport:
    def test_all_files_import(self, imported):
        db, summary = imported
        assert summary["failed"] == []
        assert summary["total"] == EXPECTED_TOTAL
        assert summary["imported"] == EXPECTED_TOTAL
        assert db.query(Email).count() == EXPECTED_TOTAL

    def test_reimport_deduplicates(self, imported):
        db, _ = imported
        again = EmailService(db).import_eml_files(CORPUS_DIR)
        assert again["imported"] == 0
        assert again["skipped"] == EXPECTED_TOTAL
        assert db.query(Email).count() == EXPECTED_TOTAL

    def test_evidence_retained_for_every_email(self, imported):
        db, _ = imported
        from app.models.email_source import EmailSource

        rows = db.query(EmailSource).all()
        assert len(rows) == EXPECTED_TOTAL
        assert all(r.raw_path for r in rows)          # gzipped copy on disk
        assert all(r.raw_sha256 for r in rows)        # custody hash
        assert all(r.headers_json for r in rows)      # header block

    def test_attachment_and_html_scenarios(self, imported):
        db, _ = imported
        ext = (
            db.query(Email)
            .filter(Email.subject.contains("Scanned invoice"))
            .one()
        )
        assert ext.has_attachments
        assert ext.attachments[0].filename == "invoice.pdf.exe"

        html = (
            db.query(Email)
            .filter(Email.subject.contains("Q1 forecast"))
            .one()
        )
        assert html.has_html
        assert html.body_text is None

    def test_missing_received_has_no_hops(self, imported):
        db, _ = imported
        email = (
            db.query(Email)
            .filter(Email.subject.contains("Salary revision"))
            .one()
        )
        assert db.query(ReceivedHop).filter_by(email_id=email.id).count() == 0


class TestCorpusScenarios:
    def test_spoof_origin_is_external_relay_ip(self, imported):
        db, _ = imported
        email = (
            db.query(Email).filter(Email.subject.contains("limited")).one()
        )
        hops = (
            db.query(ReceivedHop)
            .filter_by(email_id=email.id)
            .order_by(ReceivedHop.hop_index)
            .all()
        )
        origin = build_origin_trace(hops)
        assert origin is not None
        assert origin.ip == "203.0.113.66"
        assert origin.is_internal is False

    def test_relay_forged_chain_parses(self, imported):
        db, _ = imported
        email = (
            db.query(Email).filter(Email.subject.contains("Ticket #9981")).one()
        )
        hops = (
            db.query(ReceivedHop)
            .filter_by(email_id=email.id)
            .order_by(ReceivedHop.hop_index)
            .all()
        )
        assert len(hops) == 2
        # forged ordering: origin hop timestamp is LATER than relay hop
        assert hops[0].timestamp_utc > hops[1].timestamp_utc

    def _bec(self, db, subject_fragment):
        email = (
            db.query(Email).filter(Email.subject.contains(subject_fragment)).one()
        )
        return analyze_bec(
            email.subject, email.body_text or "", email.source.headers_json
        )

    def test_payment_diversion_fires(self, imported):
        db, _ = imported
        result = self._bec(db, "updated supplier payment")
        cats = [c.category for c in result.categories]
        assert "payment_diversion" in cats
        assert result.bec_score >= 40

    def test_invoice_fires(self, imported):
        db, _ = imported
        result = self._bec(db, "overdue")
        cats = [c.category for c in result.categories]
        assert "fake_invoice" in cats

    def test_credential_harvest_fires(self, imported):
        db, _ = imported
        result = self._bec(db, "verify your mailbox")
        cats = [c.category for c in result.categories]
        assert "credential_harvest" in cats

    def test_replyto_hijack_header_signal(self, imported):
        db, _ = imported
        from app.engines.headers.common import domain_of

        email = db.query(Email).filter(
            Email.subject.contains("statement is ready")
        ).one()
        headers = email.source.headers_json
        from_domain = domain_of(headers["from"][0])
        reply_domain = domain_of(headers["reply-to"][0])
        assert from_domain == "amex-billing.com"
        assert reply_domain == "account-verify.ru"
        assert from_domain != reply_domain  # the hijack signal itself

    def test_lookalike_matches(self, imported):
        db, _ = imported
        result = analyze_lookalike(["paypa1.com"])
        brands = {m.brand for m in result.matches}
        assert "paypal" in brands
        assert result.score > 0

    def test_clean_mail_stays_clean(self, imported):
        db, _ = imported
        for fragment in ("weekly reading list", "Receipt for order"):
            email = (
                db.query(Email).filter(Email.subject.contains(fragment)).one()
            )
            result = analyze_bec(
                email.subject, email.body_text or "", email.source.headers_json
            )
            assert result.bec_score < 40, fragment
            lk = analyze_lookalike(["newsletter.example.org", "example.org"])
            assert lk.score == 0, fragment

    def test_bulk_campaign_share_sender(self, imported):
        db, _ = imported
        senders = (
            db.query(Email.sender)
            .filter(Email.sender.contains("parcel-redelivery.org"))
            .all()
        )
        assert len(senders) == 5
