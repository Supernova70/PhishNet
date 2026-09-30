"""Indicator extraction + upsert semantics."""

from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.engines.correlation.ioc_store import extract_indicators, store_indicators
from app.models import Base
from app.models.indicator import Indicator


class TestExtractIndicators:
    def test_full_email_yields_all_types(self):
        pairs = extract_indicators(
            sender="PayPal Security <alert@paypa1.com>",
            headers={"reply-to": ["collections@attacker.example"]},
            subject="x",
            attachments=[type("A", (), {"sha256_hash": "abc123"})()],
            url_domains=["http://phish.example/path", "https://other.example"],
            origin_ip="203.0.113.50",
            lookalike_brand="paypal",
        )
        kinds = dict(pairs)
        assert kinds["sender_domain"] == "paypa1.com"
        assert kinds["replyto_domain"] == "attacker.example"
        assert kinds["origin_ip"] == "203.0.113.50"
        assert kinds["attachment_hash"] == "abc123"
        assert kinds["lookalike_brand"] == "paypal"
        assert "url_domain" in kinds

    def test_dedupes_and_lowercases(self):
        pairs = extract_indicators(
            sender="A <User@Example.COM>",
            url_domains=["Example.com", "www.example.com"],
        )
        urls = [v for k, v in pairs if k == "url_domain"]
        senders = [v for k, v in pairs if k == "sender_domain"]
        assert urls == ["example.com"]          # www collapses, dup removed
        assert senders == ["example.com"]       # different kind → separate row

    def test_missing_evidence_yields_nothing(self):
        assert extract_indicators() == []
        assert extract_indicators(sender=None, headers={}) == []

    def test_dict_attachments_supported(self):
        pairs = extract_indicators(attachments=[{"sha256": "deadbeef"}])
        assert ("attachment_hash", "deadbeef") in pairs


class TestStoreIndicators:
    def _session(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        return sessionmaker(bind=engine)()

    def test_first_sighting_creates_row(self):
        db = self._session()
        rows = store_indicators(db, scan_id=1, pairs=[("origin_ip", "203.0.113.50")])
        db.commit()
        assert len(rows) == 1
        row = db.query(Indicator).one()
        assert row.scan_id == 1
        assert row.sighting_count == 1

    def test_same_scan_restored_bumps_count(self):
        db = self._session()
        store_indicators(db, 1, [("origin_ip", "203.0.113.50")])
        db.commit()
        store_indicators(db, 1, [("origin_ip", "203.0.113.50")])
        db.commit()
        row = db.query(Indicator).one()
        assert row.sighting_count == 2

    def test_same_value_across_scans_keeps_per_scan_rows(self):
        # Per-scan rows are what clustering/graph join on — two scans
        # sharing an IP must both keep a row.
        db = self._session()
        store_indicators(db, 1, [("origin_ip", "203.0.113.50")])
        store_indicators(db, 2, [("origin_ip", "203.0.113.50")])
        db.commit()
        rows = db.query(Indicator).all()
        assert len(rows) == 2
        assert {r.scan_id for r in rows} == {1, 2}
        assert all(r.sighting_count == 1 for r in rows)

    def test_mixed_pairs_partial_rows(self):
        db = self._session()
        store_indicators(
            db, 1,
            [("origin_ip", "203.0.113.50"), ("sender_domain", "evil.example")],
        )
        db.commit()
        assert db.query(Indicator).count() == 2
