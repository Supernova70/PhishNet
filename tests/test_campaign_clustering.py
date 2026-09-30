"""Campaign clustering: union-find over shared IoCs + subject pass."""

from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.engines.correlation.campaign_clustering import (
    ScanInput,
    cluster_scans,
    save_clusters,
)
from app.models import Base
from app.models.campaign import Campaign
from app.models.email import Email
from app.models.scan import Scan


def _scan(id, score=50.0, indicators=(), subject="", sent_at=None):
    return ScanInput(
        id=id,
        score=score,
        indicators=tuple(indicators),
        subject=subject,
        sent_at=sent_at,
    )


IP = ("origin_ip", "203.0.113.50")
BRAND = ("lookalike_brand", "paypal")


class TestUnionOnIocs:
    def test_shared_origin_ip_unions(self):
        clusters = cluster_scans([
            _scan(1, indicators=[IP]),
            _scan(2, indicators=[IP]),
            _scan(3, indicators=[("origin_ip", "198.51.100.7")]),
        ])
        sizes = sorted(c.email_count for c in clusters)
        assert sizes == [1, 2]

    def test_shared_replyto_domain_unions(self):
        reply = ("replyto_domain", "attacker.example")
        clusters = cluster_scans([
            _scan(1, indicators=[reply]),
            _scan(2, indicators=[reply]),
        ])
        assert len(clusters) == 1
        assert clusters[0].shared_iocs["replyto_domain"] == ["attacker.example"]

    def test_chained_union_transitive(self):
        clusters = cluster_scans([
            _scan(1, indicators=[IP]),
            _scan(2, indicators=[IP, ("url_domain", "evil.example")]),
            _scan(3, indicators=[("url_domain", "evil.example")]),
        ])
        assert len(clusters) == 1
        assert clusters[0].email_count == 3
        # shared across ALL members only
        assert "origin_ip" not in clusters[0].shared_iocs

    def test_no_shared_ioc_no_union(self):
        clusters = cluster_scans([
            _scan(1, indicators=[IP]),
            _scan(2, indicators=[("origin_ip", "198.51.100.7")]),
        ])
        assert len(clusters) == 2

    def test_low_value_iocs_do_not_union(self):
        # sender_domain is deliberately not a high-value IOC type
        clusters = cluster_scans([
            _scan(1, indicators=[("sender_domain", "same.example")]),
            _scan(2, indicators=[("sender_domain", "same.example")]),
        ])
        assert len(clusters) == 2


class TestSubjectSimilarityPass:
    def test_same_brand_similar_subjects_union(self):
        # Threshold lowered so the mechanism is tested deterministically
        clusters = cluster_scans(
            [
                _scan(1, indicators=[BRAND],
                      subject="PayPal account suspension notice"),
                _scan(2, indicators=[BRAND],
                      subject="PayPal account suspension notic"),
            ],
            subject_similarity_threshold=0.5,
        )
        assert len(clusters) == 1
        assert clusters[0].email_count == 2

    def test_same_brand_dissimilar_subjects_keep_default_pass(self):
        clusters = cluster_scans([
            _scan(1, indicators=[BRAND],
                  subject="PayPal account suspension notice click here now"),
            _scan(2, indicators=[BRAND],
                  subject="Your monthly PayPal statement is ready to download"),
        ])
        assert len(clusters) == 2  # cosine below 0.72

    def test_similar_subjects_without_shared_brand_never_union(self):
        clusters = cluster_scans(
            [
                _scan(1, subject="PayPal account suspension notice"),
                _scan(2, subject="PayPal account suspension notic"),
            ],
            subject_similarity_threshold=0.1,  # would match if brands counted
        )
        assert len(clusters) == 2


class TestClusterMetadata:
    def test_name_prefers_brand(self):
        clusters = cluster_scans([
            _scan(1, indicators=[BRAND, IP]),
            _scan(2, indicators=[BRAND, IP]),
        ])
        assert clusters[0].name == "paypal impersonation"

    def test_name_falls_back_to_replyto_then_ip(self):
        clusters = cluster_scans([
            _scan(1, indicators=[("replyto_domain", "x.example"), IP]),
            _scan(2, indicators=[("replyto_domain", "x.example"), IP]),
        ])
        assert clusters[0].name == "replies → x.example"

    def test_name_uses_tactic_from_subjects(self):
        clusters = cluster_scans([
            _scan(1, subject="Your invoice #4471 is attached", indicators=[IP]),
            _scan(2, subject="Invoice overdue — pay now", indicators=[IP]),
        ])
        assert clusters[0].name == "payment lure campaign"

    def test_name_combines_brand_and_tactic(self):
        clusters = cluster_scans([
            _scan(1, subject="Verify your password", indicators=[BRAND]),
            _scan(2, subject="Confirm your password", indicators=[BRAND]),
        ])
        assert clusters[0].name == "paypal credential phishing"

    def test_name_appends_shared_infra_when_no_brand(self):
        clusters = cluster_scans([
            _scan(1, subject="Track your parcel", indicators=[("replyto_domain", "bad.example")]),
            _scan(2, subject="Delivery notice", indicators=[("replyto_domain", "bad.example")]),
        ])
        assert clusters[0].name == "delivery notice via bad.example"

    def test_tactic_ignores_empty_subjects(self):
        # No subjects → no tactic votes → old infra fallbacks stay intact
        clusters = cluster_scans([
            _scan(1, indicators=[IP]),
            _scan(2, indicators=[IP]),
        ])
        assert clusters[0].name == f"origin {IP[1]}"

    def test_avg_score_and_dates(self):
        at = datetime(2026, 1, 1, 12, 0)
        clusters = cluster_scans([
            _scan(1, score=80.0, indicators=[IP], sent_at=at),
            _scan(2, score=40.0, indicators=[IP],
                  sent_at=datetime(2026, 1, 2, 12, 0)),
        ])
        assert clusters[0].avg_score == 60.0
        assert clusters[0].first_seen == at
        assert clusters[0].last_seen == datetime(2026, 1, 2, 12, 0)

    def test_confidence_grows_with_ioc_breadth(self):
        narrow = cluster_scans([
            _scan(1, indicators=[IP]), _scan(2, indicators=[IP]),
        ])[0]
        broad = cluster_scans([
            _scan(1, indicators=[IP, BRAND]),
            _scan(2, indicators=[IP, BRAND]),
        ])[0]
        assert broad.confidence > narrow.confidence
        assert narrow.confidence == 0.6  # 0.4 + 0.2 * 1 shared type

    def test_empty_input(self):
        assert cluster_scans([]) == []


class TestSaveClusters:
    def _session(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        return sessionmaker(bind=engine)()

    def test_persists_multi_scan_clusters_only(self):
        db = self._session()
        for i in (1, 2, 3):
            email = Email(
                message_id=f"<m{i}>", sender="a@b.example",
                subject=f"s{i}", body_text="x",
            )
            db.add(email)
            db.flush()
            db.add(Scan(email_id=email.id, status="complete"))
        db.flush()

        clusters = cluster_scans([
            _scan(1, indicators=[IP]),
            _scan(2, indicators=[IP]),
            _scan(3, indicators=[("origin_ip", "198.51.100.7")]),
        ])
        campaigns = save_clusters(db, clusters)
        db.commit()

        assert len(campaigns) == 1  # singleton is not a campaign
        member_ids = {
            s.id for s in db.query(Scan).filter(Scan.campaign_id.isnot(None))
        }
        assert member_ids == {1, 2}
        singleton = db.query(Scan).filter(Scan.campaign_id.is_(None)).one()
        assert singleton.id == 3
