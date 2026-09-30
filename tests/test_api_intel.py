"""API tests for the Week 2 intelligence endpoints (SQLite, offline)."""

from datetime import datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch

from app.api.intel import router as intel_router
from app.dependencies import get_db
from app.models import Base
from app.models.campaign import Campaign
from app.models.email import Email
from app.models.email_source import AuthResult, EmailSource, ReceivedHop
from app.models.indicator import Indicator
from app.models.ip_intel import IpIntel
from app.models.scan import Scan, Verdict


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/api_test.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    app = FastAPI()
    app.include_router(intel_router)

    def override_get_db():
        return session

    app.dependency_overrides[get_db] = override_get_db

    yield {
        "app": app,
        "client": TestClient(app),
        "db": session,
    }
    session.close()


def seed_email(db, mid="m1", with_source=True, with_hops=True):
    email = Email(
        message_id=f"<{mid}>",
        sender="Billing <billing@paypa1.com>",
        subject="Account notice",
        body_text="body",
        fetched_at=datetime(2026, 1, 1, 12, 0),
    )
    db.add(email)
    db.flush()

    headers = {
        "from": ["Billing <billing@paypa1.com>"],
        "authentication-results": [
            "mx.example; spf=fail smtp.mailfrom=paypa1.com "
            "dmarc=fail header.from=bank.example"
        ],
        "received": [
            "from mx.example (mx.example [192.0.2.1]) by localhost; "
            "Mon, 01 Jan 2026 12:02:00 +0000",
            "from origin.paypa1.com (origin.paypa1.com [203.0.113.50]) "
            "by mx.example; Mon, 01 Jan 2026 12:01:00 +0000",
        ],
    }
    if with_source:
        db.add(EmailSource(
            email_id=email.id,
            raw_path="/tmp/x.eml.gz",
            raw_sha256="abc123",
            size_bytes=42,
            headers_json=headers,
        ))
        db.add(AuthResult(
            email_id=email.id,
            spf_result="fail",
            dmarc_result="fail",
            alignment="mismatched",
            source="header",
        ))
    if with_hops:
        db.add(ReceivedHop(
            email_id=email.id, hop_index=0,
            raw=headers["received"][1],
            from_host="origin.paypa1.com", from_ip="203.0.113.50",
            by_host="mx.example",
            timestamp_utc=datetime(2026, 1, 1, 12, 1),
            is_internal=False, parse_confidence=1.0,
        ))
        db.add(ReceivedHop(
            email_id=email.id, hop_index=1,
            raw=headers["received"][0],
            from_host="mx.example", from_ip="192.0.2.1",
            by_host="localhost",
            timestamp_utc=datetime(2026, 1, 1, 12, 2),
            is_internal=True, parse_confidence=1.0,
        ))
    db.commit()
    return email


def seed_scan(db, email, score=75.0, iocs=()):
    scan = Scan(email_id=email.id, status="complete",
                completed_at=datetime(2026, 1, 1, 12, 5))
    db.add(scan)
    db.flush()
    db.add(Verdict(scan_id=scan.id, final_score=score, classification="dangerous"))
    for kind, value in iocs:
        db.add(Indicator(scan_id=scan.id, type=kind, value=value,
                         first_seen=datetime(2026, 1, 1), last_seen=datetime(2026, 1, 1),
                         sighting_count=1))
    db.commit()
    return scan


# ── /emails/{id}/headers ──────────────────────────────────────────────

class TestHeadersEndpoint:
    def test_present_with_hops_and_auth(self, env):
        email = seed_email(env["db"])
        resp = env["client"].get(f"/emails/{email.id}/headers")
        assert resp.status_code == 200
        data = resp.json()
        assert data["present"] is True
        assert data["auth"]["spf_result"] == "fail"
        assert len(data["hops"]) == 2
        assert data["hops"][0]["from_ip"] == "203.0.113.50"  # chronological
        assert data["raw_sha256"] == "abc123"

    def test_absent_source(self, env):
        email = seed_email(env["db"], mid="m2", with_source=False, with_hops=False)
        resp = env["client"].get(f"/emails/{email.id}/headers")
        data = resp.json()
        assert data["present"] is False
        assert data["hops"] == []
        assert data["auth"] is None

    def test_hops_reparsed_from_headers_when_rows_missing(self, env):
        email = seed_email(env["db"], mid="m3", with_hops=False)
        resp = env["client"].get(f"/emails/{email.id}/headers")
        data = resp.json()
        assert data["present"] is True
        assert len(data["hops"]) == 2   # fallback re-parse

    def test_unknown_email_404(self, env):
        assert env["client"].get("/emails/999/headers").status_code == 404


# ── /emails/{id}/trace ────────────────────────────────────────────────

class TestTraceEndpoint:
    def test_origin_and_hops(self, env):
        email = seed_email(env["db"])
        resp = env["client"].get(f"/emails/{email.id}/trace")
        assert resp.status_code == 200
        data = resp.json()
        assert data["origin"]["ip"] == "203.0.113.50"
        assert data["origin"]["is_internal"] is False
        assert len(data["hops"]) == 2
        assert data["intel"] is None     # cache miss, refresh not requested
        # auto background enrichment is disabled for tests (tests/conftest.py)
        assert data["enriching"] == 0

    def test_cached_intel_returned(self, env):
        email = seed_email(env["db"], mid="m5")
        env["db"].add(IpIntel(
            ip="203.0.113.50", country="Germany", asn=64500,
            asn_org="Example Hosting GmbH", is_hosting=True,
            fetched_at=datetime(2026, 1, 1),
            expires_at=datetime(2030, 1, 1),
        ))
        env["db"].commit()
        data = env["client"].get(f"/emails/{email.id}/trace").json()
        assert data["intel"]["country"] == "Germany"
        assert data["intel"]["is_hosting"] is True

    def test_refresh_uses_provider_service(self, env):
        email = seed_email(env["db"], mid="m6")
        with patch("app.api.intel.IpIntelService") as mock_cls:
            mock_cls.return_value.enrich.return_value.to_dict.return_value = {
                "ip": "203.0.113.50", "country": "France",
            }
            data = env["client"].get(
                f"/emails/{email.id}/trace?refresh=true"
            ).json()
        assert data["intel"]["country"] == "France"
        called = [c.args[0] for c in mock_cls.return_value.enrich.call_args_list]
        assert called[0] == "203.0.113.50"   # origin first
        assert "192.0.2.1" in called         # missing hop IPs enriched too
        assert data["enriching"] == 0        # refresh is synchronous

    def test_refresh_persists_enrichment(self, env):
        """get_db never commits — the endpoint must commit after enrich."""
        from datetime import datetime as dt

        email = seed_email(env["db"], mid="p1")

        class _FakeService:
            def __init__(self, db, ptr_resolver=None):
                self.db = db

            def enrich(self, ip):
                row = self.db.query(IpIntel).filter(IpIntel.ip == ip).first()
                if row is None:
                    row = IpIntel(
                        ip=ip, country="France", fetched_at=dt(2026, 1, 1),
                        expires_at=dt(2030, 1, 1),
                    )
                    self.db.add(row)
                return row

            def cached_only(self, ip):
                return self.db.query(IpIntel).filter(IpIntel.ip == ip).first()

        commits = {"n": 0}
        real_commit = env["db"].commit

        def counting_commit():
            commits["n"] += 1
            return real_commit()

        env["db"].commit = counting_commit
        with patch("app.api.intel.IpIntelService", _FakeService):
            body = env["client"].get(
                f"/emails/{email.id}/trace?refresh=true"
            ).json()
        assert body["intel"]["country"] == "France"
        assert commits["n"] >= 1

    def test_missing_ips_queued_for_background_enrichment(self, env):
        from types import SimpleNamespace

        email = seed_email(env["db"], mid="bg1")
        stub = SimpleNamespace(
            HEADER_DNS_CHECKS_ENABLED=False,
            IP_INTEL_AUTO_ENRICH=True,
        )
        with patch("app.api.intel.get_settings", return_value=stub), \
                patch("app.api.intel._enrich_ips_background") as bg:
            data = env["client"].get(f"/emails/{email.id}/trace").json()
        assert data["enriching"] > 0
        queued = bg.call_args.args[0]
        assert "203.0.113.50" in queued
        assert "192.0.2.1" in queued

    def test_auto_enrich_disabled_means_no_queue(self, env):
        email = seed_email(env["db"], mid="bg2")
        with patch("app.api.intel._enrich_ips_background") as bg:
            data = env["client"].get(f"/emails/{email.id}/trace").json()
        assert data["enriching"] == 0
        bg.assert_not_called()

    def test_unknown_email_404(self, env):
        assert env["client"].get("/emails/999/trace").status_code == 404


# ── /ips/{ip} ─────────────────────────────────────────────────────────

class TestIpIntelEndpoint:
    def test_cache_only_hit(self, env):
        env["db"].add(IpIntel(
            ip="203.0.113.50", country="Germany",
            fetched_at=datetime(2026, 1, 1),
            expires_at=datetime(2030, 1, 1),
        ))
        env["db"].commit()
        data = env["client"].get("/ips/203.0.113.50").json()
        assert data["intel"]["country"] == "Germany"

    def test_cache_miss_returns_null_without_network(self, env):
        # No provider call happens without refresh=true
        data = env["client"].get("/ips/203.0.113.50").json()
        assert data == {"ip": "203.0.113.50", "intel": None}

    def test_refresh_calls_enrich(self, env):
        with patch("app.api.intel.IpIntelService") as mock_cls:
            mock_cls.return_value.enrich.return_value.to_dict.return_value = {
                "ip": "198.51.100.1", "country": "Netherlands",
            }
            commits = {"n": 0}
            real_commit = env["db"].commit

            def counting_commit():
                commits["n"] += 1
                return real_commit()

            env["db"].commit = counting_commit
            data = env["client"].get("/ips/198.51.100.1?refresh=true").json()
        assert data["intel"]["country"] == "Netherlands"
        mock_cls.return_value.enrich.assert_called_once_with("198.51.100.1")
        assert commits["n"] >= 1  # fresh lookup persisted for cache-only reads


# ── /ips/stats ────────────────────────────────────────────────────────

class TestIpStatsEndpoint:
    def test_empty(self, env):
        data = env["client"].get("/ips/stats").json()
        assert data == {"total_ips": 0, "countries": []}

    def test_country_counts(self, env):
        for i, country in enumerate(["Germany", "Germany", "Netherlands"]):
            env["db"].add(IpIntel(
                ip=f"203.0.113.{i}", country=country,
                fetched_at=datetime(2026, 1, 1),
            ))
        env["db"].commit()
        data = env["client"].get("/ips/stats").json()
        assert data["total_ips"] == 3
        assert data["countries"][0] == {"country": "Germany", "count": 2}
        assert data["countries"][1] == {"country": "Netherlands", "count": 1}


# ── /ips/geo ───────────────────────────────────────────────────────────

class TestIpGeoEndpoint:
    def test_empty(self, env):
        data = env["client"].get("/ips/geo").json()
        assert data == {"points": [], "total_ips": 0, "geoed": 0}

    def test_filters_unlocated_and_flags(self, env):
        env["db"].add_all([
            IpIntel(
                ip="185.220.101.5", country="Germany", country_code="DE",
                city="Berlin", lat=52.52, lon=13.41, is_tor=True,
                fetched_at=datetime(2026, 1, 1),
            ),
            # No coordinates → must not appear on the globe payload.
            IpIntel(ip="203.0.113.9", fetched_at=datetime(2026, 1, 1)),
        ])
        env["db"].commit()
        data = env["client"].get("/ips/geo").json()
        assert data["total_ips"] == 2
        assert data["geoed"] == 1
        point = data["points"][0]
        assert point["ip"] == "185.220.101.5"
        assert point["lat"] == pytest.approx(52.52)
        assert point["lng"] == pytest.approx(13.41)
        assert point["country"] == "Germany"
        assert point["is_tor"] is True
        assert point["is_vpn"] is False
        assert point["is_proxy"] is False


# ── /indicators ───────────────────────────────────────────────────────

class TestIndicatorsEndpoint:
    def test_list_and_filters(self, env):
        email = seed_email(env["db"])
        seed_scan(env["db"], email, iocs=[
            ("origin_ip", "203.0.113.50"),
            ("sender_domain", "paypa1.com"),
        ])
        all_rows = env["client"].get("/indicators").json()
        assert all_rows["count"] == 2

        by_type = env["client"].get("/indicators?type=origin_ip").json()
        assert by_type["count"] == 1

        search = env["client"].get("/indicators?q=paypa").json()
        assert search["count"] == 1
        assert search["indicators"][0]["value"] == "paypa1.com"


# ── /graph ────────────────────────────────────────────────────────────

class TestGraphEndpoint:
    def test_graph_nodes_and_edges(self, env):
        e1 = seed_email(env["db"])
        e2 = seed_email(env["db"], mid="g2")
        seed_scan(env["db"], e1, score=90.0, iocs=[("origin_ip", "203.0.113.50")])
        seed_scan(env["db"], e2, score=40.0, iocs=[("origin_ip", "203.0.113.50")])

        data = env["client"].get("/graph").json()
        node_ids = {n["id"] for n in data["nodes"]}
        assert "ip:203.0.113.50" in node_ids
        email_nodes = [n for n in data["nodes"] if n["type"] == "email"]
        assert len(email_nodes) == 2

        relations = {e["relation"] for e in data["edges"]}
        assert "originated_from" in relations

    def test_min_score_filters(self, env):
        e1 = seed_email(env["db"])
        e2 = seed_email(env["db"], mid="g4")
        seed_scan(env["db"], e1, score=90.0, iocs=[("origin_ip", "203.0.113.50")])
        seed_scan(env["db"], e2, score=40.0, iocs=[("origin_ip", "198.51.100.9")])

        data = env["client"].get("/graph?min_score=70").json()
        email_nodes = [n for n in data["nodes"] if n["type"] == "email"]
        assert len(email_nodes) == 1
        assert email_nodes[0]["risk"] == 90.0


# ── /campaigns ────────────────────────────────────────────────────────

class TestCampaignsEndpoints:
    def test_recluster_and_fetch(self, env):
        e1 = seed_email(env["db"])
        e2 = seed_email(env["db"], mid="c2")
        seed_scan(env["db"], e1, iocs=[("origin_ip", "203.0.113.50")])
        seed_scan(env["db"], e2, iocs=[("origin_ip", "203.0.113.50")])

        resp = env["client"].post("/campaigns/recluster")
        assert resp.status_code == 200
        body = resp.json()
        assert body["scans_total"] == 2
        assert body["scans_clustered"] == 2
        assert len(body["campaigns"]) == 1
        campaign_id = body["campaigns"][0]["id"]

        listing = env["client"].get("/campaigns").json()
        assert listing["count"] == 1

        detail = env["client"].get(f"/campaigns/{campaign_id}").json()
        assert detail["campaign"]["id"] == campaign_id
        assert len(detail["scans"]) == 2
        assert {s["subject"] for s in detail["scans"]} == {
            "Account notice", "Account notice",
        }

    def test_recluster_empty_db(self, env):
        body = env["client"].post("/campaigns/recluster").json()
        assert body == {"campaigns": [], "scans_clustered": 0, "scans_total": 0}

    def test_status_filter(self, env):
        env["db"].add(Campaign(name="x", status="closed"))
        env["db"].commit()
        assert env["client"].get("/campaigns?status=open").json()["count"] == 0
        assert env["client"].get("/campaigns?status=closed").json()["count"] == 1

    def test_campaign_404(self, env):
        assert env["client"].get("/campaigns/42").status_code == 404


# ── /graph?scan_id= (plan B5) ─────────────────────────────────────────

class TestGraphScanFilter:
    def test_scan_id_filters_to_one_scan(self, env):
        e1 = seed_email(env["db"], mid="g1")
        e2 = seed_email(env["db"], mid="g2")
        s1 = seed_scan(env["db"], e1, score=80.0)
        s2 = seed_scan(env["db"], e2, score=60.0)

        data = env["client"].get(f"/graph?scan_id={s1.id}").json()
        ids = {n["id"] for n in data["nodes"]}
        assert f"email:{s1.id}" in ids
        assert f"email:{s2.id}" not in ids

    def test_unfiltered_graph_keeps_both(self, env):
        e1 = seed_email(env["db"], mid="g3")
        e2 = seed_email(env["db"], mid="g4")
        s1 = seed_scan(env["db"], e1, score=80.0)
        s2 = seed_scan(env["db"], e2, score=60.0)

        data = env["client"].get("/graph").json()
        ids = {n["id"] for n in data["nodes"]}
        assert f"email:{s1.id}" in ids
        assert f"email:{s2.id}" in ids


# ── PATCH /campaigns/{id} (plan B4) ───────────────────────────────────

class TestCampaignUpdate:
    def _campaign(self, env, status="open"):
        campaign = Campaign(name="run-1", status=status)
        env["db"].add(campaign)
        env["db"].commit()
        return campaign

    def test_patch_status_and_notes(self, env):
        campaign = self._campaign(env)
        resp = env["client"].patch(
            f"/campaigns/{campaign.id}",
            json={"status": "investigating", "notes": "triaged by analyst"},
        )
        assert resp.status_code == 200
        body = resp.json()["campaign"]
        assert body["status"] == "investigating"
        assert body["notes"] == "triaged by analyst"

        env["db"].refresh(campaign)
        assert campaign.status == "investigating"
        assert campaign.notes == "triaged by analyst"

    def test_patch_notes_only(self, env):
        campaign = self._campaign(env, status="closed")
        resp = env["client"].patch(
            f"/campaigns/{campaign.id}", json={"notes": "keep closed"}
        )
        assert resp.status_code == 200
        assert resp.json()["campaign"]["status"] == "closed"  # unchanged
        assert resp.json()["campaign"]["notes"] == "keep closed"

    @pytest.mark.parametrize("status", ["new", "closed", "open"])
    def test_valid_statuses(self, env, status):
        campaign = self._campaign(env)
        resp = env["client"].patch(
            f"/campaigns/{campaign.id}", json={"status": status}
        )
        assert resp.status_code == 200
        assert resp.json()["campaign"]["status"] == status

    def test_invalid_status_rejected(self, env):
        campaign = self._campaign(env)
        resp = env["client"].patch(
            f"/campaigns/{campaign.id}", json={"status": "archived"}
        )
        assert resp.status_code == 422
        env["db"].refresh(campaign)
        assert campaign.status == "open"  # unchanged

    def test_patch_unknown_campaign_404(self, env):
        resp = env["client"].patch("/campaigns/999", json={"notes": "x"})
        assert resp.status_code == 404


# ── /domains/{domain}/intel (plan B1) ─────────────────────────────────

class TestDomainIntelEndpoint:
    def test_offline_by_default(self, env):
        resp = env["client"].get("/domains/example.com/intel")
        assert resp.status_code == 200
        body = resp.json()
        assert body["domain"] == "example.com"
        assert body["lookups"] == {"dns": False, "rdap": False}
        assert body["has_mx"] is None
        assert body["is_young"] is None

    def test_invalid_domain_422(self, env):
        assert env["client"].get("/domains/nope/intel").status_code == 422

    def test_engine_invoked_with_requested_lookups(self, env, monkeypatch):
        import app.engines.intel.domain_intel as di_mod
        from app.engines.intel.domain_intel import DomainIntel

        captured = {}

        def fake(domain, *, use_dns, use_rdap, **kwargs):
            captured["dns"] = use_dns
            captured["rdap"] = use_rdap
            return DomainIntel(
                domain=domain, has_mx=True, is_young=True,
                registrar="ExampleRegistrar",
            )

        monkeypatch.setattr(di_mod, "assess_domain", fake)
        resp = env["client"].get(
            "/domains/fresh-domain.example/intel?dns=true"
        )
        assert resp.status_code == 200
        assert captured == {"dns": True, "rdap": False}  # rdap off by default
        body = resp.json()
        assert body["registrar"] == "ExampleRegistrar"
        assert body["is_young"] is True
        assert body["lookups"] == {"dns": True, "rdap": False}


# ── /emails/{id}/trace per-hop geo (FE-C6) ─────────────────────────────

class TestTraceHopGeo:
    def test_cached_hop_geo_attached(self, env):
        email = seed_email(env["db"], mid="geo1")
        env["db"].add(
            IpIntel(
                ip="203.0.113.50", country="Germany", country_code="DE",
                lat=52.52, lon=13.40, source="test",
                expires_at=datetime(2027, 1, 1),
            )
        )
        env["db"].commit()

        body = env["client"].get(f"/emails/{email.id}/trace").json()
        by_ip = {h["from_ip"]: h for h in body["hops"]}
        assert by_ip["203.0.113.50"]["geo"]["lat"] == 52.52
        assert by_ip["203.0.113.50"]["geo"]["country"] == "Germany"
        # IPs without a cached row degrade to null (no network)
        assert by_ip["192.0.2.1"]["geo"] is None


# ── /attribution/stats (FE-C5) ─────────────────────────────────────────

class TestAttributionStats:
    def test_counts_attribution_kinds(self, env):
        e = seed_email(env["db"], mid="a1")
        scan = seed_scan(env["db"], e, score=75.0)
        verdict = (
            env["db"].query(Verdict).filter(Verdict.scan_id == scan.id).one()
        )
        verdict.breakdown = {"attribution": {"kind": "spoofed_domain"}}
        env["db"].commit()

        body = env["client"].get("/attribution/stats").json()
        kinds = {k["kind"]: k["count"] for k in body["kinds"]}
        assert kinds.get("spoofed_domain") == 1
        assert body["total"] == 1

    def test_missing_attribution_counts_as_unknown(self, env):
        e = seed_email(env["db"], mid="a2")
        seed_scan(env["db"], e, score=50.0)
        body = env["client"].get("/attribution/stats").json()
        kinds = {k["kind"]: k["count"] for k in body["kinds"]}
        assert kinds.get("unknown") == 1

    def test_empty_db(self, env):
        assert env["client"].get("/attribution/stats").json() == {
            "total": 0, "kinds": [],
        }
