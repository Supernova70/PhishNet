"""IpIntelService: cache hit/expiry, enrichment merge, offline guards."""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.engines.intel.geo_provider import GeoResult, NullProvider
from app.engines.intel.vpn_tor import TorExitCache
from app.models import Base
from app.models.ip_intel import IpIntel
from app.services.ip_intel_service import IpIntelService

NOW = datetime(2026, 1, 1, 12, 0, 0)


class FakeProvider:
    name = "fake"

    def __init__(self, result=None):
        self.result = result
        self.calls = 0

    def lookup(self, ip):
        self.calls += 1
        return self.result


class FakeSettings:
    GEOIP_PROVIDER = "none"
    MAXMIND_DB_PATH = None
    IP_INTEL_CACHE_DAYS = 30
    DNSBL_ENABLED = False
    DNSBL_ZONES = "bl.spamcop.net"


def make_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def make_geo(ip="203.0.113.50"):
    return GeoResult(
        ip=ip,
        provider="fake",
        country="Germany",
        country_code="DE",
        region="Hesse",
        city="Frankfurt",
        lat=50.11,
        lon=8.68,
        asn=64500,
        asn_org="Example Hosting GmbH",
        isp="Example ISP",
        domain="example-hosting.net",
        raw={"success": True},
    )


def make_service(db, provider=None, tor_ips=None, **settings_kw):
    settings = FakeSettings()
    for k, v in settings_kw.items():
        setattr(settings, k, v)
    tor = TorExitCache(fetch_text=lambda url: "\n".join(tor_ips or ()))
    # Prime the cache at NOW so ips() doesn't fetch at "today"
    tor._ips = set(tor_ips or ())
    tor._fetched_on = NOW.date()
    return IpIntelService(
        db,
        provider=provider or FakeProvider(make_geo()),
        tor_cache=tor,
        settings_obj=settings,
        now=lambda: NOW,
    )


class TestEnrichment:
    def test_enrich_writes_full_row(self):
        db = make_session()
        service = make_service(db, DNSBL_ENABLED=True)
        service._dnsbl_resolver = lambda name, rdtype: ["127.0.0.2"]

        row = service.enrich("203.0.113.50")

        assert row.country == "Germany"
        assert row.asn == 64500
        assert row.is_hosting is True          # org has "hosting"
        assert row.is_dnsbl_listed is True
        assert row.dnsbl_json == {"bl.spamcop.net": "listed"}
        assert row.expires_at == NOW + timedelta(days=30)
        assert row.source == "fake"
        assert row.raw_json["asn_summary"]["is_hosting"] is True

    def test_cache_hit_avoids_provider_call(self):
        db = make_session()
        provider = FakeProvider(make_geo())
        service = make_service(db, provider=provider)

        service.enrich("203.0.113.50")
        assert provider.calls == 1

        again = service.enrich("203.0.113.50")
        assert provider.calls == 1  # served from DB
        assert again.country == "Germany"
        assert again.country_code == "DE"

    def test_expired_cache_triggers_refresh(self):
        db = make_session()
        provider = FakeProvider(make_geo())
        service = make_service(db, provider=provider)
        service.enrich("203.0.113.50")

        row = db.query(IpIntel).filter(IpIntel.ip == "203.0.113.50").first()
        row.expires_at = NOW - timedelta(seconds=1)
        db.commit()

        service.enrich("203.0.113.50")
        assert provider.calls == 2

    def test_tor_exit_flagged(self):
        db = make_session()
        service = make_service(db, tor_ips=["203.0.113.50"])
        row = service.enrich("203.0.113.50")
        assert row.is_tor is True

    def test_vpn_org_flagged(self):
        db = make_session()
        geo = make_geo()
        geo.asn_org = "Mullvad VPN AB"
        service = make_service(db, provider=FakeProvider(geo))
        row = service.enrich("203.0.113.50")
        assert row.is_vpn is True

    def test_dnsbl_off_writes_no_dnsbl_fields(self):
        db = make_session()
        service = make_service(db, DNSBL_ENABLED=False)
        row = service.enrich("203.0.113.50")
        assert row.is_dnsbl_listed is False
        assert row.dnsbl_json is None


class TestOfflineGuards:
    def test_null_provider_and_dnsbl_off_does_nothing(self):
        db = make_session()
        service = make_service(db, provider=NullProvider(),
                               GEOIP_PROVIDER="none", DNSBL_ENABLED=False)
        assert service.enrich("203.0.113.50") is None
        assert db.query(IpIntel).count() == 0

    def test_transient_provider_failure_writes_no_negative_cache(self):
        # A failed geo lookup must not leave an empty row behind — it would
        # block re-enrichment for IP_INTEL_CACHE_DAYS after recovery.
        db = make_session()
        service = make_service(db, provider=FakeProvider(None),
                               DNSBL_ENABLED=False)
        assert service.enrich("203.0.113.50") is None
        assert db.query(IpIntel).count() == 0

    def test_provider_failure_still_persists_dnsbl(self):
        db = make_session()
        service = make_service(db, provider=FakeProvider(None),
                               DNSBL_ENABLED=True)
        service._dnsbl_resolver = lambda name, rdtype: []
        row = service.enrich("203.0.113.50")
        assert row is not None
        assert row.country is None
        assert row.dnsbl_json == {"bl.spamcop.net": "clean"}

    def test_cached_only_returns_row_without_provider_call(self):
        db = make_session()
        provider = FakeProvider(make_geo())
        service = make_service(db, provider=provider)
        service.enrich("203.0.113.50")

        assert service.cached_only("203.0.113.50") is not None
        assert service.cached_only("198.51.100.1") is None
        assert provider.calls == 1

    def test_empty_ip_returns_none(self):
        db = make_session()
        service = make_service(db)
        assert service.enrich("") is None
        assert service.cached_only(None) is None
