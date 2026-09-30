"""Domain intel engine (plan §5, B1) — offline with injectable edges."""

from datetime import datetime, timezone

import pytest

import app.engines.intel.domain_intel as di_mod
from app.engines.intel.domain_intel import (
    DomainIntel,
    YOUNG_DOMAIN_DAYS,
    assess_domain,
    assess_domain_cached,
    is_valid_domain,
    sender_is_young,
)

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)

DNS_RECORDS = {
    ("example.com", "MX"): ["10 mail.example.com."],
    ("example.com", "NS"): ["ns1.example.com.", "ns2.example.com."],
    ("example.com", "TXT"): ["v=spf1 -all", "google-site-verification=abc"],
    ("_dmarc.example.com", "TXT"): [
        "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
    ],
}


def fake_resolver(domain, rdtype):
    return DNS_RECORDS.get((domain, rdtype), [])


def raising_resolver(domain, rdtype):
    raise TimeoutError("dns down")


def rdap_young(domain):
    return {
        "events": [
            {"eventAction": "registration", "eventDate": "2026-09-20T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-09-20T00:00:00Z"},
        ],
        "entities": [{"roles": ["registrar"], "handle": "ExampleRegistrar"}],
    }


def rdap_old(domain):
    return {
        "events": [
            {"eventAction": "registration", "eventDate": "2015-01-02T00:00:00Z"},
        ],
        "entities": [],
    }


@pytest.fixture(autouse=True)
def clear_cache():
    di_mod._cache.clear()
    yield
    di_mod._cache.clear()


class TestValidation:
    @pytest.mark.parametrize(
        "domain,valid",
        [
            ("example.com", True),
            ("sub.example.co.uk", True),
            ("xn--80ak6aa92e.com", True),
            ("", False),
            ("not a domain", False),
            ("no_scheme_https://x.com", False),
            ("localhost", False),
        ],
    )
    def test_is_valid_domain(self, domain, valid):
        assert is_valid_domain(domain) is valid

    def test_invalid_domain_short_circuits(self):
        intel = assess_domain("bogus", use_dns=True, use_rdap=True)
        assert intel.errors == ["invalid-domain"]
        assert intel.has_mx is None and intel.is_young is None


class TestDnsPosture:
    def test_records_parsed(self):
        intel = assess_domain(
            "example.com", resolver=fake_resolver, use_rdap=False, now=NOW
        )
        assert intel.has_mx is True and intel.mx_count == 1
        assert intel.has_ns is True and intel.ns_count == 2
        assert intel.has_spf is True
        assert intel.dmarc_present is True
        assert intel.dmarc_policy == "quarantine"

    def test_absent_dmarc_and_spf(self):
        intel = assess_domain(
            "plain.test", resolver=fake_resolver, use_rdap=False, now=NOW
        )
        assert intel.has_spf is False
        assert intel.dmarc_present is False
        assert intel.dmarc_policy is None
        assert intel.has_mx is False

    def test_dns_failure_is_recorded_not_raised(self):
        intel = assess_domain(
            "example.com", resolver=raising_resolver, use_rdap=False, now=NOW
        )
        assert intel.has_mx is None and intel.has_ns is None
        assert any(e.startswith("mx:") for e in intel.errors)
        assert any(e.startswith("ns:") for e in intel.errors)
        assert "rdap:TimeoutError" not in intel.errors  # rdap disabled


class TestRdapRegistration:
    def test_young_domain(self):
        intel = assess_domain(
            "fresh.example",
            use_dns=False,
            rdap_fetch=rdap_young,
            now=NOW,
        )
        assert intel.registrar == "ExampleRegistrar"
        assert intel.is_young is True
        assert intel.domain_age_days == 9
        assert intel.domain_age_days < YOUNG_DOMAIN_DAYS
        assert intel.rdap_source == "rdap"

    def test_old_domain(self):
        intel = assess_domain(
            "old.example", use_dns=False, rdap_fetch=rdap_old, now=NOW
        )
        assert intel.is_young is False
        assert intel.domain_age_days is not None

    def test_rdap_failure_degrades(self):
        def boom(domain):
            raise TimeoutError("rdap down")

        intel = assess_domain("fresh.example", use_dns=False, rdap_fetch=boom)
        assert intel.rdap_source is None
        assert intel.is_young is None
        assert "rdap:TimeoutError" in intel.errors


class TestCacheAndSenderIsYoung:
    def test_cache_hits_avoid_requery(self):
        calls = {"n": 0}

        def counting(domain, rdtype):
            calls["n"] += 1
            return fake_resolver(domain, rdtype)

        assess_domain_cached(
            "example.com", resolver=counting, use_rdap=False, now=NOW
        )
        assess_domain_cached(
            "example.com", resolver=counting, use_rdap=False, now=NOW
        )
        assert calls["n"] == 4  # MX, NS, TXT, DMARC — once only

    def test_sender_is_young_offline_by_default(self):
        # Settings default: RDAP disabled → no network, always False.
        assert sender_is_young("anything.example") is False

    def test_sender_is_young_gated_by_settings(self, monkeypatch):
        class _Settings:
            DOMAIN_INTEL_DNS_ENABLED = False
            DOMAIN_INTEL_RDAP_ENABLED = True

        import app.config as cfg

        monkeypatch.setattr(cfg, "get_settings", lambda: _Settings())

        def fake_cached(domain, **kwargs):
            return DomainIntel(domain=domain, is_young=True)

        monkeypatch.setattr(di_mod, "assess_domain_cached", fake_cached)
        assert sender_is_young("fresh.example") is True

    def test_sender_is_young_false_when_rdap_disabled(self, monkeypatch):
        class _Settings:
            DOMAIN_INTEL_DNS_ENABLED = True
            DOMAIN_INTEL_RDAP_ENABLED = False

        import app.config as cfg

        monkeypatch.setattr(cfg, "get_settings", lambda: _Settings())

        def must_not_run(*args, **kwargs):
            raise AssertionError("cache must not be consulted")

        monkeypatch.setattr(di_mod, "assess_domain_cached", must_not_run)
        assert sender_is_young("fresh.example") is False

    def test_sender_is_young_never_raises(self, monkeypatch):
        def boom(*args, **kwargs):
            raise RuntimeError("engine exploded")

        monkeypatch.setattr(di_mod, "assess_domain_cached", boom)
        assert sender_is_young("fresh.example") is False
