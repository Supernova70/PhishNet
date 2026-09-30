"""Offline tests for geo providers (fake http_get, no network)."""

import pytest

from app.engines.intel.geo_provider import (
    IpWhoisIoProvider,
    MaxMindGeoLite2Provider,
    NullProvider,
    get_provider,
)

IWHOIS_PAYLOAD = {
    "ip": "203.0.113.50",
    "success": True,
    "country": "Germany",
    "region": "Hesse",
    "city": "Frankfurt",
    "latitude": 50.11,
    "longitude": 8.68,
    "connection": {
        "asn": 64500,
        "org": "Example Hosting GmbH",
        "isp": "Example ISP",
        "domain": "example-hosting.net",
    },
}


class TestIpWhoisIo:
    def test_successful_lookup_maps_fields(self):
        seen = {}

        def fake_get(url):
            seen["url"] = url
            return IWHOIS_PAYLOAD

        provider = IpWhoisIoProvider(http_get=fake_get)
        result = provider.lookup("203.0.113.50")

        assert seen["url"].endswith("/203.0.113.50")
        assert result.provider == "ipwhois"
        assert result.country == "Germany"
        assert result.city == "Frankfurt"
        assert result.lat == 50.11
        assert result.asn == 64500
        assert result.asn_org == "Example Hosting GmbH"
        assert result.isp == "Example ISP"
        assert result.raw["success"] is True

    def test_definitive_error_returns_empty_result(self):
        # Reserved/invalid IPs are permanent misses — an empty GeoResult
        # lets the service cache the stop-retrying marker.
        provider = IpWhoisIoProvider(
            http_get=lambda url: {"success": False, "message": "Reserved range"}
        )
        result = provider.lookup("198.51.100.10")
        assert result is not None
        assert result.provider == "ipwhois"
        assert result.country is None

    def test_transient_error_returns_none(self):
        # Rate limits etc. must not be cached — retry on the next request.
        provider = IpWhoisIoProvider(
            http_get=lambda url: {"success": False, "message": "Rate limit exceeded"}
        )
        assert provider.lookup("203.0.113.50") is None

    def test_network_failure_returns_none(self):
        def boom(url):
            raise OSError("connection refused")

        provider = IpWhoisIoProvider(http_get=boom)
        assert provider.lookup("203.0.113.50") is None

    def test_malformed_asn_does_not_crash(self):
        payload = dict(IWHOIS_PAYLOAD, connection={"asn": "AS64500"})
        provider = IpWhoisIoProvider(http_get=lambda url: payload)
        result = provider.lookup("203.0.113.50")
        assert result.asn is None


class TestFactoryAndNull:
    def test_null_provider(self):
        assert NullProvider().lookup("1.2.3.4") is None

    def test_factory_none(self):
        assert isinstance(get_provider("none"), NullProvider)

    def test_factory_ipwhois(self):
        assert isinstance(get_provider("ipwhois"), IpWhoisIoProvider)

    def test_factory_unknown_defaults_to_null(self):
        assert isinstance(get_provider("bogus"), NullProvider)

    def test_maxmind_without_db_is_inert(self):
        provider = MaxMindGeoLite2Provider(db_path=None)
        assert provider.available is False
        assert provider.lookup("1.2.3.4") is None

    def test_maxmind_with_missing_db_is_inert(self, tmp_path):
        provider = MaxMindGeoLite2Provider(
            db_path=str(tmp_path / "missing.mmdb")
        )
        assert provider.available is False
        assert provider.lookup("1.2.3.4") is None
