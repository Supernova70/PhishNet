"""Tests for hosting/VPN heuristics and the Tor exit-list cache."""

from app.engines.intel.asn_rdap import asn_summary, is_hosting, is_vpn_org
from app.engines.intel.vpn_tor import (
    TorExitCache,
    classify_anonymization,
    parse_tor_exitlist,
)


class TestHostingDetection:
    def test_known_providers_detected(self):
        assert is_hosting(asn_org="Amazon Technologies Inc.") is True
        assert is_hosting(asn_org="DigitalOcean, LLC") is True
        assert is_hosting(asn_org="Hetzner Online GmbH") is True
        assert is_hosting(asn_org="Google Cloud") is True

    def test_consumer_isp_not_hosting(self):
        assert is_hosting(asn_org="Deutsche Telekom AG") is False
        assert is_hosting(asn_org="Comcast Cable Communications") is False

    def test_matches_across_any_field(self):
        assert is_hosting(isp="OVH SAS") is True
        assert is_hosting(domain="vultr.com") is True

    def test_none_values_safe(self):
        assert is_hosting(None, None, None) is False


class TestVpnDetection:
    def test_vpn_orgs(self):
        assert is_vpn_org(asn_org="Mullvad VPN") is True
        assert is_vpn_org(isp="NordVPN Ltd") is True

    def test_normal_isp_not_vpn(self):
        assert is_vpn_org(asn_org="Example Hosting GmbH") is False


class TestAsnSummary:
    def test_summary_fields(self):
        s = asn_summary(64500, "Example Hosting GmbH", "Example ISP", "ex.net")
        assert s["asn"] == 64500
        assert s["is_hosting"] is True
        assert s["is_vpn_org"] is False


class TestTorExitList:
    def test_parses_lines_and_skips_comments(self):
        body = "# comment\n203.0.113.5\n198.51.100.7\n\nnot-an-ip\n"
        ips = parse_tor_exitlist(body)
        assert ips == {"203.0.113.5", "198.51.100.7"} | set()

    def test_daily_cache_fetches_once(self):
        calls = []

        def fetch(url):
            calls.append(url)
            return "203.0.113.5\n"

        cache = TorExitCache(fetch_text=fetch)
        assert cache.is_exit("203.0.113.5") is True
        assert cache.is_exit("198.51.100.1") is False
        assert len(calls) == 1  # second membership check reuses the fetch

    def test_fetch_failure_keeps_previous_list(self):
        state = {"fail": False, "calls": 0}

        def fetch(url):
            state["calls"] += 1
            if state["fail"]:
                raise OSError("network down")
            return "203.0.113.5\n"

        cache = TorExitCache(fetch_text=fetch)
        cache.ips()
        state["fail"] = True
        # Simulate the day rolling over
        cache._fetched_on = None
        stale = cache.ips()  # refresh fails → keeps previous set
        assert "203.0.113.5" in stale


class TestClassify:
    def test_merge_signals(self):
        flags = classify_anonymization(
            "198.51.100.1", tor_ips={"198.51.100.1"}, org_is_vpn=True
        )
        assert flags == {"is_vpn": True, "is_tor": True, "is_proxy": False}

    def test_provider_threat_fields_win(self):
        flags = classify_anonymization(
            "198.51.100.2", tor_ips=set(),
            provider_threat={"proxy": True, "vpn": True},
        )
        assert flags["is_proxy"] is True
        assert flags["is_vpn"] is True
