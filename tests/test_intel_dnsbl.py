"""Offline tests for DNSBL checks (fake resolver, no network)."""

from app.engines.intel.dnsbl import check_dnsbl, reverse_ipv4


def make_resolver(listed: set):
    def resolver(name, rdtype):
        for zone in listed:
            if name.endswith("." + zone):
                return ["127.0.0.2"]
        return []
    return resolver


class TestReverseIpv4:
    def test_public_ipv4(self):
        assert reverse_ipv4("203.0.113.5") == "5.113.0.203"

    def test_private_skipped(self):
        assert reverse_ipv4("10.0.0.1") is None

    def test_loopback_skipped(self):
        assert reverse_ipv4("127.0.0.1") is None

    def test_ipv6_skipped(self):
        assert reverse_ipv4("2001:db8::1") is None

    def test_garbage_skipped(self):
        assert reverse_ipv4("not-an-ip") is None


class TestCheckDnsbl:
    def test_listed(self):
        results = check_dnsbl(
            "203.0.113.5", ["bl.spamcop.net"],
            resolver=make_resolver({"bl.spamcop.net"}),
        )
        assert results == {"bl.spamcop.net": "listed"}

    def test_clean(self):
        results = check_dnsbl(
            "203.0.113.5", ["bl.spamcop.net"], resolver=make_resolver(set())
        )
        assert results == {"bl.spamcop.net": "clean"}

    def test_zone_error_is_contained(self):
        def flaky(name, rdtype):
            raise OSError("timeout")

        results = check_dnsbl("203.0.113.5", ["bl.spamcop.net"], resolver=flaky)
        assert results == {"bl.spamcop.net": "error"}

    def test_private_ip_skipped_without_queries(self):
        def must_not_query(name, rdtype):
            raise AssertionError("resolver must not be called")

        results = check_dnsbl(
            "192.168.1.1", ["bl.spamcop.net"], resolver=must_not_query
        )
        assert results == {"bl.spamcop.net": "skipped"}

    def test_multiple_zones(self):
        zones = ["bl.spamcop.net", "zen.spamhaus.org"]
        results = check_dnsbl(
            "203.0.113.5", zones, resolver=make_resolver({"zen.spamhaus.org"})
        )
        assert results["bl.spamcop.net"] == "clean"
        assert results["zen.spamhaus.org"] == "listed"

    def test_never_raises(self):
        results = check_dnsbl("999.999.999.999", ["bl.spamcop.net"])
        assert results == {"bl.spamcop.net": "skipped"}
