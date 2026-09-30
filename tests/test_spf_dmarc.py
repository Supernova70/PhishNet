"""Tests for SPF evaluation, DMARC record parsing, and domain alignment."""

import pytest

from app.engines.headers.dns_checks import (
    check_alignment,
    evaluate_spf,
    parse_dmarc_record,
    run_dns_checks,
)


def make_resolver(zone: dict):
    """zone = {(domain, rdtype): [values...]} with NXDOMAIN otherwise."""
    def resolver(domain: str, rdtype: str):
        key = (domain.lower(), rdtype.upper())
        if key in zone:
            return zone[key]
        raise OSError(f"NXDOMAIN {domain}")
    return resolver


# ── SPF ───────────────────────────────────────────────────────────────

def test_spf_ip4_match_pass():
    zone = {("example.com", "TXT"): ["v=spf1 ip4:203.0.113.0/24 -all"]}
    result, detail = evaluate_spf(zone[("example.com", "TXT")][0],
                                  "203.0.113.55", make_resolver(zone))
    assert result == "pass"


def test_spf_ip4_mismatch_falls_to_all():
    zone = {("example.com", "TXT"): ["v=spf1 ip4:203.0.113.0/24 -all"]}
    result, detail = evaluate_spf(zone[("example.com", "TXT")][0],
                                  "198.51.100.7", make_resolver(zone))
    assert result == "fail"
    assert "-all" in detail


def test_spf_softfail_qualifier():
    zone = {("example.com", "TXT"): ["v=spf1 ip4:203.0.113.5 -all"]}
    result, _ = evaluate_spf("v=spf1 ip4:203.0.113.5 ~all",
                             "198.51.100.7", make_resolver(zone))
    assert result == "softfail"


def test_spf_include_chain_pass():
    zone = {
        ("example.com", "TXT"): ["v=spf1 include:_spf.vendor.net -all"],
        ("_spf.vendor.net", "TXT"): ["v=spf1 ip4:198.51.100.0/24 -all"],
    }
    result, _ = evaluate_spf("v=spf1 include:_spf.vendor.net -all",
                             "198.51.100.42", make_resolver(zone))
    assert result == "pass"


def test_spf_include_without_record_permerror():
    zone = {("example.com", "TXT"): ["v=spf1 include:missing.example -all"]}
    result, _ = evaluate_spf("v=spf1 include:missing.example -all",
                             "203.0.113.1", make_resolver(zone))
    assert result == "permerror"


def test_spf_lookup_budget_permerror():
    # Chain of includes that loops → budget must stop it
    zone = {("loop.example", "TXT"): ["v=spf1 include:loop.example -all"]}
    result, _ = evaluate_spf("v=spf1 include:loop.example -all",
                             "203.0.113.1", make_resolver(zone))
    assert result == "permerror"


def test_spf_invalid_sender_ip():
    result, _ = evaluate_spf("v=spf1 -all", "not-an-ip", make_resolver({}))
    assert result == "permerror"


def test_spf_record_must_start_with_vspf1():
    result, _ = evaluate_spf("hello world", "203.0.113.1", make_resolver({}))
    assert result == "permerror"


def test_spf_plus_all_passes_everything():
    result, _ = evaluate_spf("v=spf1 +all", "203.0.113.1", make_resolver({}))
    assert result == "pass"


# ── DMARC ─────────────────────────────────────────────────────────────

def test_parse_dmarc_record_basic():
    tags = parse_dmarc_record("v=DMARC1; p=reject; rua=mailto:d@e.com")
    assert tags["p"] == "reject"
    assert tags["rua"] == "mailto:d@e.com"


def test_parse_dmarc_record_rejects_non_dmarc():
    assert parse_dmarc_record("v=spf1 -all") is None
    assert parse_dmarc_record("some random txt") is None


# ── Alignment ─────────────────────────────────────────────────────────

def test_alignment_relaxed_same_org_domain():
    assert check_alignment("mail.example.com", "billing.example.com") is True


def test_alignment_strict_requires_exact_host():
    assert check_alignment("mail.example.com", "billing.example.com",
                           strict=True) is False
    assert check_alignment("example.com", "example.com", strict=True) is True


def test_alignment_differs_across_orgs():
    assert check_alignment("evil.example", "paypal.com") is False


def test_alignment_missing_domain_false():
    assert check_alignment(None, "example.com") is False
    assert check_alignment("example.com", None) is False


# ── run_dns_checks integration ────────────────────────────────────────

def test_run_dns_checks_full_record_set():
    zone = {
        ("example.com", "TXT"): ["v=spf1 ip4:203.0.113.5 -all"],
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=quarantine;"],
        ("s1._domainkey.example.com", "TXT"): ["p=MIGfMA0GCSq..."],
    }
    result = run_dns_checks(
        from_domain="example.com",
        sender_ip="203.0.113.5",
        dkim_domain="example.com",
        dkim_selector="s1",
        resolver=make_resolver(zone),
    )
    assert result.spf_result == "pass"
    assert result.dmarc_record is not None
    assert result.dmarc_policy == "quarantine"
    assert result.dkim_key_present is True
    assert result.errors == []


def test_run_dns_checks_graceful_on_dns_failure():
    def broken(domain, rdtype):
        raise OSError("timeout")

    result = run_dns_checks(
        from_domain="example.com",
        sender_ip="203.0.113.5",
        dkim_domain=None,
        dkim_selector=None,
        resolver=broken,
    )
    assert result.spf_result is None
    assert any("spf_lookup_failed" in e for e in result.errors)
