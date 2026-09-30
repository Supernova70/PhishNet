"""Tests for Authentication-Results / Received-SPF / DKIM-Signature parsing."""

from app.engines.headers.auth_parser import (
    compute_alignment,
    parse_auth_headers,
)


GOOGLE_STYLE = (
    "mx.google.com; spf=pass smtp.mailfrom=example.com "
    "dkim=pass header.d=example.com dmarc=pass header.from=example.com"
)


def test_parses_google_style_auth_results():
    summary = parse_auth_headers({"authentication-results": [GOOGLE_STYLE]})
    assert summary.spf_result == "pass"
    assert summary.spf_domain == "example.com"
    assert summary.dkim_result == "pass"
    assert summary.dkim_domain == "example.com"
    assert summary.dmarc_result == "pass"
    assert summary.dmarc_domain == "example.com"
    assert summary.source == "header"


def test_parses_failure_verdicts():
    summary = parse_auth_headers({
        "authentication-results": [
            "mail.corp.example; spf=fail smtp.mailfrom=evil.example "
            "dkim=fail header.d=evil.example dmarc=fail header.from=bank.example"
        ]
    })
    assert summary.spf_result == "fail"
    assert summary.dkim_result == "fail"
    assert summary.dmarc_result == "fail"


def test_received_spf_legacy_header():
    summary = parse_auth_headers({
        "received-spf": [
            "pass (google.com: domain of sender@legit.example "
            "designates 203.0.113.5 as permitted sender) receiver=google.com"
        ]
    })
    assert summary.spf_result == "pass"
    assert summary.spf_domain == "legit.example"


def test_dkim_signature_gives_signer_without_verdict():
    summary = parse_auth_headers({
        "dkim-signature": [
            "v=1; a=rsa-sha256; d=signer.example; s=selector1; "
            "bh=abc; b=def"
        ]
    })
    assert summary.dkim_domain == "signer.example"
    assert summary.dkim_selector == "selector1"
    # No Authentication-Results → no verdict, source stays none
    assert summary.dkim_result is None
    assert summary.source == "none"


def test_no_auth_headers():
    summary = parse_auth_headers({})
    assert summary.source == "none"
    assert summary.spf_result is None


def test_multiple_auth_headers_prefers_non_none_spf():
    summary = parse_auth_headers({
        "authentication-results": [
            "relay.example; spf=none smtp.mailfrom=example.com",
            "mx.example; spf=pass smtp.mailfrom=example.com dmarc=pass header.from=example.com",
        ]
    })
    assert summary.spf_result == "pass"


def test_alignment_aligned_on_pass():
    summary = parse_auth_headers({"authentication-results": [GOOGLE_STYLE]})
    compute_alignment(summary, "Support Team <billing@example.com>")
    assert summary.alignment == "aligned"


def test_alignment_mismatched_when_domains_differ():
    summary = parse_auth_headers({
        "authentication-results": [
            "mx.example; spf=pass smtp.mailfrom=attacker.example "
            "dmarc=fail header.from=paypal.com"
        ]
    })
    compute_alignment(summary, "PayPal Security <alert@paypal.com>")
    assert summary.alignment == "mismatched"


def test_alignment_unknown_without_evidence():
    summary = parse_auth_headers({})
    compute_alignment(summary, "someone@example.com")
    assert summary.alignment == "unknown"
