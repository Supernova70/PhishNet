"""End-to-end tests for the HeaderAnalyzer orchestration layer."""

from app.engines.header_analyzer import HeaderAnalyzer


CLEAN_HEADERS = {
    "from": ["Billing Dept <billing@example.com>"],
    "to": ["victim@receiver.org"],
    "subject": ["Monthly statement"],
    "message-id": ["<abc123@example.com>"],
    "return-path": ["<billing@example.com>"],
    "date": ["Mon, 01 Jan 2026 12:00:00 +0000"],
    "authentication-results": [
        "mx.receiver.org; spf=pass smtp.mailfrom=example.com "
        "dkim=pass header.d=example.com dmarc=pass header.from=example.com"
    ],
    "received": [
        "from mx.receiver.org (mx.receiver.org [192.0.2.1]) by localhost; "
        "Mon, 01 Jan 2026 12:01:00 +0000",
        "from mail.example.com (mail.example.com [203.0.113.5]) "
        "by mx.receiver.org with ESMTPS; Mon, 01 Jan 2026 12:00:30 +0000",
        "from submit.example.com (submit.example.com [203.0.113.4]) "
        "by mail.example.com; Mon, 01 Jan 2026 12:00:00 +0000",
    ],
}

SPOOF_HEADERS = {
    "from": ["PayPal Security <alert@secure-paypal.session-validate.tk>"],
    "to": ["victim@receiver.org"],
    "subject": ["Your account is suspended"],
    "message-id": ["<x@evil-mail.ru>"],
    "reply-to": ["collections@attacker-mail.ru"],
    "date": ["Mon, 01 Jan 2026 12:00:00 +0000"],
    # No Authentication-Results, no Received at all
}


def test_clean_email_scores_low():
    result = HeaderAnalyzer(settings=_settings()).analyze(CLEAN_HEADERS)
    assert result.present is True
    assert result.score < 10
    assert result.origin_ip == "203.0.113.4"
    assert len(result.hops) == 3
    assert result.auth.spf_result == "pass"
    assert result.auth.alignment == "aligned"


def test_spoofed_email_scores_high_with_explained_flags():
    result = HeaderAnalyzer(settings=_settings()).analyze(SPOOF_HEADERS)
    assert result.present is True
    assert result.score >= 60
    joined = " | ".join(result.flags)
    assert "display" in joined.lower()          # brand display-name spoof
    assert "Reply-To" in joined                 # reply-to hijack
    assert "Received" in joined                 # missing chain
    assert "Message-ID" in joined               # mid domain mismatch
    # Every point has a rule entry
    assert len(result.rules) >= 4


def test_no_headers_present_false_score_zero():
    result = HeaderAnalyzer(settings=_settings()).analyze(None)
    assert result.present is False
    assert result.score == 0.0
    assert result.flags  # explains why evidence is absent


def test_non_monotonic_timestamps_flagged():
    headers = dict(CLEAN_HEADERS)
    headers["received"] = [
        # Newest-first storage: the MTA closest to the receiver claims
        # an EARLIER time than the hop that follows it → chain decreases.
        "from relay.example.org (relay [198.51.100.10]) by mx.receiver.org; "
        "Mon, 01 Jan 2026 12:00:00 +0000",
        "from mail.example.com (mail [203.0.113.5]) by relay.example.org; "
        "Mon, 01 Jan 2026 12:05:00 +0000",
    ]
    result = HeaderAnalyzer(settings=_settings()).analyze(headers)
    assert any("not increasing" in f for f in result.flags)


def test_dns_checks_with_fake_resolver():
    """HEADER_DNS_CHECKS_ENABLED + injected resolver → SPF verdict from DNS."""

    def fake_resolver(domain: str, rdtype: str):
        if domain == "example.com" and rdtype == "TXT":
            return ["v=spf1 ip4:203.0.113.0/24 -all"]
        if domain == "_dmarc.example.com" and rdtype == "TXT":
            return ["v=DMARC1; p=quarantine;"]
        if domain.endswith("._domainkey.example.com") and rdtype == "TXT":
            return ["p=MIGfMA0GCSq..."]
        raise OSError("NXDOMAIN")

    analyzer = HeaderAnalyzer(settings=_settings(dns_enabled=True),
                              resolver=fake_resolver)
    result = analyzer.analyze(CLEAN_HEADERS)
    assert result.auth.spf_result == "pass"          # origin IP in ip4 range
    assert result.auth.dmarc_result == "pass"        # aligned + spf pass
    assert result.auth.source in ("dns", "both")


def test_dns_spf_fail_when_origin_outside_range():
    def fake_resolver(domain: str, rdtype: str):
        if domain == "example.com" and rdtype == "TXT":
            return ["v=spf1 ip4:192.0.2.0/24 -all"]  # origin NOT in range
        if domain == "_dmarc.example.com" and rdtype == "TXT":
            return ["v=DMARC1; p=reject;"]
        raise OSError("NXDOMAIN")

    analyzer = HeaderAnalyzer(settings=_settings(dns_enabled=True),
                              resolver=fake_resolver)
    result = analyzer.analyze(CLEAN_HEADERS)
    assert result.auth.spf_result == "fail"
    # SPF fail must raise the header score
    assert result.score >= 30


def test_esp_envelope_mismatch_not_scored_when_auth_passes():
    """SES-style mail: envelope/tracking domains differ from From but
    SPF+DKIM+DMARC all pass → architecture, not hijacking."""
    headers = {
        "from": ["Amazon Web Services <billing@aws.com>"],
        "to": ["victim@receiver.org"],
        "subject": ["AWS GST Invoice Available"],
        "message-id": ["<abc@email.amazonses.com>"],
        "return-path": ["<bounce-123@amazonses.com>"],
        "date": ["Mon, 01 Jan 2026 12:00:00 +0000"],
        "authentication-results": [
            "mx.receiver.org; spf=pass smtp.mailfrom=amazonses.com "
            "dkim=pass header.d=aws.com dmarc=pass header.from=aws.com"
        ],
        "received": [
            "from mx.receiver.org (mx.receiver.org [192.0.2.1]) by localhost; "
            "Mon, 01 Jan 2026 12:01:00 +0000",
            "from a1-85.smtp-out.amazonses.com (a1-85 [54.240.11.85]) "
            "by mx.receiver.org with ESMTPS; Mon, 01 Jan 2026 12:00:30 +0000",
        ],
    }
    result = HeaderAnalyzer(settings=_settings()).analyze(headers)
    rules = {r["rule"] for r in result.rules}
    assert "return_path_mismatch" not in rules
    assert "message_id_mismatch" not in rules
    assert "display_name_spoof" not in rules   # aws.com is amazon's
    assert result.score < 10


def test_return_path_mismatch_still_scored_without_auth():
    headers = {
        "from": ["Billing Dept <billing@example.com>"],
        "to": ["victim@receiver.org"],
        "subject": ["Monthly statement"],
        "message-id": ["<abc123@example.com>"],
        "return-path": ["<bounce@mailers-esp.net>"],
        "date": ["Mon, 01 Jan 2026 12:00:00 +0000"],
        # no Authentication-Results → envelope not validated
        "received": [
            "from mx.receiver.org (mx.receiver.org [192.0.2.1]) by localhost; "
            "Mon, 01 Jan 2026 12:01:00 +0000",
            "from mail.example.com (mail.example.com [203.0.113.5]) "
            "by mx.receiver.org; Mon, 01 Jan 2026 12:00:30 +0000",
        ],
    }
    result = HeaderAnalyzer(settings=_settings()).analyze(headers)
    assert any(r["rule"] == "return_path_mismatch" for r in result.rules)


def test_display_name_spoof_survives_passing_auth():
    """DMARC pass does not excuse a display name naming a brand that does
    not own the From domain."""
    headers = {
        "from": ["PayPal Inc <alerts@paypa1-secure.tk>"],
        "to": ["victim@receiver.org"],
        "subject": ["Your PayPal reward is waiting"],
        "message-id": ["<x@paypa1-secure.tk>"],
        "return-path": ["<alerts@paypa1-secure.tk>"],
        "date": ["Mon, 01 Jan 2026 12:00:00 +0000"],
        "authentication-results": [
            "mx.receiver.org; spf=pass smtp.mailfrom=paypa1-secure.tk "
            "dkim=pass header.d=paypa1-secure.tk "
            "dmarc=pass header.from=paypa1-secure.tk"
        ],
        "received": [
            "from mx.receiver.org (mx.receiver.org [192.0.2.1]) by localhost; "
            "Mon, 01 Jan 2026 12:01:00 +0000",
            "from mail.paypa1-secure.tk (mail.paypa1-secure.tk [203.0.113.9]) "
            "by mx.receiver.org; Mon, 01 Jan 2026 12:00:30 +0000",
        ],
    }
    result = HeaderAnalyzer(settings=_settings()).analyze(headers)
    assert any(r["rule"] == "display_name_spoof" for r in result.rules)


def _settings(dns_enabled: bool = False):
    """Minimal Settings stand-in (avoids .env dependence)."""
    from app.config import Settings

    return Settings(
        HEADER_DNS_CHECKS_ENABLED=dns_enabled,
        DATABASE_URL="postgresql://u:p@localhost/db",
    )
