"""Tests for the Received-header chain parser."""

from datetime import datetime

from app.engines.headers.received_parser import (
    chain_is_monotonic,
    origin_hop,
    parse_received_chain,
    parse_received_hop,
)


# ── Single-hop parsing ────────────────────────────────────────────────

def test_parses_standard_from_with_bracketed_ip():
    hop = parse_received_hop(
        "from mail.example.com (mail.example.com [203.0.113.5]) "
        "by mx.receiver.net with ESMTPS id abc123; "
        "Mon, 01 Jan 2026 12:00:00 +0000"
    )
    assert hop.from_host == "mail.example.com"
    assert hop.from_ip == "203.0.113.5"
    assert hop.by_host == "mx.receiver.net"
    assert hop.protocol == "ESMTPS"
    assert hop.timestamp_utc == datetime(2026, 1, 1, 12, 0, 0)
    assert hop.parse_confidence >= 0.8


def test_parses_forged_unknown_ehlo_form():
    hop = parse_received_hop(
        "from unknown (EHLO evil.example.org) [198.51.100.23] "
        "by mx.example.com with ESMTP; Mon, 01 Jan 2026 12:05:00 +0000"
    )
    assert hop.from_ip == "198.51.100.23"
    assert hop.helo == "evil.example.org"


def test_parses_helo_directive():
    hop = parse_received_hop(
        "from legit.example.com (helo=legit.example.com) [192.0.2.10] "
        "by inbox.example.net; Mon, 01 Jan 2026 12:01:00 +0000"
    )
    assert hop.helo == "legit.example.com"
    assert hop.from_ip == "192.0.2.10"


def test_missing_timestamp_yields_none_and_lower_confidence():
    hop = parse_received_hop("from host.example.com (host.example.com [203.0.113.7])")
    assert hop.timestamp_utc is None
    assert hop.parse_confidence < 1.0


def test_invalid_octet_ip_rejected():
    hop = parse_received_hop("from bad.example.com (bad [999.1.2.3]) by mx.example.com")
    assert hop.from_ip is None  # 999 is not a valid IPv4 octet


def test_private_ip_marked_internal():
    hop = parse_received_hop(
        "from localhost (localhost [127.0.0.1]) by mail.example.com; "
        "Mon, 01 Jan 2026 12:00:00 +0000"
    )
    assert hop.is_internal is True


def test_global_ip_marked_external():
    hop = parse_received_hop(
        "from out.example.com (out.example.com [203.0.113.9]) "
        "by mx.example.com; Mon, 01 Jan 2026 12:00:00 +0000"
    )
    assert hop.is_internal is False


def test_ipv6_bracketed_address():
    hop = parse_received_hop(
        "from v6.example.com (v6.example.com [2001:db8::1]) "
        "by mx.example.com; Mon, 01 Jan 2026 12:00:00 +0000"
    )
    assert hop.from_ip == "2001:db8::1"


# ── Chain-level parsing ───────────────────────────────────────────────

def _chain_headers():
    """Newest-first, exactly as stored in a message."""
    return [
        # hop 3 (most recent, receiving MTA side)
        "from mx.receiver.net (mx.receiver.net [192.0.2.1]) by localhost "
        "with ESMTPS; Mon, 01 Jan 2026 12:03:00 +0000",
        # hop 2 (relay)
        "from relay.example.org (relay.example.org [198.51.100.10]) "
        "by mx.receiver.net; Mon, 01 Jan 2026 12:02:00 +0000",
        # hop 1 (origin MTA)
        "from origin.example.net (origin.example.net [203.0.113.50]) "
        "by relay.example.org; Mon, 01 Jan 2026 12:01:00 +0000",
        # hop 0 (client submission, internal)
        "from localhost (localhost [127.0.0.1]) by origin.example.net "
        "with ESMTP; Mon, 01 Jan 2026 12:00:00 +0000",
    ]


def test_chain_reversed_to_chronological_order():
    hops = parse_received_chain(_chain_headers())
    assert len(hops) == 4
    # hop 0 is the earliest (localhost submission)
    assert hops[0].from_ip == "127.0.0.1"
    assert hops[0].timestamp_utc <= hops[1].timestamp_utc <= hops[2].timestamp_utc
    assert hops[-1].from_ip == "192.0.2.1"  # most recent last


def test_origin_is_first_external_hop():
    hops = parse_received_chain(_chain_headers())
    origin = origin_hop(hops)
    assert origin is not None
    # localhost (127.0.0.1) is internal → skipped
    assert origin.from_ip == "203.0.113.50"


def test_origin_none_when_no_ips():
    hops = parse_received_chain(["no parseable trace here"])
    assert origin_hop(hops) is None


def test_monotonic_chain_true():
    assert chain_is_monotonic(parse_received_chain(_chain_headers())) is True


def test_non_monotonic_chain_detected():
    headers = [
        "from relay.example.org (relay [198.51.100.10]) by mx.example.com; "
        "Mon, 01 Jan 2026 12:02:00 +0000",
        "from origin.example.net (origin [203.0.113.50]) by relay.example.org; "
        "Mon, 01 Jan 2026 12:05:00 +0000",  # 3 min LATER than the hop that follows it
    ]
    hops = parse_received_chain(headers)
    assert chain_is_monotonic(hops) is False


def test_empty_input_empty_chain():
    assert parse_received_chain([]) == []
