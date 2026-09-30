"""Tests for origin-trace construction over Received chains."""

from datetime import datetime

from app.engines.intel.origin import build_origin_trace
from app.engines.headers.received_parser import parse_received_chain


def _chain():
    return parse_received_chain([
        "from mx.receiver.org (mx.receiver.org [192.0.2.1]) by localhost; "
        "Mon, 01 Jan 2026 12:03:00 +0000",
        "from relay.example.org (relay.example.org [198.51.100.10]) "
        "by mx.receiver.org; Mon, 01 Jan 2026 12:02:00 +0000",
        "from origin.example.net (origin.example.net [203.0.113.50]) "
        "by relay.example.org; Mon, 01 Jan 2026 12:01:00 +0000",
        "from localhost (localhost [127.0.0.1]) by origin.example.net; "
        "Mon, 01 Jan 2026 12:00:00 +0000",
    ])


def test_origin_is_first_external_hop():
    trace = build_origin_trace(_chain())
    assert trace is not None
    assert trace.ip == "203.0.113.50"
    assert trace.hop_index == 1          # hop 0 (localhost) skipped
    assert trace.from_host == "origin.example.net"
    assert trace.is_internal is False
    assert trace.timestamp_utc == datetime(2026, 1, 1, 12, 1)


def test_origin_dict_serializable():
    d = build_origin_trace(_chain()).to_dict()
    assert d["ip"] == "203.0.113.50"
    assert d["timestamp_utc"].startswith("2026-01-01")


def test_all_internal_chain_falls_back_to_first_ip():
    hops = [
        {"from_ip": "10.0.0.5", "is_internal": True, "from_host": "mx1"},
        {"from_ip": "10.0.0.6", "is_internal": True, "from_host": "mx2"},
    ]
    trace = build_origin_trace(hops)
    assert trace.ip == "10.0.0.5"
    assert trace.is_internal is True


def test_empty_chain_returns_none():
    assert build_origin_trace([]) is None
    assert build_origin_trace([{"from_ip": None}]) is None


def test_accepts_orm_like_objects():
    class HopRow:
        from_ip = "203.0.113.9"
        from_host = "h.example"
        helo = None
        by_host = "mx.example"
        timestamp_utc = datetime(2026, 1, 1, 0, 0)
        is_internal = False

    trace = build_origin_trace([HopRow()])
    assert trace.ip == "203.0.113.9"
    assert trace.hop_index == 0
