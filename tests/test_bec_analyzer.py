"""Tests for the BEC category rule engine (pure, offline)."""

import pytest

from app.engines.bec_analyzer import (
    CATEGORY_THRESHOLD,
    RULE_TABLE,
    analyze_bec,
    export_bec_labels,
)


# ── payment_diversion ─────────────────────────────────────────────────

def test_payment_diversion_bank_change():
    result = analyze_bec(
        subject="Updated payment details",
        body="Hi, our bank account details have changed. Please wire the "
             "payment to the new account and update the beneficiary in your "
             "records. Kindly make the payment today.",
    )
    cats = {c.category for c in result.categories}
    assert "payment_diversion" in cats
    assert result.bec_score >= CATEGORY_THRESHOLD


def test_payment_diversion_iban_signal():
    result = analyze_bec(
        body="Please wire the transfer to IBAN DE89370400440532013000 urgently."
    )
    assert "payment_diversion" in {c.category for c in result.categories}


# ── fake_invoice ──────────────────────────────────────────────────────

def test_fake_invoice_needs_converging_signals():
    weak = analyze_bec(body="Please see the invoice attached.")
    assert "fake_invoice" not in {c.category for c in weak.categories}

    strong = analyze_bec(
        body="Invoice #4471 for $12,400 is past due — payment due within "
             "3 days. Balance due on the outstanding amount."
    )
    assert "fake_invoice" in {c.category for c in strong.categories}


# ── credential_harvest ────────────────────────────────────────────────

def test_credential_harvest_with_link():
    result = analyze_bec(
        body="Your account has been suspended. Verify your account "
             "identity here: https://login.secure-verify.example/session"
    )
    match = next(
        c for c in result.categories if c.category == "credential_harvest"
    )
    assert match.confidence >= 50
    assert any("link" in e for e in match.evidence)


def test_benign_body_no_categories():
    result = analyze_bec(
        subject="Lunch tomorrow?",
        body="Want to grab lunch at 1pm? Let me know.",
    )
    assert result.categories == []
    assert result.bec_score == 0.0
    assert result.flags == []


# ── executive_impersonation (header-driven) ───────────────────────────

def test_exec_impersonation_replyto_mismatch():
    result = analyze_bec(
        subject="Urgent",
        body="Need this asap, keep this between us.",
        headers={
            "from": ["John Smith, CEO <ceo@company.com>"],
            "reply-to": ["collections@payback.example"],
        },
    )
    match = next(
        c for c in result.categories if c.category == "executive_impersonation"
    )
    assert any("executive title" in e for e in match.evidence)
    assert any("Reply-To domain" in e for e in match.evidence)
    assert match.confidence == 100.0  # 30 + 20 + 30 + 35 capped


def test_no_replyto_mismatch_when_domains_match():
    result = analyze_bec(
        body="quick one asap please",
        headers={
            "from": ["Boss <ceo@company.com>"],
            "reply-to": ["assistant@company.com"],
        },
    )
    match = next(
        (c for c in result.categories if c.category == "executive_impersonation"),
        None,
    )
    if match:
        assert not any("Reply-To" in e for e in match.evidence)


# ── urgency_threat ────────────────────────────────────────────────────

def test_urgency_threat_deadline_and_legal():
    result = analyze_bec(
        body="Failure to respond within 24 hours will result in legal "
             "action. Your account will be closed. Final warning."
    )
    match = next(c for c in result.categories if c.category == "urgency_threat")
    assert any("short deadline" in e for e in match.evidence)
    assert any("legal threat" in e for e in match.evidence)


# ── structure / score semantics ───────────────────────────────────────

def test_bec_score_is_max_category():
    result = analyze_bec(
        body="Your account has been suspended. Verify your account at "
             "https://x.example/login and failure to respond within 24 "
             "hours means legal action and your account closure."
    )
    assert result.categories
    assert result.bec_score == max(c.confidence for c in result.categories)


def test_flags_match_categories():
    result = analyze_bec(
        body="Account suspended — verify your account at https://a.example/x"
    )
    for cat in result.categories:
        assert any(f"bec:{cat.category}" in flag for flag in result.flags)


def test_all_rule_table_categories_are_stable():
    assert set(RULE_TABLE) == {
        "payment_diversion", "fake_invoice", "credential_harvest",
        "executive_impersonation", "urgency_threat",
    }
    for rules in RULE_TABLE.values():
        for pattern, weight, label in rules:
            assert weight > 0
            assert label


def test_to_dict_roundtrip():
    result = analyze_bec(
        body="Account suspended. Verify your account at https://a.example/login"
    )
    d = result.to_dict()
    assert d["bec_score"] >= 40
    assert d["categories"][0]["evidence"]


# ── weak-supervision label export ─────────────────────────────────────

def test_export_bec_labels_csv(tmp_path):
    path = tmp_path / "bec_labels.csv"
    rows = [
        {"text": "wire transfer urgent new account", "category": "payment_diversion"},
        {"text": "lunch tomorrow", "category": "benign"},
        {"text": "verify account suspended"},
    ]
    written = export_bec_labels(rows, str(path))
    assert written == 3
    content = path.read_text().splitlines()
    assert content[0] == "text,category"
    assert "payment_diversion" in content[1]
    assert content[2].endswith(",benign")
    assert content[3].endswith(",benign")  # default applied
