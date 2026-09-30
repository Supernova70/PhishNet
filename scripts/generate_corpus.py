#!/usr/bin/env python3
"""Generate the 24-file demo corpus in tests/fixtures/eml/.

Deterministic (fixed dates, message-ids) so regenerated files are
byte-identical. Each scenario exercises a specific detection path —
see SCENARIOS for the mapping.
"""

import base64
import textwrap
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "eml"
CRLF = "\r\n"

ORIGIN = "203.0.113.66"
RELAY_IP = "10.0.0.5"


def received_hop(*, frm, ip, by, for_addr, date, helo=None):
    helo_part = f" ({helo})" if helo else ""
    return (
        f"from {frm}{helo_part} [{ip}] by {by} for <{for_addr}>; {date}"
    )


def build(
    *,
    message_id,
    from_,
    to,
    subject,
    date,
    body="",
    received=None,
    auth=None,
    reply_to=None,
    body_html=None,
    extra_headers=None,
    attachment=None,  # (filename, content_bytes, content_type)
):
    lines = []
    for r in received or []:
        lines.append(f"Received: {r}")
    if auth:
        lines.append(f"Authentication-Results: {auth}")
    lines += [
        f"From: {from_}",
        f"To: {to}",
        f"Subject: {subject}",
        f"Message-ID: <{message_id}>",
        f"Date: {date}",
    ]
    if reply_to:
        lines.append(f"Reply-To: {reply_to}")
    for k, v in (extra_headers or {}).items():
        lines.append(f"{k}: {v}")
    lines.append("MIME-Version: 1.0")

    if attachment:
        fname, content, ctype = attachment
        boundary = f"----=_Part_{message_id}"
        lines.append(f'Content-Type: multipart/mixed; boundary="{boundary}"')
        head = CRLF.join(lines) + CRLF + CRLF
        part1 = (
            f"--{boundary}{CRLF}"
            f'Content-Type: text/plain; charset="utf-8"{CRLF}{CRLF}'
            f"{body}{CRLF}"
        )
        part2 = (
            f"--{boundary}{CRLF}"
            f"Content-Type: {ctype}; name=\"{fname}\"{CRLF}"
            f"Content-Transfer-Encoding: base64{CRLF}"
            f'Content-Disposition: attachment; filename="{fname}"{CRLF}{CRLF}'
            + base64.b64encode(content).decode() + CRLF
        )
        tail = f"--{boundary}--{CRLF}"
        return (head + part1 + part2 + tail).encode("utf-8")

    if body_html is not None:
        lines.append('Content-Type: text/html; charset="utf-8"')
        head = CRLF.join(lines) + CRLF + CRLF
        return (head + body_html).encode("utf-8")

    lines.append('Content-Type: text/plain; charset="utf-8"')
    head = CRLF.join(lines) + CRLF + CRLF
    return (head + body + CRLF).encode("utf-8")


def hop_newest_first(origin_host, origin_ip, relay_host="mx.corp.example",
                     dest="inbox.corp.example", addr="alice@example.com",
                     origin_date="Mon, 05 Jan 2026 09:01:00 +0000",
                     relay_date="Mon, 05 Jan 2026 09:02:00 +0000"):
    """Standard chain: newest (our relay) first, oldest (origin) last."""
    return [
        received_hop(frm=relay_host, ip=RELAY_IP, by=dest, for_addr=addr,
                     date=relay_date, helo=relay_host),
        received_hop(frm=origin_host, ip=origin_ip, by=relay_host,
                     for_addr=addr, date=origin_date, helo=origin_host),
    ]


AUTH_PASS = "mx.corp.example; spf=pass smtp.mailfrom=example.org dkim=pass header.d=example.org dmarc=pass header.from=example.org"
AUTH_FAIL = "mx.corp.example; spf=fail smtp.mailfrom=paypal.com dkim=none dmarc=fail header.from=paypal.com"

D = "Mon, 05 Jan 2026 09:00:00 +0000"

SCENARIOS = []


def scenario(name, spec):
    SCENARIOS.append((name, spec))


# ── clean mail ────────────────────────────────────────────────────────
scenario("clean_newsletter", dict(
    message_id="clean-newsletter-001@newsletter.example.org",
    from_="Weekly Digest <digest@newsletter.example.org>",
    to="alice@example.com",
    subject="Your weekly reading list",
    date=D,
    received=hop_newest_first("mail1.example.org", "198.51.100.10"),
    auth=AUTH_PASS,
    body="Five articles we loved this week. Nothing urgent, no links to "
         "sign in. Unsubscribe anytime from the footer.",
))

scenario("clean_receipt", dict(
    message_id="clean-receipt-002@orders.example.org",
    from_="Orders <orders@example.org>",
    to="alice@example.com",
    subject="Receipt for order #5521",
    date=D,
    received=hop_newest_first("mx1.example.org", "198.51.100.11"),
    auth=AUTH_PASS,
    body="Thanks for your purchase. Order 5521 shipped yesterday. "
         "View details in your account dashboard.",
))

# ── spoofing ──────────────────────────────────────────────────────────
scenario("plain_spoof", dict(
    message_id="plain-spoof-003@evil.example",
    from_="PayPal <service@paypal.com>",
    to="alice@example.com",
    subject="Your account is limited",
    date=D,
    received=hop_newest_first("host.dynamic-isp.net", ORIGIN),
    auth=AUTH_FAIL,
    body="Your account has been limited. Sign in at "
         "https://account-verify.paypa1-secure.net to restore access.",
))

scenario("display_name_spoof", dict(
    message_id="display-spoof-004@random-host.net",
    from_="PayPal Security <spoof@random-host.net>",
    to="alice@example.com",
    subject="Unusual sign-in attempt detected",
    date=D,
    received=hop_newest_first("vps-44.random-host.net", "203.0.113.44"),
    auth="mx.corp.example; spf=pass smtp.mailfrom=random-host.net "
         "dkim=none dmarc=none",
    body="We detected an unusual sign-in attempt on your PayPal account. "
         "Verify your account within 24 hours to avoid suspension.",
))

scenario("spf_dkim_fail", dict(
    message_id="spf-dkim-fail-005@forger.example",
    from_="IT Helpdesk <helpdesk@forger.example>",
    to="alice@example.com",
    subject="Password reset required",
    date=D,
    received=hop_newest_first("relay.bad-net.example", "198.51.100.77"),
    auth="mx.corp.example; spf=fail smtp.mailfrom=forger.example "
         "dkim=fail dmarc=fail header.from=forger.example",
    body="Your password expires today. Update your password immediately "
         "at http://forger.example/reset to keep your mailbox active.",
))

# ── BEC ───────────────────────────────────────────────────────────────
scenario("bec_invoice", dict(
    message_id="bec-invoice-006@fake-vendor-ops.com",
    from_="Billing <billing@fake-vendor-ops.com>",
    to="alice@example.com",
    subject="Invoice INV-88421 overdue — payment due",
    date=D,
    received=hop_newest_first("mail.fake-vendor-ops.com", "203.0.113.90"),
    auth="mx.corp.example; spf=pass smtp.mailfrom=fake-vendor-ops.com "
         "dkim=none dmarc=none",
    body="Please find invoice INV-88421 for $12,480.00. This balance is "
         "outstanding and past due. Kindly make the payment within 24 "
         "hours to avoid service interruption.",
))

scenario("payment_diversion", dict(
    message_id="payment-diversion-007@company-mail.co",
    from_="CEO Marcus Reed <m.reed@company-mail.co>",
    to="alice@example.com",
    subject="Confidential: updated supplier payment",
    date=D,
    received=hop_newest_first("webmail.company-mail.co", "198.51.100.52"),
    auth="mx.corp.example; spf=pass smtp.mailfrom=company-mail.co "
         "dkim=none dmarc=none",
    reply_to="payables@company-mail.co",
    body="Hi, I am tied up in a meeting and cannot call. Our beneficiary "
         "bank account details have changed — please wire the transfer "
         "of $45,000 to the new account today. Keep this between us; "
         "do not discuss with the wider team. Kindly process the payment "
         "before end of day. IBAN GB29NWBK60161331926819, SWIFT NWBKGB2L.",
))

scenario("exec_impersonation", dict(
    message_id="exec-impersonation-008@ceo-urgent-mail.com",
    from_="Marcus Reed, CEO <m.reed@ceo-urgent-mail.com>",
    to="alice@example.com",
    subject="URGENT — need this done immediately",
    date=D,
    received=hop_newest_first("smtp.ceo-urgent-mail.com", "203.0.113.91"),
    auth="mx.corp.example; spf=pass smtp.mailfrom=ceo-urgent-mail.com "
         "dkim=none dmarc=none",
    body="Are you at your desk? I need you to process an urgent wire "
         "transfer immediately — this is top priority and strictly "
         "confidential, between us only. Do not reply to this thread, "
         "reach me on my mobile.",
))

scenario("replyto_hijack", dict(
    message_id="replyto-hijack-009@amex-billing.com",
    from_="Statements <billing@amex-billing.com>",
    to="alice@example.com",
    subject="Your statement is ready to view",
    date=D,
    received=hop_newest_first("mail.amex-billing.com", "198.51.100.63"),
    auth="mx.corp.example; spf=pass smtp.mailfrom=amex-billing.com "
         "dkim=none dmarc=none",
    reply_to="recover@account-verify.ru",
    body="Your monthly statement is ready. Reply to this email if you "
         "need a copy re-sent to a different address.",
))

scenario("dkim_pass_bec", dict(
    message_id="dkim-pass-bec-010@compromised-partner.com",
    from_="Accounts Payable <ap@compromised-partner.com>",
    to="alice@example.com",
    subject="RE: Purchase order PO#7731 — payment details",
    date=D,
    received=hop_newest_first("mail.compromised-partner.com", "198.51.100.88"),
    auth="mx.corp.example; spf=pass smtp.mailfrom=compromised-partner.com "
         "dkim=pass header.d=compromised-partner.com "
         "dmarc=pass header.from=compromised-partner.com",
    body="Following up on PO#7731. Please note our account details have "
         "been updated — payment to the new account only. The outstanding "
         "amount of $8,200.00 is due today; kindly confirm once the wire "
         "transfer is initiated.",
))

# ── lookalikes / harvest ──────────────────────────────────────────────
scenario("lookalike_domain", dict(
    message_id="lookalike-011@paypa1.com",
    from_="PayPal <no-reply@paypa1.com>",
    to="alice@example.com",
    subject="Confirm your identity",
    date=D,
    received=hop_newest_first("mx.paypa1.com", "203.0.113.70"),
    auth="mx.corp.example; spf=pass smtp.mailfrom=paypa1.com "
         "dkim=none dmarc=none",
    body="Confirm your identity to keep your wallet active. Verify your "
         "account details here: https://paypa1.com/confirm",
))

scenario("credential_harvest", dict(
    message_id="credential-harvest-012@login-verify.xyz",
    from_="Mailbox Team <postmaster@login-verify.xyz>",
    to="alice@example.com",
    subject="Action required: verify your mailbox",
    date=D,
    received=hop_newest_first("srv1.login-verify.xyz", "198.51.100.99"),
    auth="mx.corp.example; spf=pass smtp.mailfrom=login-verify.xyz "
         "dkim=none dmarc=none",
    body="Unusual sign-in activity was detected. Your mailbox will be "
         "suspended unless you sign in and verify your account within "
         "12 hours: http://login-verify.xyz/signin",
))

scenario("url_shortener_brand", dict(
    message_id="url-short-013@deals.example.net",
    from_="Account Services <notice@deals.example.net>",
    to="alice@example.com",
    subject="Your PayPal reward is waiting",
    date=D,
    received=hop_newest_first("deals-mail.example.net", "198.51.100.34"),
    auth="mx.corp.example; spf=pass smtp.mailfrom=deals.example.net "
         "dkim=none dmarc=none",
    body="You have been selected for a PayPal reward. Claim it now via "
         "our short link: https://bit.ly/3x-verify-paypal",
))

scenario("young_domain", dict(
    message_id="young-domain-014@secure-delivery-update2026.xyz",
    from_="Delivery Desk <updates@secure-delivery-update2026.xyz>",
    to="alice@example.com",
    subject="Package held — update your details",
    date=D,
    received=hop_newest_first("ns1.secure-delivery-update2026.xyz",
                              "203.0.113.101"),
    auth="mx.corp.example; spf=pass smtp.mailfrom="
         "secure-delivery-update2026.xyz dkim=none dmarc=none",
    body="Your parcel is on hold. Confirm your identity and address "
         "details to reschedule delivery: "
         "https://secure-delivery-update2026.xyz/reschedule",
))

# ── header anomalies ──────────────────────────────────────────────────
scenario("relay_forged", dict(
    message_id="relay-forged-015@anomaly.example",
    from_="Support <support@anomaly.example>",
    to="alice@example.com",
    subject="Ticket #9981 update",
    date=D,
    received=[
        # relay hop stamped BEFORE the origin hop — chain is forged
        received_hop(frm="mx.corp.example", ip=RELAY_IP,
                     by="inbox.corp.example", for_addr="alice@example.com",
                     date="Mon, 05 Jan 2026 09:00:30 +0000"),
        received_hop(frm="host.anomaly.example", ip="198.51.100.120",
                     by="mx.corp.example", for_addr="alice@example.com",
                     date="Mon, 05 Jan 2026 09:05:00 +0000"),
    ],
    auth="mx.corp.example; spf=pass smtp.mailfrom=anomaly.example "
         "dkim=none dmarc=none",
    body="Your support ticket has been updated. No action required.",
))

scenario("missing_received", dict(
    message_id="missing-received-016@forged.direct",
    from_="HR <hr@forged.direct>",
    to="alice@example.com",
    subject="Salary revision document",
    date=D,
    received=None,  # no Received headers at all
    auth=None,
    body="Please open the attached salary revision and confirm the "
         "figures shown are correct.",
))

scenario("tor_origin", dict(
    message_id="tor-origin-017@anon.example",
    from_="Newsletter <blast@anon.example>",
    to="alice@example.com",
    subject="Breaking news digest",
    date=D,
    # historical Tor exit range (exercises the Tor classifier when
    # TOR_EXIT_LIST checks are enabled; offline runs just skip it)
    received=hop_newest_first("tor-exit.example", "185.220.101.5"),
    auth="mx.corp.example; spf=fail smtp.mailfrom=anon.example "
         "dkim=none dmarc=fail header.from=anon.example",
    body="Click here for today's headlines: http://anon.example/now",
))

# ── attachments / HTML ────────────────────────────────────────────────
scenario("html_hidden_link", dict(
    message_id="html-hidden-018@stealth.example",
    from_="Document Share <files@stealth.example>",
    to="alice@example.com",
    subject="Shared document: Q1 forecast",
    date=D,
    received=hop_newest_first("webhook.stealth.example", "198.51.100.140"),
    auth="mx.corp.example; spf=pass smtp.mailfrom=stealth.example "
         "dkim=none dmarc=none",
    body_html=(
        '<html><body style="color:#ffffff;font-size:1px">'
        "<p>Q1 forecast attached.</p>"
        '<div><a href="http://stealth.example/login">'
        "Open the document</a></div>"
        '<span style="display:none"><a href='
        '"http://stealth.example/session">click</a></span>'
        "</body></html>"
    ),
))

scenario("double_extension_attachment", dict(
    message_id="double-ext-019@invoice-desk.example",
    from_="Invoices <invoices@invoice-desk.example>",
    to="alice@example.com",
    subject="Scanned invoice attached",
    date=D,
    received=hop_newest_first("smtp.invoice-desk.example", "203.0.113.130"),
    auth="mx.corp.example; spf=pass smtp.mailfrom=invoice-desk.example "
         "dkim=none dmarc=none",
    body="Please review the attached invoice and reply with approval.",
    attachment=("invoice.pdf.exe",
                b"MZ\x90\x00fake-payload-for-detector-tests" + b"\x00" * 64,
                "application/octet-stream"),
))

# ── bulk campaign (5 similar) ─────────────────────────────────────────
for i in range(1, 6):
    scenario(f"bulk_campaign_{i:02d}", dict(
        message_id=f"bulk-campaign-019-{i}@parcel-redelivery.org",
        from_="Parcel Service <track@parcel-redelivery.org>",
        to="alice@example.com",
        subject=f"Delivery attempt {1230 + i} failed",
        date=D,
        received=hop_newest_first(f"mx{i}.parcel-redelivery.org",
                                  "203.0.113.20"),
        auth="mx.corp.example; spf=pass smtp.mailfrom=parcel-redelivery.org "
             "dkim=none dmarc=none",
        body=f"We could not deliver parcel #{1230 + i}. Confirm your "
             "address details and pay the $2.99 re-delivery fee: "
             "https://parcel-redelivery.org/track",
    ))


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, spec in SCENARIOS:
        data = build(**spec)
        path = OUT / f"{name}.eml"
        path.write_bytes(data)
    print(f"wrote {len(SCENARIOS)} files to {OUT}")


if __name__ == "__main__":
    main()
