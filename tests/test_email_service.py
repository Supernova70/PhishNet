from email.message import EmailMessage
from unittest.mock import MagicMock, patch

import gzip
import hashlib

import pytest

from app.models.email import Email
from app.services import email_service as email_service_mod
from app.services.email_service import EmailService

RAW_MESSAGE = (
    b"From: Billing <billing@example.com>\r\n"
    b"To: victim@receiver.org\r\n"
    b"Subject: Statement\r\n"
    b"Message-ID: <raw-roundtrip@example.com>\r\n"
    b"\r\n"
    b"Your monthly statement.\r\n"
)

HEADERS = {
    "from": ["Billing <billing@example.com>"],
    "to": ["victim@receiver.org"],
    "subject": ["Statement"],
    "message-id": ["<raw-roundtrip@example.com>"],
    "authentication-results": [
        "mx.receiver.org; spf=pass smtp.mailfrom=example.com "
        "dkim=pass header.d=example.com dmarc=pass header.from=example.com"
    ],
    "received": [
        "from mx.receiver.org (mx.receiver.org [192.0.2.1]) by localhost; "
        "Mon, 01 Jan 2026 12:03:00 +0000",
        "from relay.example.org (relay.example.org [198.51.100.10]) "
        "by mx.receiver.org; Mon, 01 Jan 2026 12:02:00 +0000",
        "from origin.example.net (origin.example.net [203.0.113.50]) "
        "by relay.example.org; Mon, 01 Jan 2026 12:01:00 +0000",
        "from localhost (localhost [127.0.0.1]) by origin.example.net; "
        "Mon, 01 Jan 2026 12:00:00 +0000",
    ],
}


def _settings_stub(raw_dir, preserve=True):
    class _Stub:
        PRESERVE_RAW_EMAIL = preserve
        raw_email_dir = raw_dir
    return _Stub()


def _added(db):
    return [call.args[0] for call in db.add.call_args_list]


class TestRawEvidenceRetention:

    def test_gzip_roundtrip_and_chain_of_custody(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            email_service_mod, "settings", _settings_stub(str(tmp_path))
        )
        db = MagicMock()
        email_obj = Email(id=42)

        EmailService(db)._store_email_source(email_obj, RAW_MESSAGE, HEADERS)

        # On-disk gzipped copy decompresses to the exact original bytes
        raw_file = tmp_path / "42.eml.gz"
        assert raw_file.exists()
        with gzip.open(raw_file, "rb") as fh:
            assert fh.read() == RAW_MESSAGE

        source = [r for r in _added(db) if type(r).__name__ == "EmailSource"][0]
        assert source.email_id == 42
        assert source.raw_sha256 == hashlib.sha256(RAW_MESSAGE).hexdigest()
        assert source.size_bytes == len(RAW_MESSAGE)
        assert source.headers_json == HEADERS

    def test_received_hops_stored_chronologically(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            email_service_mod, "settings", _settings_stub(str(tmp_path))
        )
        db = MagicMock()
        EmailService(db)._store_email_source(Email(id=1), RAW_MESSAGE, HEADERS)

        hops = [
            r for r in _added(db) if type(r).__name__ == "ReceivedHop"
        ]
        assert len(hops) == 4
        assert [h.hop_index for h in hops] == [0, 1, 2, 3]
        # hop 0 = earliest (client submission), hop 3 = closest to receiver
        assert hops[0].from_ip == "127.0.0.1"
        assert hops[0].timestamp_utc < hops[-1].timestamp_utc
        assert hops[3].from_ip == "192.0.2.1"

    def test_auth_result_persisted_with_alignment(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            email_service_mod, "settings", _settings_stub(str(tmp_path))
        )
        db = MagicMock()
        EmailService(db)._store_email_source(Email(id=1), RAW_MESSAGE, HEADERS)

        auth = [r for r in _added(db) if type(r).__name__ == "AuthResult"]
        assert len(auth) == 1
        assert auth[0].spf_result == "pass"
        assert auth[0].dkim_result == "pass"
        assert auth[0].dmarc_result == "pass"
        assert auth[0].alignment == "aligned"
        assert auth[0].source == "header"

    def test_preserve_disabled_stores_headers_without_raw_file(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            email_service_mod, "settings", _settings_stub(str(tmp_path), preserve=False)
        )
        db = MagicMock()
        EmailService(db)._store_email_source(Email(id=7), RAW_MESSAGE, HEADERS)

        source = [r for r in _added(db) if type(r).__name__ == "EmailSource"][0]
        assert source.raw_path is None
        assert source.raw_sha256 is None
        assert source.headers_json == HEADERS
        assert list(tmp_path.iterdir()) == []

    def test_evidence_failure_never_raises(self, tmp_path, monkeypatch):
        # raw_email_dir points at a regular file → makedirs fails →
        # ingestion must swallow the error and continue.
        blocker = tmp_path / "blocker"
        blocker.write_text("not a dir")
        monkeypatch.setattr(
            email_service_mod, "settings", _settings_stub(str(blocker))
        )
        db = MagicMock()

        EmailService(db)._store_email_source(Email(id=9), RAW_MESSAGE, HEADERS)

        assert db.add.call_count == 0  # nothing half-written either


class TestEmailService:
    @patch("app.services.email_service.IMAPClient")
    def test_message_id_and_fallback(self, mock_imap_cls):
        db = MagicMock()
        db.query().filter().first.return_value = None  # No duplicates

        service = EmailService(db)

        # Proper Message-ID
        msg1 = EmailMessage()
        msg1["Message-ID"] = "<proper-id-123@domain.com>"
        msg1.set_content("Test")

        # Missing Message-ID (Fallback)
        msg2 = EmailMessage()
        msg2["From"] = "sender@domain.com"
        msg2["Subject"] = "Hello"
        msg2["Date"] = "Wed, 13 Apr 2026"
        msg2.set_content("Test 2")

        # Mock client
        mock_client = MagicMock()
        mock_client.search.return_value = [1, 2]

        # Mock fetch results
        mock_client.fetch.side_effect = [
            {1: {b"RFC822": msg1.as_bytes()}},
            {2: {b"RFC822": msg2.as_bytes()}},
        ]
        mock_imap_cls.return_value = mock_client

        service._fetch_from_imap(10)

        assert mock_client.search.called
        assert mock_client.fetch.call_count == 2

    def test_filename_sanitization(self):
        service = EmailService(MagicMock())
        safe = service._sanitize_filename("../../etc/passwd", "b4hashxxx")
        assert safe == "b4hashxx_passwd"
        assert "/" not in safe
        assert "\\" not in safe
        assert safe.startswith("b4hashxx_")


class TestParseMimeExtendedKeys:
    """plan §4 B8 — convenience keys alongside the verbatim headers."""

    RAW = (
        b"From: Billing <billing@example.com>\r\n"
        b"To: victim@receiver.org\r\n"
        b"Cc: audit@receiver.org, boss@receiver.org\r\n"
        b"Subject: Statement\r\n"
        b"Message-ID: <ext-keys@example.com>\r\n"
        b"Date: Mon, 01 Jan 2026 12:00:00 +0000\r\n"
        b"Return-Path: <bounce@example.com>\r\n"
        b"Reply-To: support@other.org\r\n"
        b"X-Mailer: AcmeMail 1.0\r\n"
        b"Received: from mx.example.com (mx.example.com [192.0.2.1])\r\n"
        b"\tby localhost; Mon, 01 Jan 2026 12:03:00 +0000\r\n"
        b"Received: from origin.example.net ([203.0.113.50])\r\n"
        b"\tby mx.example.com; Mon, 01 Jan 2026 12:01:00 +0000\r\n"
        b"\r\n"
        b"Your monthly statement.\r\n"
    )

    def _parsed(self):
        from email import policy
        from email.parser import BytesParser

        msg = BytesParser(policy=policy.default).parsebytes(self.RAW)
        return EmailService(db=None)._parse_mime(msg, self.RAW)

    def test_extended_keys_present(self):
        data = self._parsed()
        assert data["return_path"] == "<bounce@example.com>"
        assert data["reply_to"] == "support@other.org"
        assert data["cc"] == "audit@receiver.org, boss@receiver.org"
        assert data["x_mailer"] == "AcmeMail 1.0"
        # Header continuations are unfolded by the MIME parser.
        assert data["received_raw"] == [
            "from mx.example.com (mx.example.com [192.0.2.1])\t"
            "by localhost; Mon, 01 Jan 2026 12:03:00 +0000",
            "from origin.example.net ([203.0.113.50])\t"
            "by mx.example.com; Mon, 01 Jan 2026 12:01:00 +0000",
        ]

    def test_original_keys_unchanged(self):
        data = self._parsed()
        assert data["message_id"] == "ext-keys@example.com"  # brackets stripped
        assert data["sender"] == "Billing <billing@example.com>"
        assert data["subject"] == "Statement"
        assert data["to_address"] == "victim@receiver.org"
        assert data["body_text"].strip() == "Your monthly statement."
        assert "headers" in data and "raw_bytes" in data

    def test_missing_headers_default_to_empty(self):
        from email import policy
        from email.parser import BytesParser

        raw = (
            b"From: a@example.com\r\n"
            b"Subject: hi\r\n"
            b"Message-ID: <minimal@example.com>\r\n"
            b"\r\n"
            b"ok\r\n"
        )
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        data = EmailService(db=None)._parse_mime(msg, raw)
        assert data["return_path"] == ""
        assert data["reply_to"] == ""
        assert data["cc"] == ""
        assert data["x_mailer"] == ""
        assert data["received_raw"] == []
