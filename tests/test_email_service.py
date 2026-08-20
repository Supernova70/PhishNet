from email.message import EmailMessage
from unittest.mock import MagicMock, patch

from app.services.email_service import EmailService


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
