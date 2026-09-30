import pytest
from unittest.mock import MagicMock, patch

from app.engines.header_analyzer import HeaderAnalysisResult
from app.models.email import Email
from app.models.scan import Verdict
from app.services.scan_service import ScanService


def _last_verdict(db):
    """Latest Verdict among db.add calls (evidence rows may trail it)."""
    return next(
        c[0][0]
        for c in reversed(db.add.call_args_list)
        if isinstance(c[0][0], Verdict)
    )


class TestScanService:

    @patch("app.services.scan_service.get_text_analyzer")
    @patch("app.services.scan_service.AttachmentAnalyzer")
    @patch("app.services.scan_service.UrlAnalyzer")
    def test_scan_aggregates_scores(self, MockUrl, MockAtt, mock_get_text):
        db = MagicMock()

        # ── Engine mocks ──────────────────────────────────
        mock_text = MagicMock()
        mock_text.analyze.return_value.confidence = 50.0
        mock_text.analyze.return_value.label = "Phishing"
        mock_text.analyze.return_value.is_phishing = True
        mock_get_text.return_value = mock_text

        mock_url = MagicMock()
        mock_url.analyze.return_value.url_score = 60.0
        mock_url.analyze.return_value.total_urls = 1
        mock_url.analyze.return_value.analyzed_urls = 1
        mock_url.analyze.return_value.vt_checked_urls = 0
        mock_url.analyze.return_value.high_risk_urls = []
        mock_url.analyze.return_value.per_url_results = []
        MockUrl.return_value = mock_url

        mock_att = MagicMock()
        mock_att.analyze.return_value.attachment_score = 10.0
        mock_att.analyze.return_value.total_files = 1
        mock_att.analyze.return_value.analyzed_files = 1
        mock_att.analyze.return_value.high_risk_files = []
        mock_att.analyze.return_value.per_file_results = []
        MockAtt.return_value = mock_att

        email = Email(id=1, body_text="Test", attachments=[])

        service = ScanService(db)
        # Header evidence present with score 0 → same math as legacy
        header_result = HeaderAnalysisResult(present=True, score=0.0)
        with patch.object(
            ScanService, "_analyze_headers", return_value=header_result
        ):
            service._execute_pipeline(MagicMock(id=1), email)

        # p_safe = (1 - 0.5) * (1 - 0.6) * (1 - 0.1) * (1 - 0.0)
        #        = 0.5 * 0.4 * 0.9 = 0.18 → final = 82.0
        verdict = _last_verdict(db)
        assert verdict.final_score == 82.0
        assert verdict.classification == "dangerous"
        assert verdict.header_score == 0.0
        assert verdict.breakdown["header"]["present"] is True
        assert "score" in verdict.breakdown["header"]

    @patch("app.services.scan_service.get_text_analyzer")
    @patch("app.services.scan_service.AttachmentAnalyzer")
    @patch("app.services.scan_service.UrlAnalyzer")
    def test_header_score_contributes_to_verdict(
        self, MockUrl, MockAtt, mock_get_text
    ):
        db = MagicMock()

        mock_text = MagicMock()
        mock_text.analyze.return_value.confidence = 0.0
        mock_text.analyze.return_value.label = "Legitimate"
        mock_text.analyze.return_value.is_phishing = False
        mock_get_text.return_value = mock_text

        mock_url = MagicMock()
        mock_url.analyze.return_value.url_score = 0.0
        mock_url.analyze.return_value.total_urls = 0
        mock_url.analyze.return_value.analyzed_urls = 0
        mock_url.analyze.return_value.vt_checked_urls = 0
        mock_url.analyze.return_value.high_risk_urls = []
        mock_url.analyze.return_value.per_url_results = []
        MockUrl.return_value = mock_url

        mock_att = MagicMock()
        mock_att.analyze.return_value.attachment_score = 0.0
        mock_att.analyze.return_value.total_files = 0
        mock_att.analyze.return_value.analyzed_files = 0
        mock_att.analyze.return_value.high_risk_files = []
        mock_att.analyze.return_value.per_file_results = []
        MockAtt.return_value = mock_att

        email = Email(id=2, body_text="bland", attachments=[])
        header_result = HeaderAnalysisResult(
            present=True,
            score=80.0,
            flags=["SPF returned 'fail'"],
        )

        service = ScanService(db)
        with patch.object(
            ScanService, "_analyze_headers", return_value=header_result
        ):
            service._execute_pipeline(MagicMock(id=2), email)

        verdict = _last_verdict(db)
        # p_safe = (1)(1)(1)(1 - 0.8) = 0.2 → final = (1 - 0.2) * 100 = 80.0
        assert verdict.header_score == 80.0
        assert verdict.final_score == 80.0
        assert verdict.classification == "dangerous"
        assert verdict.breakdown["header"]["flags"] == ["SPF returned 'fail'"]


class TestFusion:
    """Direct math checks for the 4-signal probabilistic fusion."""

    def _service(self):
        return ScanService(MagicMock())

    def test_no_signals_scores_zero(self):
        assert self._service()._compute_final_score(0, 0, 0, 0) == 0.0

    def test_legacy_three_signal_formula_unchanged(self):
        svc = self._service()
        # Matches README example: AI=40, URL=70, ATT=10 → 83.8
        assert svc._compute_final_score(40, 70, 10, 0) == 83.8

    def test_header_signal_raises_risk(self):
        svc = self._service()
        base = svc._compute_final_score(40, 70, 10, 0)
        with_header = svc._compute_final_score(40, 70, 10, 50)
        assert with_header > base
        # p_safe = 0.6*0.3*0.9*0.5 = 0.081 → 91.9
        assert with_header == 91.9

    def test_missing_header_evidence_does_not_penalize(self):
        svc = self._service()
        assert svc._compute_final_score(30, 30, 30, 0) == svc._compute_final_score(
            30, 30, 30
        )

    def test_all_signals_maxed_capped_at_100(self):
        assert self._service()._compute_final_score(100, 100, 100, 100) == 100.0

    def test_negative_header_clamped_to_zero(self):
        svc = self._service()
        assert svc._compute_final_score(10, 10, 10, -5) == svc._compute_final_score(
            10, 10, 10, 0
        )

    @pytest.mark.parametrize(
        "score,expected",
        [(29.9, "safe"), (30.0, "suspicious"), (69.9, "suspicious"),
         (70.0, "dangerous")],
    )
    def test_classification_thresholds(self, score, expected):
        assert self._service()._classify(score) == expected


class TestCorroborationCap:
    """Legit-labeled ML with an authenticated envelope and every other
    channel clean cannot cross the flagging threshold on its own."""

    @staticmethod
    def _mocks(mock_get_text, MockUrl, MockAtt, confidence):
        mock_text = MagicMock()
        mock_text.analyze.return_value.confidence = confidence
        mock_text.analyze.return_value.label = "Legitimate"
        mock_text.analyze.return_value.is_phishing = False
        mock_get_text.return_value = mock_text

        mock_url = MagicMock()
        mock_url.analyze.return_value.url_score = 0.0
        mock_url.analyze.return_value.total_urls = 0
        mock_url.analyze.return_value.analyzed_urls = 0
        mock_url.analyze.return_value.vt_checked_urls = 0
        mock_url.analyze.return_value.high_risk_urls = []
        mock_url.analyze.return_value.per_url_results = []
        MockUrl.return_value = mock_url

        mock_att = MagicMock()
        mock_att.analyze.return_value.attachment_score = 0.0
        mock_att.analyze.return_value.total_files = 0
        mock_att.analyze.return_value.analyzed_files = 0
        mock_att.analyze.return_value.high_risk_files = []
        mock_att.analyze.return_value.per_file_results = []
        MockAtt.return_value = mock_att

    @patch("app.services.scan_service.get_text_analyzer")
    @patch("app.services.scan_service.AttachmentAnalyzer")
    @patch("app.services.scan_service.UrlAnalyzer")
    def test_ml_capped_when_envelope_authenticated(
        self, MockUrl, MockAtt, mock_get_text
    ):
        from app.engines.headers.auth_parser import AuthSummary

        self._mocks(mock_get_text, MockUrl, MockAtt, confidence=64.6)
        db = MagicMock()
        email = Email(id=21, body_text="Token Harbor verification", attachments=[])
        header_result = HeaderAnalysisResult(
            present=True,
            score=0.0,
            auth=AuthSummary(
                spf_result="pass", dkim_result="pass", dmarc_result="pass"
            ),
        )
        service = ScanService(db)
        with patch.object(
            ScanService, "_analyze_headers", return_value=header_result
        ):
            service._execute_pipeline(MagicMock(id=21), email)

        verdict = _last_verdict(db)
        # Damped 10+(64.6-10)*0.5 = 37.3 → capped to 25
        assert verdict.breakdown["ai"]["ml_score"] == 64.6
        assert verdict.ai_score == 25.0
        assert verdict.final_score < 30.0
        assert any("ml_residual_capped" in f for f in verdict.breakdown["ai"]["flags"])

    @patch("app.services.scan_service.get_text_analyzer")
    @patch("app.services.scan_service.AttachmentAnalyzer")
    @patch("app.services.scan_service.UrlAnalyzer")
    def test_ml_not_capped_without_authentication(
        self, MockUrl, MockAtt, mock_get_text
    ):
        self._mocks(mock_get_text, MockUrl, MockAtt, confidence=64.6)
        db = MagicMock()
        email = Email(id=22, body_text="Verify your email", attachments=[])
        header_result = HeaderAnalysisResult(present=True, score=0.0)
        service = ScanService(db)
        with patch.object(
            ScanService, "_analyze_headers", return_value=header_result
        ):
            service._execute_pipeline(MagicMock(id=22), email)

        verdict = _last_verdict(db)
        # No auth evidence → plain sub-threshold damping only: 37.3
        assert verdict.ai_score == 10.0 + (64.6 - 10.0) * 0.5


class TestBecLookalikeIntegration:
    """BEC categories and lookalike domains raise the combined AI signal."""

    @staticmethod
    def _engines_zero(mock_get_text, MockUrl, MockAtt):
        mock_text = MagicMock()
        mock_text.analyze.return_value.confidence = 5.0   # ML says benign
        mock_text.analyze.return_value.label = "Legitimate"
        mock_text.analyze.return_value.is_phishing = False
        mock_get_text.return_value = mock_text

        mock_url = MagicMock()
        mock_url.analyze.return_value.url_score = 0.0
        mock_url.analyze.return_value.total_urls = 0
        mock_url.analyze.return_value.analyzed_urls = 0
        mock_url.analyze.return_value.vt_checked_urls = 0
        mock_url.analyze.return_value.high_risk_urls = []
        mock_url.analyze.return_value.per_url_results = []
        MockUrl.return_value = mock_url

        mock_att = MagicMock()
        mock_att.analyze.return_value.attachment_score = 0.0
        mock_att.analyze.return_value.total_files = 0
        mock_att.analyze.return_value.analyzed_files = 0
        mock_att.analyze.return_value.high_risk_files = []
        mock_att.analyze.return_value.per_file_results = []
        MockAtt.return_value = mock_att

    @patch("app.services.scan_service.get_text_analyzer")
    @patch("app.services.scan_service.AttachmentAnalyzer")
    @patch("app.services.scan_service.UrlAnalyzer")
    def test_bec_category_drives_ai_score(self, MockUrl, MockAtt, mock_get_text):
        self._engines_zero(mock_get_text, MockUrl, MockAtt)
        db = MagicMock()

        email = Email(
            id=11,
            sender="Billing <billing@vendor-payments.example>",
            subject="Updated payment details",
            body_text=(
                "Our bank account details have changed. Please wire the "
                "payment to the new account and update the beneficiary. "
                "Kindly make the payment today to avoid service interruption."
            ),
            attachments=[],
        )
        header_result = HeaderAnalysisResult(present=False, flags=["none"])

        service = ScanService(db)
        with patch.object(
            ScanService, "_analyze_headers", return_value=header_result
        ):
            service._execute_pipeline(MagicMock(id=11), email)

        verdict = _last_verdict(db)
        assert verdict.ai_score >= 70.0          # BEC drove the AI signal
        assert verdict.ai_score > 5.0            # ...above the ML score
        ai_block = verdict.breakdown["ai"]
        assert ai_block["ml_score"] == 5.0
        assert ai_block["bec"]["categories"]
        assert any(f.startswith("bec:") for f in ai_block["flags"])

    @patch("app.services.scan_service.get_text_analyzer")
    @patch("app.services.scan_service.AttachmentAnalyzer")
    @patch("app.services.scan_service.UrlAnalyzer")
    def test_lookalike_sender_drives_ai_score(
        self, MockUrl, MockAtt, mock_get_text
    ):
        self._engines_zero(mock_get_text, MockUrl, MockAtt)
        db = MagicMock()

        email = Email(
            id=12,
            sender="PayPal Security <alert@paypa1.com>",
            subject="Confirm your account",
            body_text="Routine notice, nothing to do.",
            attachments=[],
        )
        header_result = HeaderAnalysisResult(present=False, flags=["none"])

        service = ScanService(db)
        with patch.object(
            ScanService, "_analyze_headers", return_value=header_result
        ):
            service._execute_pipeline(MagicMock(id=12), email)

        verdict = _last_verdict(db)
        assert verdict.ai_score == 85.0          # homoglyph lookalike
        ai_block = verdict.breakdown["ai"]
        assert ai_block["lookalike"]["matched_brand"] == "paypal"
        assert any("lookalike:paypal" in f for f in ai_block["flags"])

    @patch("app.services.scan_service.get_text_analyzer")
    @patch("app.services.scan_service.AttachmentAnalyzer")
    @patch("app.services.scan_service.UrlAnalyzer")
    def test_clean_email_keeps_ml_score(self, MockUrl, MockAtt, mock_get_text):
        self._engines_zero(mock_get_text, MockUrl, MockAtt)
        db = MagicMock()

        email = Email(
            id=13,
            sender="Alice <alice@example.org>",
            subject="Lunch tomorrow?",
            body_text="Want to grab lunch at 1pm? Let me know.",
            attachments=[],
        )
        header_result = HeaderAnalysisResult(present=False, flags=["none"])

        service = ScanService(db)
        with patch.object(
            ScanService, "_analyze_headers", return_value=header_result
        ):
            service._execute_pipeline(MagicMock(id=13), email)

        verdict = _last_verdict(db)
        assert verdict.ai_score == 5.0           # max(5, 0, 0)
        assert verdict.breakdown["ai"]["flags"] == []
