"""
Scan Service — Orchestrates the analysis pipeline.

Given an email, runs all available analysis engines, computes
a verdict, and stores the results in the database.
"""

import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.engines.attachment_analyzer import AttachmentAnalyzer
from app.engines.text_analyzer import get_text_analyzer
from app.engines.url_analyzer import UrlAnalyzer
from app.models.email import Email
from app.models.scan import Classification, Scan, ScanStatus, Verdict
from app.models.url_result import UrlResult

logger = logging.getLogger(__name__)


class ScanService:
    """Orchestrates the full email analysis pipeline."""

    def __init__(self, db: Session):
        self.db = db

    def run_scan_by_id(self, scan_id: int) -> Optional[Scan]:
        """Load an existing scan and execute it."""
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None

        email = scan.email
        if not email:
            scan.status = ScanStatus.ERROR.value
            self.db.commit()
            return scan

        scan.status = ScanStatus.RUNNING.value
        scan.started_at = datetime.utcnow()
        self.db.commit()
        return self._execute_pipeline(scan, email)

    def run_scan(self, email: Email) -> Scan:
        """Create a scan and execute it immediately."""
        scan = Scan(
            email_id=email.id,
            status=ScanStatus.RUNNING.value,
            started_at=datetime.utcnow(),
        )
        self.db.add(scan)
        self.db.flush()
        return self._execute_pipeline(scan, email)

    def _execute_pipeline(self, scan: Scan, email: Email) -> Scan:
        """
        Execute the full email analysis pipeline.

        Runs:
            1. ML Text Analysis    → ai_score
            2. URL Analysis        → url_score  (+ writes url_results rows)
            3. Attachment Analysis → attachment_score
            4. Probabilistic final score + Verdict
        """
        try:
            # ── 1. ML Text Analysis ──────────────────────────────
            text_analyzer = get_text_analyzer()
            text = email.body_text or email.body_html or ""
            ai_result = text_analyzer.analyze(text)
            ai_score = ai_result.confidence
            ai_label = ai_result.label

            # ── 2. URL Analysis ───────────────────────────────────
            url_analyzer = UrlAnalyzer()
            body_text = email.body_text or ""
            body_html = email.body_html or ""
            url_result = url_analyzer.analyze(body_text, body_html, scan_id=scan.id)
            url_score = url_result.url_score

            # Persist each URL result row
            for ur in url_result.per_url_results:
                db_url = UrlResult(
                    scan_id=scan.id,
                    original_url=ur.original_url,
                    normalized_url=ur.normalized_url,
                    is_shortener=ur.is_shortener,
                    heuristic_score=ur.heuristic_score,
                    vt_score=ur.vt_score,
                    final_score=ur.final_score,
                    vt_malicious=ur.vt_malicious,
                    vt_suspicious=ur.vt_suspicious,
                    vt_harmless=ur.vt_harmless,
                    vt_total=ur.vt_total,
                    vt_error=ur.vt_error,
                    heuristic_flags=ur.heuristic_flags,
                    dynamic_score=ur.dynamic_score,
                    redirect_chain=ur.redirect_chain,
                    dom_has_login_form=ur.dom_has_login_form,
                    ssl_valid=ur.ssl_valid,
                    playwright_screenshot_path=ur.playwright_screenshot_path,
                )
                self.db.add(db_url)

            # ── 3. Attachment Analysis ────────────────────────────
            attachment_analyzer = AttachmentAnalyzer()
            att_result = attachment_analyzer.analyze(email.attachments)
            attachment_score = att_result.attachment_score

            # ── 4. Compute Final Score + Verdict ──────────────────
            final_score = self._compute_final_score(
                ai_score, url_score, attachment_score
            )
            classification = self._classify(final_score)

            verdict = Verdict(
                scan_id=scan.id,
                final_score=final_score,
                classification=classification,
                ai_score=ai_score,
                ai_label=ai_label,
                url_score=url_score,
                attachment_score=attachment_score,
                breakdown={
                    "ai": {
                        "score": ai_score,
                        "label": ai_label,
                        "is_phishing": ai_result.is_phishing,
                    },
                    "url": {
                        "score": url_score,
                        "total_urls": url_result.total_urls if url_result else 0,
                        "analyzed_urls": url_result.analyzed_urls if url_result else 0,
                        "vt_checked_urls": url_result.vt_checked_urls
                        if url_result
                        else 0,
                        "high_risk_urls": url_result.high_risk_urls
                        if url_result
                        else [],
                        "per_url": [
                            {
                                "url": u.original_url,
                                "score": u.final_score,
                                "vt_malicious": u.vt_malicious,
                                "vt_suspicious": u.vt_suspicious,
                                "vt_harmless": u.vt_harmless,
                                "vt_total": u.vt_total,
                                "vt_error": u.vt_error,
                                "top_flags": (
                                    (u.heuristic_flags or []) + (u.dynamic_flags or [])
                                )[:8],
                                "heuristic_score": u.heuristic_score,
                                "vt_score": u.vt_score,
                                "dynamic_score": u.dynamic_score,
                                "final_score": u.final_score,
                                "dynamic_status": u.dynamic_status,
                                "dynamic_flags": u.dynamic_flags,
                                "dynamic_error": u.dynamic_error,
                                "final_url": u.final_url,
                                "redirect_chain": u.redirect_chain,
                                "dom_has_login_form": u.dom_has_login_form,
                                "ssl_valid": u.ssl_valid,
                                "external_form_action": u.external_form_action,
                                "download_attempted": u.download_attempted,
                                "popup_attempted": u.popup_attempted,
                                "dynamic_elapsed_ms": u.dynamic_elapsed_ms,
                                "playwright_screenshot_path": u.playwright_screenshot_path,
                                "screenshot_url": (
                                    f"/artifacts/url-screenshots/{scan.id}/"
                                    f"{Path(u.playwright_screenshot_path).name}"
                                    if u.playwright_screenshot_path
                                    else None
                                ),
                            }
                            for u in (url_result.per_url_results if url_result else [])
                        ],
                    },
                    "attachment": {
                        "score": att_result.attachment_score,
                        "total_files": att_result.total_files,
                        "analyzed_files": att_result.analyzed_files,
                        "high_risk_files": att_result.high_risk_files,
                        "per_file": att_result.per_file_results,
                    },
                },
            )
            self.db.add(verdict)

            scan.status = ScanStatus.COMPLETE.value
            scan.completed_at = datetime.utcnow()
            self.db.commit()
            self.db.refresh(scan)

            # Publish SSE event for real-time updates
            try:
                from app.api.scan import publish_scan_event
                publish_scan_event(scan.id, {
                    "type": "complete",
                    "scan_id": scan.id,
                    "classification": classification,
                    "final_score": final_score,
                    "ai_score": ai_score,
                    "url_score": url_score,
                    "attachment_score": attachment_score,
                })
            except Exception:
                pass  # SSE publish failure should not block scan

            logger.info(
                f"Scan {scan.id} complete: "
                f"ai={ai_score:.1f} url={url_score:.1f} att={attachment_score:.1f} "
                f"→ final={final_score:.1f} ({classification})"
            )
            return scan

        except Exception as e:
            import traceback

            scan.status = ScanStatus.ERROR.value
            scan.completed_at = datetime.utcnow()
            self.db.commit()
            logger.error(
                f"Scan {scan.id} failed: {type(e).__name__}: {e}\n{traceback.format_exc()}"
            )
            raise

    def _compute_final_score(
        self, ai_score: float, url_score: float, attachment_score: float
    ) -> float:
        """
        Probabilistic risk accumulation.

        P(risk) = 1 - (1 - p_ai)(1 - p_url)(1 - p_att)

        Each input is 0-100, output is 0-100.
        """
        p_ai = min(ai_score, 100.0) / 100.0
        p_url = min(url_score, 100.0) / 100.0
        p_att = min(attachment_score, 100.0) / 100.0

        p_safe = (1.0 - p_ai) * (1.0 - p_url) * (1.0 - p_att)
        final = (1.0 - p_safe) * 100.0

        return round(min(100.0, final), 1)

    def _classify(self, score: float) -> str:
        """Map a 0-100 score to a classification label."""
        if score >= 70.0:
            return Classification.DANGEROUS.value
        elif score >= 30.0:
            return Classification.SUSPICIOUS.value
        else:
            return Classification.SAFE.value
