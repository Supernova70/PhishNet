"""
Scan Service — Orchestrates the analysis pipeline.

Given an email, runs all available analysis engines, computes
a verdict, and stores the results in the database.

SIH 26106: the pipeline now includes header forensics (Received chain,
SPF/DKIM/DMARC, relay anomalies) as a fourth signal in the
probabilistic fusion: p_safe = (1-p_ai)(1-p_url)(1-p_att)(1-p_header).
"""

import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.engines.attachment_analyzer import AttachmentAnalyzer
from app.engines.bec_analyzer import analyze_bec
from app.engines.correlation.attribution import AttributionInputs, attribute
from app.engines.correlation.ioc_store import extract_indicators, store_indicators
from app.engines.header_analyzer import HeaderAnalysisResult, HeaderAnalyzer
from app.engines.headers.common import domain_of
from app.engines.intel.domain_intel import sender_is_young
from app.engines.lookalike import analyze_lookalike
from app.engines.text_analyzer import get_text_analyzer, scan_body_yara
from app.engines.url_analyzer import UrlAnalyzer
from app.models.email import Email
from app.models.ip_intel import IpIntel
from app.models.scan import Classification, Scan, ScanStatus, Verdict
from app.models.url_result import UrlResult

logger = logging.getLogger(__name__)


class ScanService:
    """Orchestrates the full email analysis pipeline."""

    def __init__(self, db: Session):
        self.db = db

    def run_scan_by_id(self, scan_id: int) -> Optional[Scan]:
        """Atomically claim a pending scan and execute it.

        The UPDATE ... WHERE status='pending' claim makes dispatch safe with
        multiple uvicorn workers / a startup requeue: only one caller can
        flip the row to RUNNING, everyone else skips. Previously the status
        was set unconditionally, so two workers could run the same pipeline
        concurrently and double-write verdicts, indicators and alerts.
        """
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None

        email = scan.email
        if not email:
            scan.status = ScanStatus.ERROR.value
            self.db.commit()
            return scan

        claimed = (
            self.db.query(Scan)
            .filter(Scan.id == scan_id, Scan.status == ScanStatus.PENDING.value)
            .update(
                {
                    Scan.status: ScanStatus.RUNNING.value,
                    Scan.started_at: datetime.utcnow(),
                },
                synchronize_session=False,
            )
        )
        self.db.commit()
        if not claimed:
            logger.info(
                "Scan %s already claimed or no longer pending — skipping",
                scan_id,
            )
            return None
        return self._execute_pipeline(scan, email)

    def run_scan(self, email: Email) -> Scan:
        """Create a scan and execute it immediately."""
        scan = Scan(
            email_id=email.id,
            user_id=email.user_id,
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
            1. ML Text Analysis    → ml score (raw confidence)
            2. Header Forensics    → header_score + envelope validation
            3. URL Analysis        → url_score  (+ writes url_results rows)
            4. BEC + lookalike     → combined ai_score (ML evidence damped
                                     and, when every other channel is clean
                                     and the envelope is authenticated,
                                     capped — see corroboration note below)
            5. Attachment Analysis → attachment_score
            6. Probabilistic final score + Verdict
        """
        try:
            # ── 1. ML Text Analysis ──────────────────────────────
            text_analyzer = get_text_analyzer()
            text = email.body_text or email.body_html or ""
            ai_result = text_analyzer.analyze(text)
            ml_score = ai_result.confidence
            ai_label = ai_result.label

            # ── 2. Header Forensics ──────────────────────────────
            header_result = self._analyze_headers(email)
            header_score = header_result.score
            # Envelope validated: DMARC passed (aligned with From), or
            # SPF passed for Return-Path AND DKIM passed for From.
            envelope_validated = header_result.auth.dmarc_result == "pass" or (
                header_result.auth.spf_result == "pass"
                and header_result.auth.dkim_result == "pass"
            )

            # ── 3. URL Analysis ──────────────────────────────────
            url_analyzer = UrlAnalyzer()
            body_text = email.body_text or ""
            body_html = email.body_html or ""
            url_result = url_analyzer.analyze(
                body_text,
                body_html,
                scan_id=scan.id,
                sender_domain=domain_of(email.sender) if email.sender else None,
                sender_authenticated=envelope_validated,
            )
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
                    # Dynamic detail columns (migration 0003)
                    dynamic_status=ur.dynamic_status,
                    dynamic_flags=ur.dynamic_flags,
                    dynamic_error=ur.dynamic_error,
                    final_url=ur.final_url,
                    external_form_action=ur.external_form_action,
                    download_attempted=ur.download_attempted,
                    popup_attempted=ur.popup_attempted,
                    dynamic_elapsed_ms=ur.dynamic_elapsed_ms,
                )
                self.db.add(db_url)

            # ── 2b. BEC categories + lookalike domains (rules) ────
            headers_map = self._headers_for(email)
            bec_result = analyze_bec(
                subject=email.subject or "",
                body=text,
                headers=headers_map,
            )
            domains = [domain_of(email.sender)]
            reply_to = (headers_map.get("reply-to") or [None])[0]
            if reply_to:
                domains.append(domain_of(reply_to))
            for ur in url_result.per_url_results:
                domains.append(ur.original_url)
            lk_result = analyze_lookalike([d for d in domains if d])

            # ── 3. Attachment Analysis ────────────────────────────
            attachment_analyzer = AttachmentAnalyzer()
            att_result = attachment_analyzer.analyze(email.attachments)
            attachment_score = att_result.attachment_score

            # Combined AI signal: strongest of ML / BEC / lookalike
            # (ML label stays authoritative; flags record other drivers).
            # Sub-threshold ML probability (model still labels the mail
            # "Legitimate") counts as half-weight evidence: the model is
            # known to emit 30–65% on legitimate urgent mail — receipts,
            # newsletters, registration deadlines (see PHISHING_THRESHOLD
            # rationale in text_analyzer). Tiny probabilities stay as-is.
            if ai_result.is_phishing or ml_score <= 10.0:
                ml_evidence = ml_score
            else:
                ml_evidence = 10.0 + (ml_score - 10.0) * 0.5
            # Corroboration cap: the envelope is authenticated (SPF+DKIM
            # pass or DMARC pass) and headers, URLs and attachments are
            # all clean → a lone ML signal must not flag the mail on its
            # own. Sub-threshold model output is capped at 25 (cannot
            # cross the 30 flag threshold); a model that claims
            # "Phishing" (>=65) with zero corroboration anywhere — no
            # header anomalies, no risky URLs, no attachments, no BEC or
            # lookalike evidence — is capped at 49 (suspicious, never
            # dangerous) and flagged as uncorroborated.
            ml_capped = False
            ml_cap_flag = ""
            if (
                not ai_result.is_phishing
                and envelope_validated
                and header_score < 10
                and url_score < 10
                and attachment_score == 0
                and ml_evidence > 25.0
            ):
                ml_evidence = 25.0
                ml_capped = True
                ml_cap_flag = (
                    "ml_residual_capped: envelope authenticated, "
                    "all channels clean"
                )
            elif (
                ai_result.is_phishing
                and envelope_validated
                and header_score == 0
                and url_score == 0
                and attachment_score == 0
                and bec_result.bec_score == 0
                and lk_result.score == 0
                and ml_evidence > 49.0
            ):
                ml_evidence = 49.0
                ml_capped = True
                ml_cap_flag = (
                    "ml_uncorroborated_capped: lone ML claim on fully "
                    "authenticated mail with every other channel clean "
                    "cannot exceed suspicious"
                )
            ai_score = max(ml_evidence, bec_result.bec_score, lk_result.score)
            # Content rules over the body text (plan §5 B7) — flags only.
            ai_flags = (
                list(bec_result.flags)
                + list(lk_result.flags)
                + scan_body_yara(text)
            )
            if ml_capped:
                ai_flags.append(ml_cap_flag)

            # ── 5. Compute Final Score + Verdict ──────────────────
            final_score = self._compute_final_score(
                ai_score, url_score, attachment_score, header_score
            )
            classification = self._classify(final_score)

            # ── 5b. Attribution verdict (pure, evidence-based) ────
            ipintel = self._cached_ip_intel(header_result.origin_ip)
            attribution = attribute(
                AttributionInputs(
                    spf_result=header_result.auth.spf_result,
                    dkim_result=header_result.auth.dkim_result,
                    dmarc_result=header_result.auth.dmarc_result,
                    alignment=header_result.auth.alignment,
                    display_name_spoof=any(
                        "display name" in f.lower() for f in header_result.flags
                    ),
                    replyto_mismatch=any(
                        "reply-to" in f.lower() for f in header_result.flags
                    ),
                    internal_sender=bool(header_result.hops)
                    and header_result.hops[0].is_internal,
                    bec_score=bec_result.bec_score,
                    lookalike_score=lk_result.score,
                    origin_is_vpn=bool(ipintel and ipintel.is_vpn),
                    origin_is_tor=bool(ipintel and ipintel.is_tor),
                    origin_is_proxy=bool(ipintel and ipintel.is_proxy),
                    origin_is_hosting=bool(ipintel and ipintel.is_hosting),
                    origin_dnsbl_listed=bool(
                        ipintel and ipintel.is_dnsbl_listed
                    ),
                    young_domain=sender_is_young(domain_of(email.sender)),
                    no_tls=self._no_transport_tls(header_result.hops),
                )
            )

            verdict = Verdict(
                scan_id=scan.id,
                final_score=final_score,
                classification=classification,
                ai_score=ai_score,
                ai_label=ai_label,
                url_score=url_score,
                attachment_score=attachment_score,
                header_score=header_score,
                breakdown={
                    "ai": {
                        "score": ai_score,
                        "ml_score": ml_score,
                        "label": ai_label,
                        "is_phishing": ai_result.is_phishing,
                        "bec": bec_result.to_dict(),
                        "lookalike": lk_result.to_dict(),
                        "flags": ai_flags,
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
                    "header": {
                        "score": header_result.score,
                        "present": header_result.present,
                        "flags": header_result.flags,
                        "rules": header_result.rules,
                        "origin_ip": header_result.origin_ip,
                        "origin_host": header_result.origin_host,
                        "hop_count": len(header_result.hops),
                        "auth": header_result.auth.to_dict(),
                        "errors": header_result.errors,
                    },
                    "attribution": attribution.to_dict(),
                },
            )
            self.db.add(verdict)

            # ── 6. Indicator extraction for correlation ──────────
            try:
                pairs = extract_indicators(
                    sender=email.sender,
                    headers=headers_map,
                    subject=email.subject or "",
                    attachments=email.attachments,
                    url_domains=[
                        u.original_url for u in url_result.per_url_results
                    ],
                    origin_ip=header_result.origin_ip,
                    lookalike_brand=lk_result.matched_brand,
                )
                store_indicators(self.db, scan.id, pairs, user_id=scan.user_id)
            except Exception as exc:  # correlation must never fail a scan
                logger.error(
                    f"Indicator extraction failed for scan {scan.id}: {exc}"
                )

            # ── 7. Chain-of-custody: append evidence row ─────────
            try:
                from app.services.evidence_service import append_evidence

                source = email.source
                append_evidence(
                    self.db,
                    email_id=email.id,
                    scan_id=scan.id,
                    raw_sha256=source.raw_sha256 if source else None,
                    actor="scanner",
                    user_id=scan.user_id,
                )
            except Exception as exc:  # custody must never fail a scan
                logger.error(
                    f"Evidence append failed for scan {scan.id}: {exc}"
                )

            # ── 7b. Feed alert when a trigger fired ─────────────
            try:
                from app.services.alert_service import build_alert

                alert = build_alert(
                    scan_id=scan.id,
                    email_id=email.id,
                    score=final_score,
                    classification=classification,
                    breakdown=verdict.breakdown,
                    subject=email.subject,
                    sender=email.sender,
                    user_id=scan.user_id,
                )
                if alert is not None:
                    self.db.add(alert)
            except Exception as exc:  # alerting must never fail a scan
                logger.error(f"Alert build failed for scan {scan.id}: {exc}")

            scan.status = ScanStatus.COMPLETE.value
            scan.completed_at = datetime.utcnow()
            self.db.commit()
            self.db.refresh(scan)

            # Publish SSE event for real-time updates
            try:
                from app.api.scan import publish_scan_event
                publish_scan_event(scan.id, {
                    "user_id": scan.user_id,
                    "type": "complete",
                    "scan_id": scan.id,
                    "classification": classification,
                    "final_score": final_score,
                    "ai_score": ai_score,
                    "url_score": url_score,
                    "attachment_score": attachment_score,
                    "header_score": header_score,
                })
            except Exception:
                pass  # SSE publish failure should not block scan

            logger.info(
                f"Scan {scan.id} complete: "
                f"ai={ai_score:.1f} url={url_score:.1f} att={attachment_score:.1f} "
                f"hdr={header_score:.1f} → final={final_score:.1f} ({classification})"
            )
            return scan

        except Exception as e:
            import traceback

            scan.status = ScanStatus.ERROR.value
            scan.completed_at = datetime.utcnow()
            self.db.commit()
            try:
                from app.api.scan import publish_scan_event

                publish_scan_event(
                    scan.id,
                    {"type": "error", "scan_id": scan.id, "user_id": scan.user_id},
                    user_id=scan.user_id,
                )
            except Exception:
                pass  # SSE publish failure should not block error handling
            logger.error(
                f"Scan {scan.id} failed: {type(e).__name__}: {e}\n{traceback.format_exc()}"
            )
            raise

    def _headers_for(self, email: Email) -> dict:
        """Retained header map for an email ({} when evidence absent)."""
        try:
            source = email.source
        except Exception:
            source = None
        if source is None or not source.headers_json:
            return {}
        return source.headers_json

    def _cached_ip_intel(self, ip: Optional[str]):
        """Existing IpIntel row for attribution (DB-only, never network).

        Expired cache rows are ignored so stale reputation does not
        influence a fresh verdict; missing rows simply mean "unknown".
        """
        if not ip:
            return None
        try:
            row = (
                self.db.query(IpIntel).filter(IpIntel.ip == ip).first()
            )
            if row is None:
                return None
            if row.expires_at is not None and row.expires_at <= datetime.utcnow():
                return None
            return row
        except Exception:  # noqa: BLE001 — attribution must never fail a scan
            return None

    @staticmethod
    def _no_transport_tls(hops) -> bool:
        """True when a Received chain exists but no hop negotiated TLS.

        Unknown/absent hop protocols yield False (absent evidence is not
        risk); any hop advertising STARTTLS/TLS-family protocol clears it.
        """
        if not hops:
            return False
        protocols = [
            str(h.protocol).upper()
            for h in hops
            if getattr(h, "protocol", None)
        ]
        if not protocols:
            return False
        tls_hints = (
            "ESMTPS", "ESMTPA", "ESMTPN", "SMTPS",
            "SUBMISSIONS", "STARTTLS", "TLS",
        )
        return not any(hint in proto for hint in tls_hints for proto in protocols)

    def _analyze_headers(self, email: Email) -> HeaderAnalysisResult:
        """
        Run header forensics against the email's retained raw headers.

        Emails fetched before raw retention have no EmailSource row; they
        score 0 with an explanatory flag (absent evidence is not risk).
        """
        headers_map = self._headers_for(email)
        if not headers_map:
            return HeaderAnalysisResult(
                present=False,
                flags=["No raw header evidence retained for this email"],
            )
        try:
            return HeaderAnalyzer().analyze(headers_map)
        except Exception as exc:  # forensics must never fail the scan
            logger.error(f"Header analysis failed for email {email.id}: {exc}")
            return HeaderAnalysisResult(
                present=True,
                errors=[f"header_analysis_error: {exc}"],
            )

    def _compute_final_score(
        self,
        ai_score: float,
        url_score: float,
        attachment_score: float,
        header_score: float = 0.0,
    ) -> float:
        """
        Probabilistic risk accumulation.

        P(risk) = 1 - (1 - p_ai)(1 - p_url)(1 - p_att)(1 - p_header)

        Each input is 0-100, output is 0-100. Missing header evidence
        contributes p_header = 0, so absence never raises risk.
        """
        p_ai = min(ai_score, 100.0) / 100.0
        p_url = min(url_score, 100.0) / 100.0
        p_att = min(attachment_score, 100.0) / 100.0
        p_header = min(max(header_score, 0.0), 100.0) / 100.0

        p_safe = (1.0 - p_ai) * (1.0 - p_url) * (1.0 - p_att) * (1.0 - p_header)
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
