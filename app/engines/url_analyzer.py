import asyncio
import base64
import logging
import math
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import unquote, urlparse

import httpx
from bs4 import BeautifulSoup

from app.config import Settings, get_settings
from app.engines.dynamic.dynamic_url_analyzer import DynamicUrlAnalyzer
from app.engines.dynamic.scoring import registrable_domain

# Redis caching removed — planned for Semester 2

logger = logging.getLogger(__name__)


@dataclass
class UrlAnalysisResult:
    original_url: str
    normalized_url: Optional[str]
    is_shortener: bool = False
    heuristic_score: float = 0.0
    vt_score: float = 0.0
    final_score: float = 0.0
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_harmless: int = 0
    vt_total: int = 0
    vt_error: Optional[str] = None
    heuristic_flags: List[str] = field(default_factory=list)
    dynamic_status: str = "skipped:disabled"
    dynamic_score: float = 0.0
    final_url: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    dom_has_login_form: bool = False
    ssl_valid: Optional[bool] = None
    playwright_screenshot_path: Optional[str] = None
    dynamic_flags: List[str] = field(default_factory=list)
    dynamic_error: Optional[str] = None
    external_form_action: bool = False
    download_attempted: bool = False
    popup_attempted: bool = False
    dynamic_elapsed_ms: int = 0


@dataclass
class UrlEngineResult:
    url_score: float
    total_urls: int
    analyzed_urls: int
    vt_checked_urls: int
    high_risk_urls: List[str]
    per_url_results: List[UrlAnalysisResult]


class UrlAnalyzer:
    """Engine for extracting, scoring, and looking up URLs in email bodies."""

    def __init__(
        self,
        settings: Settings | None = None,
        dynamic_analyzer: DynamicUrlAnalyzer | None = None,
    ):
        self._settings = settings or get_settings()
        self._vt_keys = self._settings.vt_api_keys
        self._vt_key_index = 0
        self._vt_disabled_reason: str | None = None
        self._dynamic_analyzer = dynamic_analyzer

    def analyze(
        self,
        body_text: Optional[str],
        body_html: Optional[str],
        *,
        scan_id: int | None = None,
    ) -> UrlEngineResult:
        urls = self._extract_and_deduplicate(body_text or "", body_html or "")

        results = []
        vt_checked = 0

        for original, normalized in urls:
            result = self._score_heuristic(original, normalized)

            # VirusTotal lookup
            if self._vt_keys:
                if self._check_virustotal(result):
                    vt_checked += 1

            # Aggregate final score
            result.final_score = min(
                100.0, max(result.heuristic_score, result.vt_score)
            )
            results.append(result)

        if self._settings.DYNAMIC_URL_ENABLED and results:
            asyncio.run(self._apply_dynamic_analysis(results, scan_id=scan_id))

        engine_score = max((r.final_score for r in results), default=0.0)
        high_risk = [r.original_url for r in results if r.final_score >= 60.0]

        return UrlEngineResult(
            url_score=engine_score,
            total_urls=len(urls),
            analyzed_urls=len(urls),
            vt_checked_urls=vt_checked,
            high_risk_urls=high_risk,
            per_url_results=results,
        )

    async def _apply_dynamic_analysis(
        self,
        results: List[UrlAnalysisResult],
        *,
        scan_id: int | None,
    ) -> None:
        analyzer = self._dynamic_analyzer or DynamicUrlAnalyzer.from_settings(
            self._settings
        )
        started = time.monotonic()
        visited = 0
        visited_domains: set[str] = set()

        for result in sorted(results, key=lambda item: item.final_score, reverse=True):
            target_url = result.normalized_url or result.original_url
            target_domain = registrable_domain(target_url)
            if target_domain and target_domain in visited_domains:
                result.dynamic_status = "skipped:duplicate_domain"
                continue

            within_budget = (
                visited < self._settings.DYNAMIC_URL_MAX_PER_SCAN
                and time.monotonic() - started
                < self._settings.DYNAMIC_URL_SCAN_BUDGET_SECONDS
            )
            dynamic = await analyzer.analyze(
                target_url,
                static_score=result.final_score,
                vt_malicious=result.vt_malicious,
                is_shortener=result.is_shortener,
                heuristic_flags=result.heuristic_flags,
                scan_id=scan_id,
                within_budget=within_budget,
            )
            if not dynamic.status.startswith("skipped:"):
                visited += 1
                if target_domain:
                    visited_domains.add(target_domain)

            observation = dynamic.observation
            result.dynamic_status = dynamic.status
            result.dynamic_score = dynamic.dynamic_score
            result.final_url = observation.final_url
            result.redirect_chain = observation.redirect_chain
            result.dom_has_login_form = observation.has_login_form
            if observation.tls_error:
                result.ssl_valid = False
            elif observation.attempted and observation.error_code is None:
                result.ssl_valid = True
            else:
                result.ssl_valid = None
            result.playwright_screenshot_path = observation.screenshot_path
            result.dynamic_flags = dynamic.dynamic_flags
            result.dynamic_error = observation.error_detail
            result.external_form_action = observation.external_form_action
            result.download_attempted = observation.download_attempted
            result.popup_attempted = observation.popup_attempted
            result.dynamic_elapsed_ms = observation.elapsed_ms
            result.final_score = min(
                100.0,
                max(result.heuristic_score, result.vt_score, result.dynamic_score),
            )

    # ── STAGE 1: Target Extraction ────────────────────────────────────────――

    def _extract_and_deduplicate(
        self, body_text: str, body_html: str
    ) -> List[Tuple[str, str]]:
        raw_urls = set()

        # From text
        text_regex = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
        raw_urls.update(text_regex.findall(body_text))

        # From HTML
        if body_html:
            soup = BeautifulSoup(body_html, "html.parser")
            for tag in soup.find_all(href=True):
                raw_urls.add(tag["href"])
            # Resource URLs (img/script/iframe src) create noisy candidates and
            # can consume the browser budget. Analyze navigable links and form
            # actions; the browser still observes resources during navigation.
            for tag in soup.find_all(action=True):
                raw_urls.add(tag["action"])

            text_nodes = soup.get_text(separator=" ")
            raw_urls.update(text_regex.findall(text_nodes))

        filtered = []
        seen_normalized = set()

        for url in raw_urls:
            url = url.strip()
            if not url.lower().startswith("http"):
                continue

            normalized = self._normalize(url)
            if not normalized or self._is_local_ip(normalized):
                continue

            if normalized not in seen_normalized:
                seen_normalized.add(normalized)
                filtered.append((url, normalized))

        return sorted(filtered, key=lambda item: item[1])

    def _normalize(self, url: str) -> str:
        try:
            url = unquote(url).strip()
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            host = parsed.netloc.lower()

            # Strip tracking
            query = []
            tracking_prefixes = ("utm_", "fbclid", "gclid", "ref", "mc_")
            if parsed.query:
                for param in parsed.query.split("&"):
                    if not param.lower().startswith(tracking_prefixes):
                        query.append(param)

            new_query = "&".join(query)
            clean_url = f"{scheme}://{host}{parsed.path}"
            if new_query:
                clean_url += f"?{new_query}"

            return clean_url
        except Exception:
            return url

    def _is_local_ip(self, url: str) -> bool:
        try:
            host = urlparse(url).netloc.split(":")[0].lower()
            if host in ("localhost", "127.0.0.1", "0.0.0.0"):
                return True
            if host.startswith("10.") or host.startswith("192.168."):
                return True
            if re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", host):
                return True
            return False
        except Exception:
            return False

    # ── STAGE 2: Static Heuristic Scoring ─────────────────────────────────――

    def _score_heuristic(
        self, original_url: str, normalized_url: str
    ) -> UrlAnalysisResult:
        res = UrlAnalysisResult(
            original_url=original_url, normalized_url=normalized_url
        )
        score = 0.0
        parsed = urlparse(normalized_url)
        hostname = parsed.netloc.split(":")[0]

        parts = hostname.split(".")
        tld = f".{parts[-1]}" if len(parts) > 1 else ""
        registered_domain = registrable_domain(normalized_url) or hostname

        # ── Domain whitelist: known-safe institutional/TLD categories ──
        institutional_tlds = {
            ".edu", ".edu.in", ".ac.in", ".ac.uk", ".gov", ".gov.in",
            ".mil", ".org", ".go.jp", ".gob", ".gouv",
        }
        is_institutional = any(registered_domain.endswith(tld) for tld in institutional_tlds)

        # Known legitimate CDNs/services that contain brand names as substrings
        brand_whitelist_domains = {
            "amazonaws.com", "googleapis.com", "google.com", "cloudfront.net",
            "akamai.net", "akamaized.net", "fastly.net", "fastly.com",
            "cloudflare.com", "azure.com", "azurewebsites.net",
            "github.io", "github.com", "gitlab.io",
            "s3.amazonaws.com", "console.aws.amazon.com",
        }
        is_known_service = any(
            registered_domain == d or registered_domain.endswith(f".{d}")
            for d in brand_whitelist_domains
        )

        # Check 1: HTTP scheme (+15, reduced for institutional)
        if parsed.scheme == "http":
            if is_institutional:
                score += 3  # Much lower penalty for .edu/.gov HTTP
                res.heuristic_flags.append("HTTP connection (institutional domain — low risk)")
            else:
                score += 15
                res.heuristic_flags.append("Unencrypted HTTP connection")

        # Check 2: IP hostname (+35)
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname):
            score += 35
            res.heuristic_flags.append(f"IP address used as hostname: {hostname}")

        # Check 3: Suspicious TLD (+20)
        suspicious_tlds = {
            ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
            ".work", ".site", ".online", ".live", ".link", ".bid", ".win",
            ".download", ".loan", ".gdn", ".rest", ".bar",
        }
        if tld in suspicious_tlds:
            score += 20
            res.heuristic_flags.append(f"High-risk TLD: {tld}")

        # Check 4: URL shortener (+20)
        shorteners = {
            "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
            "short.link", "rebrand.ly", "cutt.ly", "is.gd",
            "buff.ly", "tiny.cc", "adf.ly",
        }
        if registered_domain in shorteners:
            score += 20
            res.is_shortener = True
            res.heuristic_flags.append(f"URL shortener detected: {registered_domain}")

        # Check 5: Brand impersonation (+40) — uses word boundaries, skips known services
        if not is_known_service:
            brands = [
                (r"\bpaypa[l1]\b", "paypal.com"),
                (r"\bg[o0]{2}gle\b", "google.com"),
                (r"\bamaz[o0]n\b(?!aws)", "amazon.com"),  # Negative lookahead for amazonaws
                (r"\b[a4]pp[l1]e\b", "apple.com"),
                (r"\bmicr[o0]s[o0]ft\b", "microsoft.com"),
                (r"\bnetfl[i1]x\b", "netflix.com"),
                (r"\bfac[e3]b[o0]{2}k\b", "facebook.com"),
                (r"\bch[a4]se\b", "chase.com"),
                (r"\bwe[l1]{2}sfarg[o0]\b", "wellsfargo.com"),
            ]
            for pattern, real_domain in brands:
                if re.search(pattern, hostname) and registered_domain != real_domain:
                    match_str = re.search(pattern, hostname).group(0)
                    score += 40
                    res.heuristic_flags.append(
                        f"Brand impersonation: '{match_str}' in host but domain is '{registered_domain}'"
                    )
                    break

        # Check 6: Excessive subdomains (+15, raised threshold for institutional)
        subdomain_threshold = 5 if is_institutional else 4
        if len(parts) >= subdomain_threshold:
            score += 15
            res.heuristic_flags.append(
                f"Excessive subdomains ({len(parts)} levels): {hostname}"
            )

        # Check 7: Long URL (+10, raised threshold for known services)
        long_url_threshold = 400 if is_known_service else 200
        if len(original_url) > long_url_threshold:
            score += 10
            res.heuristic_flags.append(
                f"Unusually long URL ({len(original_url)} chars)"
            )

        # Check 8: High path entropy (+15, raised threshold)
        path = parsed.path
        if path and len(path) > 10:
            counts = Counter(path)
            entropy = -sum(
                (c / len(path)) * math.log2(c / len(path)) for c in counts.values()
            )
            entropy_threshold = 5.5 if is_known_service else 5.0
            if entropy > entropy_threshold:
                score += 15
                res.heuristic_flags.append(
                    f"High-entropy path (entropy={entropy:.2f}) — possible obfuscation"
                )

        # Check 9: @ symbol in URL (+25)
        if "@" in parsed.netloc:
            score += 25
            res.heuristic_flags.append(
                "@ symbol in URL — credential obfuscation pattern"
            )

        # Check 10: Redirect encoded (+20)
        if original_url.lower().count("http") > 1:
            score += 20
            res.heuristic_flags.append("URL contains embedded redirect")

        res.heuristic_score = min(score, 100.0)
        return res

    # ── STAGE 3: VirusTotal Lookup ──────────────────────────────────────────────────—
    # Note: Redis caching removed for Semester 1. Direct VT HTTP calls each time.
    # Caching will be re-added in Semester 2 with Redis.

    def _check_virustotal(self, result: UrlAnalysisResult) -> bool:
        if self._vt_disabled_reason:
            result.vt_error = self._vt_disabled_reason
            return False

        if not self._vt_keys:
            result.vt_error = (
                "No VT API keys configured — set VIRUSTOTAL_API_KEYS in .env"
            )
            logger.warning("VT lookup skipped: no API keys configured")
            return False

        url_id = (
            base64.urlsafe_b64encode(result.normalized_url.encode())
            .decode()
            .rstrip("=")
        )

        api_key = self._vt_keys[self._vt_key_index]
        self._vt_key_index = (self._vt_key_index + 1) % len(self._vt_keys)

        headers = {"x-apikey": api_key}

        # Log that we are actually calling VT
        logger.info(f"VT lookup for URL: {result.normalized_url[:80]}")

        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers
                )

                if resp.status_code == 200:
                    data = resp.json()["data"]["attributes"]["last_analysis_stats"]
                    self._apply_vt_stats(result, data)
                    logger.info(
                        f"VT result: malicious={result.vt_malicious} "
                        f"suspicious={result.vt_suspicious} total={result.vt_total}"
                    )
                elif resp.status_code in (401, 403):
                    self._vt_disabled_reason = (
                        "VT authentication failed — check VIRUSTOTAL_API_KEYS"
                    )
                    result.vt_error = self._vt_disabled_reason
                    logger.error(self._vt_disabled_reason)

                elif resp.status_code == 404:
                    result.vt_error = "Submitted to VT — not yet analyzed"
                    # Submit for analysis
                    client.post(
                        "https://www.virustotal.com/api/v3/urls",
                        data={"url": result.normalized_url},
                        headers=headers,
                    )
                elif resp.status_code == 429:
                    result.vt_error = "VT rate limit — heuristic score only"
                    logger.warning(
                        f"VT rate limit hit for URL: {result.normalized_url[:60]}"
                    )
                else:
                    logger.warning(
                        f"VT Error {resp.status_code} for {result.normalized_url}"
                    )
                    result.vt_error = f"VT HTTP Error {resp.status_code}"

            return True

        except Exception as e:
            logger.warning(f"VT request failed: {e}")
            result.vt_error = "VT connection failed"
            return True

    def _apply_vt_stats(self, result: UrlAnalysisResult, stats: dict) -> None:
        result.vt_malicious = stats.get("malicious", 0)
        result.vt_suspicious = stats.get("suspicious", 0)
        result.vt_harmless = stats.get("harmless", 0)
        result.vt_total = sum(stats.values())

        if result.vt_total > 0:
            result.vt_score = min(
                100.0,
                (result.vt_malicious + result.vt_suspicious * 0.5)
                / result.vt_total
                * 100.0,
            )

        if result.vt_malicious > 0:
            result.heuristic_flags.insert(
                0, f"VT found {result.vt_malicious} malicious reports"
            )
