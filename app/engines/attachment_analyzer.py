"""
Attachment Analyzer Engine — Orchestrates per-file static analysis.

Scans email attachments using format-specific sub-analyzers:
  - PE/EXE   → pe_analyzer    (pefile)
  - PDF      → pdf_analyzer   (PyPDF2)
  - OLE Doc  → office_analyzer (olefile)
  - OOXML    → office_analyzer (zipfile)
  - Other    → generic_analyzer (stdlib only)

After format-specific analysis, EVERY file is also scanned by the YARA engine:
  - YARA rules live in app/engines/rules/*.yar
  - Add or edit .yar files to customize detection without touching Python code
  - YARA score is blended with the heuristic score (max wins)

Usage (mirrors text_analyzer.py pattern):
    from app.engines.attachment_analyzer import AttachmentAnalyzer

    analyzer = AttachmentAnalyzer()
    result = analyzer.analyze(email.attachments)
    print(result.attachment_score)
"""

import io
import logging
import os
import httpx
from dataclasses import dataclass, field
from typing import List, Optional, TYPE_CHECKING

from app.config import get_settings
from app.engines.analyzers.base import FileAnalysisResult
from app.engines.analyzers.pe_analyzer import analyze_pe
from app.engines.analyzers.pdf_analyzer import analyze_pdf
from app.engines.analyzers.office_analyzer import analyze_office
from app.engines.analyzers.generic_analyzer import analyze_generic, DOUBLE_EXT_PATTERN
from app.engines.analyzers.yara_scanner import YaraScanner

if TYPE_CHECKING:
    from app.models.email import Attachment

logger = logging.getLogger(__name__)

# ── MIME / extension routing maps ─────────────────────────────────────────────

# Real MIME types that indicate PE files
PE_MIMES = {
    "application/x-dosexec",
    "application/x-msdownload",
    "application/x-executable",
    "application/octet-stream",  # Common fallback for EXEs
}

PE_EXTS = {".exe", ".dll", ".com", ".sys", ".scr", ".drv", ".cpl"}

PDF_MIMES = {"application/pdf", "application/x-pdf"}
PDF_EXTS = {".pdf"}

# OLE (legacy) Office formats
OLE_OFFICE_EXTS = {".doc", ".xls", ".ppt", ".dot", ".xlt", ".pot"}

# OOXML (modern, ZIP-based) Office formats
OOXML_EXTS = {".docx", ".xlsx", ".pptx", ".dotx", ".xlsm", ".docm", ".pptm"}


@dataclass
class AttachmentAnalysisResult:
    """
    Aggregated result for all attachments in a single email scan.

    Attributes:
        attachment_score : 0–100 overall risk (worst-file dominates)
        total_files      : Number of attachments found
        analyzed_files   : Number successfully analyzed
        per_file_results : List of per-file finding dicts (for breakdown JSON)
        high_risk_files  : Filenames whose individual score >= 60
    """

    attachment_score: float = 0.0
    total_files: int = 0
    analyzed_files: int = 0
    per_file_results: List[dict] = field(default_factory=list)
    high_risk_files: List[str] = field(default_factory=list)


class AttachmentAnalyzer:
    """
    Orchestrates attachment scanning.

    Instantiate fresh per scan (no shared state between runs).
    """

    def __init__(self):
        self._settings = get_settings()
        self._max_bytes = self._settings.MAX_ATTACHMENT_BYTES
        self._yara = YaraScanner()  # Loads/caches compiled rules on first call

    # ── Public API ─────────────────────────────────────────────────────────────

    def analyze(self, attachments: List["Attachment"]) -> AttachmentAnalysisResult:
        """
        Analyze a list of Attachment ORM objects.

        Args:
            attachments: SQLAlchemy Attachment records (already persisted to DB).
                         Each must have .filename, .storage_path, .content_type, .sha256_hash.

        Returns:
            AttachmentAnalysisResult with aggregate score and per-file details.
        """
        result = AttachmentAnalysisResult(total_files=len(attachments))

        if not attachments:
            logger.debug("No attachments to analyze — returning zero score")
            return result

        per_file_scores: List[float] = []

        for att in attachments:
            file_result = self._analyze_single(att)
            if file_result is None:
                continue  # File skipped (path invalid / oversized / missing)

            result.analyzed_files += 1
            score = file_result.risk_score

            per_file_scores.append(score)

            if score >= 60.0:
                result.high_risk_files.append(att.filename)

            result.per_file_results.append({
                "filename": att.filename,
                "file_type": file_result.file_type,
                "risk_score": score,
                "mime_mismatch": file_result.mime_mismatch,
                "findings": file_result.findings,
                "indicators": file_result.indicators,
                "yara_matches": file_result.indicators.get("yara_matches", []),
                "sha256": att.sha256_hash,
                "vt_malicious": file_result.vt_malicious,
                "vt_suspicious": file_result.vt_suspicious,
                "vt_harmless": file_result.vt_harmless,
                "vt_total": file_result.vt_total,
                "vt_error": file_result.vt_error,
            })

        # ── Aggregate score: worst file dominates ──────────────────
        if per_file_scores:
            # Use max(individual scores) as the aggregate.
            # This ensures one highly suspicious attachment flags the entire email.
            result.attachment_score = round(max(per_file_scores), 1)

        logger.info(
            f"Attachment analysis complete — "
            f"{result.analyzed_files}/{result.total_files} files analyzed, "
            f"score={result.attachment_score}, high_risk={result.high_risk_files}"
        )
        return result

    # ── Private helpers ────────────────────────────────────────────────────────

    def _analyze_single(self, att: "Attachment") -> Optional[FileAnalysisResult]:
        """
        Load and analyze one attachment.

        Returns None if the file cannot be read or should be skipped.
        """
        filename = att.filename or "unknown"
        storage_path = att.storage_path

        # ── Safety: validate path ─────────────────────────────────
        if not storage_path or not os.path.isfile(storage_path):
            logger.warning(f"Attachment '{filename}' has no valid storage_path — skipping")
            return None

        # ── Safety: size check ────────────────────────────────────
        try:
            file_size = os.path.getsize(storage_path)
        except OSError as e:
            logger.error(f"Cannot stat '{filename}': {e}")
            return None

        if file_size > self._max_bytes:
            logger.warning(
                f"Attachment '{filename}' ({file_size:,} bytes) exceeds "
                f"MAX_ATTACHMENT_BYTES ({self._max_bytes:,}) — skipping"
            )
            # Return a minimal result with a note
            skipped = FileAnalysisResult(file_type="Skipped (too large)")
            skipped.findings = [
                f"File skipped: size {file_size:,} bytes exceeds limit {self._max_bytes:,} bytes"
            ]
            return skipped

        # ── Read file into memory ─────────────────────────────────
        try:
            with open(storage_path, "rb") as f:
                data = f.read()
        except Exception as e:
            logger.error(f"Failed to read attachment '{filename}': {e}")
            return None

        # ── MIME detection ────────────────────────────────────────
        detected_mime = self._detect_mime(data)
        declared_mime = (att.content_type or "").lower().split(";")[0].strip()
        mime_mismatch = bool(
            detected_mime
            and declared_mime
            and detected_mime != declared_mime
            and declared_mime not in ("application/octet-stream", "")
        )

        # ── Route to correct analyzer ─────────────────────────────
        file_result = self._route_analyzer(data, filename, detected_mime)
        file_result.mime_mismatch = mime_mismatch

        if mime_mismatch:
            file_result.findings.insert(
                0,
                f"MIME mismatch: declared '{declared_mime}' but file magic says '{detected_mime}'"
            )
            file_result.risk_score = min(100.0, file_result.risk_score + 20.0)

        # Filename masquerading (invoice.pdf.exe) must score no matter
        # which analyzer handled the content — a fake ".exe" carrying PDF
        # bytes routes to the PDF analyzer, which knows nothing about
        # double extensions. generic_analyzer sets the same indicator
        # when it is the one that ran; don't count the signal twice.
        if (
            not file_result.indicators.get("double_extension")
            and DOUBLE_EXT_PATTERN.search(filename)
        ):
            file_result.indicators["double_extension"] = True
            file_result.findings.append(
                f"Double extension detected: '{filename}' — classic trick to disguise executables"
            )
            file_result.risk_score = min(100.0, file_result.risk_score + 30.0)

        # ── YARA scan (runs on ALL files, regardless of type) ─────
        yara_result = self._yara.scan(data, filename)
        if yara_result.matched:
            # Prepend YARA findings so they appear first in the list
            for finding in reversed(yara_result.findings):
                file_result.findings.insert(0, finding)

            # Store structured YARA match data in the indicators dict
            file_result.indicators["yara_matches"] = [
                {
                    "rule": m.rule_name,
                    "severity": m.severity,
                    "tags": m.tags,
                    "description": m.description,
                    "matched_strings": m.matched_strings,
                }
                for m in yara_result.matches
            ]

            # Score blending: highest assessment wins
            # If YARA found something worse than the heuristic, YARA score takes over
            file_result.risk_score = min(
                100.0,
                max(file_result.risk_score, yara_result.yara_score)
            )

        elif yara_result.error:
            logger.debug(f"YARA note for '{filename}': {yara_result.error}")

        # ── VirusTotal hash lookup (if enabled) ───────────────────────
        sha256 = att.sha256_hash
        if self._settings.ENABLE_VT_HASH_LOOKUP:
            vt_result = self._vt_hash_lookup(sha256 or "")
        else:
            vt_result = {
                "malicious": 0, "suspicious": 0, "harmless": 0, "total": 0,
                "error": "VT hash lookup disabled (ENABLE_VT_HASH_LOOKUP=False)",
            }

        file_result.vt_malicious = vt_result["malicious"]
        file_result.vt_suspicious = vt_result["suspicious"]
        file_result.vt_harmless = vt_result["harmless"]
        file_result.vt_total = vt_result["total"]
        file_result.vt_error = vt_result["error"]

        # Boost risk score if VT flagged the file
        if vt_result["malicious"] > 0:
            weighted = vt_result["malicious"] + (vt_result["suspicious"] * 0.5)
            vt_score = min(100.0, (weighted / vt_result["total"]) * 100) if vt_result["total"] > 0 else 80.0
            file_result.risk_score = max(file_result.risk_score, vt_score)
            file_result.findings.insert(
                0, f"VirusTotal: {vt_result['malicious']} engines flagged as malicious"
            )

        return file_result

    def _vt_hash_lookup(self, sha256: str) -> dict:
        """
        Look up a file hash on VirusTotal.
        Uses GET /api/v3/files/{hash} endpoint.
        Returns dict with keys: malicious, suspicious, harmless, total, error
        """
        settings = get_settings()
        vt_keys = settings.vt_api_keys

        if not vt_keys:
            return {
                "malicious": 0, "suspicious": 0,
                "harmless": 0, "total": 0,
                "error": "No VT API keys configured",
            }

        if not sha256 or len(sha256) != 64:
            return {
                "malicious": 0, "suspicious": 0,
                "harmless": 0, "total": 0,
                "error": "Invalid SHA256 hash",
            }

        api_key = vt_keys[0]  # use first key (rotation can come later)

        try:
            with httpx.Client(timeout=10) as client:
                resp = client.get(
                    f"https://www.virustotal.com/api/v3/files/{sha256}",
                    headers={"x-apikey": api_key},
                )

            if resp.status_code == 200:
                data = resp.json()
                stats = (
                    data.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {})
                )
                malicious  = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                harmless   = int(stats.get("harmless", 0))
                undetected = int(stats.get("undetected", 0))
                total = malicious + suspicious + harmless + undetected
                logger.info(
                    f"VT file result for {sha256[:8]}…: "
                    f"malicious={malicious} suspicious={suspicious} total={total}"
                )
                return {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "total": total,
                    "error": None,
                }

            elif resp.status_code == 404:
                # File not in VT database — common for clean/unknown files
                return {
                    "malicious": 0, "suspicious": 0,
                    "harmless": 0, "total": 0,
                    "error": "File not in VT database (possibly clean or unknown)",
                }

            elif resp.status_code == 429:
                logger.warning("VT rate limit hit for file hash lookup")
                return {
                    "malicious": 0, "suspicious": 0,
                    "harmless": 0, "total": 0,
                    "error": "VT rate limit (429)",
                }

            else:
                return {
                    "malicious": 0, "suspicious": 0,
                    "harmless": 0, "total": 0,
                    "error": f"VT HTTP {resp.status_code}",
                }

        except Exception as e:
            logger.error(f"VT file hash lookup failed for {sha256[:8]}…: {e}")
            return {
                "malicious": 0, "suspicious": 0,
                "harmless": 0, "total": 0,
                "error": str(e)[:100],
            }


    def _detect_mime(self, data: bytes) -> Optional[str]:
        """Use python-magic to detect the actual MIME type from file bytes."""
        try:
            import magic  # Lazy import — requires libmagic system dep
            return magic.from_buffer(data, mime=True)
        except ImportError:
            logger.debug("python-magic not available — MIME detection disabled")
            return None
        except Exception as e:
            logger.debug(f"MIME detection failed: {e}")
            return None

    def _route_analyzer(
        self,
        data: bytes,
        filename: str,
        detected_mime: Optional[str],
    ) -> FileAnalysisResult:
        """
        Select the correct format-specific analyzer.

        Routing priority:
          1. Detected MIME (from magic bytes) — most reliable
          2. File extension — fallback when magic is unavailable
        """
        ext = os.path.splitext(filename.lower())[1]
        mime = (detected_mime or "").lower()

        # ── PE files ──────────────────────────────────────────────
        if mime in PE_MIMES or ext in PE_EXTS:
            # Require an actual MZ header before routing to the PE
            # analyzer. A ".pdf.exe" with no executable header is the
            # masquerading trick itself — routing it to the PE analyzer
            # just errors out with score 0; falling through to generic
            # lets the double-extension + entropy rules score it.
            if data[:2] == b"MZ":
                logger.debug(f"Routing '{filename}' → PE analyzer")
                return analyze_pe(data, filename)

        # ── PDF files ─────────────────────────────────────────────
        if mime in PDF_MIMES or ext in PDF_EXTS:
            if data[:4] == b"%PDF" or ext in PDF_EXTS:
                logger.debug(f"Routing '{filename}' → PDF analyzer")
                return analyze_pdf(data, filename)

        # ── OOXML Office (ZIP-based) ──────────────────────────────
        if ext in OOXML_EXTS or mime == "application/vnd.openxmlformats-officedocument":
            logger.debug(f"Routing '{filename}' → OOXML Office analyzer")
            return analyze_office(data, filename, is_ooxml=True)

        # ── OLE Office (legacy binary) ────────────────────────────
        if ext in OLE_OFFICE_EXTS or mime in (
            "application/msword",
            "application/vnd.ms-excel",
            "application/vnd.ms-powerpoint",
            "application/x-ole-storage",
        ):
            logger.debug(f"Routing '{filename}' → OLE Office analyzer")
            return analyze_office(data, filename, is_ooxml=False)

        # ── Fallback ──────────────────────────────────────────────
        logger.debug(f"Routing '{filename}' → Generic analyzer (ext={ext}, mime={mime})")
        return analyze_generic(data, filename)
