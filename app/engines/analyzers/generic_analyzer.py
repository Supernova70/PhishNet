"""
Generic Analyzer — Fallback static analysis for unknown or unsupported file types.

Applied when no specialized analyzer can handle the file.

Checks:
  1. Shannon entropy (high entropy → possible packing/encryption)
  2. Embedded PE magic bytes (MZ header in non-PE files → dropper risk)
  3. Double extension detection (e.g., invoice.pdf.exe)
  4. Script shebang detection (#! at start → possibly executable script)
  5. URLs and IPs embedded in the raw bytes
"""

import logging
import math
import re
from typing import List

from app.engines.analyzers.base import FileAnalysisResult

logger = logging.getLogger(__name__)

ENTROPY_HIGH = 7.5     # Almost certainly packed/encrypted
ENTROPY_WARN = 6.5     # Elevated entropy — worth flagging

# Regex patterns for embedded IOCs
_URL_RE = re.compile(
    rb"https?://[^\s\"'<>\x00-\x1f]{6,200}",
    re.IGNORECASE,
)
_IP_RE = re.compile(
    rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

# Double-extension patterns — legitimate files very rarely use these
DOUBLE_EXT_PATTERN = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|zip)\.(exe|bat|cmd|vbs|js|ps1|sh)$",
    re.IGNORECASE,
)

# Known-safe file magic signatures — these are expected to have high entropy
# and may contain MZ-like byte sequences in compressed data
SAFE_MAGIC_SIGNATURES = {
    b"\x89PNG": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"GIF8": "GIF",
    b"PK\x03\x04": "ZIP",
    b"\x1f\x8b": "GZIP",
    b"%PDF": "PDF",
    b"RIFF": "RIFF (AVI/WAV)",
    b"\x1a\x45\xdf\xa3": "MKV/WebM",
}


def _detect_file_type(data: bytes) -> str | None:
    """Detect file type from magic bytes. Returns type name or None."""
    for magic, name in SAFE_MAGIC_SIGNATURES.items():
        if data[:len(magic)] == magic:
            return name
    # MP4/MOV: "ftyp" at offset 4
    if len(data) > 8 and data[4:8] == b"ftyp":
        return "MP4/MOV"
    return None


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence. Returns value 0.0–8.0."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    length = len(data)
    return round(
        -sum((c / length) * math.log2(c / length) for c in freq.values() if c > 0),
        4,
    )


def analyze_generic(data: bytes, filename: str) -> FileAnalysisResult:
    """
    Generic fallback analysis applicable to any file type.

    Args:
        data    : Raw file bytes
        filename: Original filename

    Returns:
        FileAnalysisResult with risk_score 0–100
    """
    result = FileAnalysisResult(file_type="Generic")
    risk_score = 0.0
    findings: List[str] = []
    indicators: dict = {
        "entropy": 0.0,
        "has_embedded_pe": False,
        "double_extension": False,
        "embedded_urls": [],
        "embedded_ips": [],
        "is_script": False,
    }

    # Detect known-safe file types — reduce false positives for these
    detected_type = _detect_file_type(data)
    is_safe_binary = detected_type is not None

    try:
        # ── 1. Entropy analysis ───────────────────────────────────
        entropy = _shannon_entropy(data)
        indicators["entropy"] = entropy

        if is_safe_binary:
            # Known-safe binary formats (PNG, JPEG, ZIP, etc.) naturally have
            # high entropy from compression — only flag extreme values
            if entropy >= 7.8:
                findings.append(
                    f"Very high entropy for {detected_type} file ({entropy:.2f}/8.0) — unusual"
                )
                risk_score += 10.0
            # Don't flag normal elevated entropy for safe formats
        else:
            if entropy >= ENTROPY_HIGH:
                findings.append(
                    f"Very high file entropy ({entropy:.2f}/8.0) — file appears packed or encrypted"
                )
                risk_score += 35.0
            elif entropy >= ENTROPY_WARN:
                findings.append(f"Elevated file entropy ({entropy:.2f}/8.0) — possible obfuscation")
                risk_score += 15.0

        # ── 2. Embedded PE header ─────────────────────────────────
        # MZ header (PE magic) embedded inside a non-PE file is a classic dropper trick
        # BUT: binary formats like PNG/JPEG/ZIP can contain 'MZ' bytes in compressed data
        mz_count = data.count(b"MZ")
        if mz_count > 0:
            if is_safe_binary:
                # For known-safe formats, MZ in compressed data is normal — skip
                pass
            else:
                indicators["has_embedded_pe"] = True
                findings.append(
                    f"Embedded PE magic bytes (MZ) found {mz_count}× inside file — possible dropper"
                )
                risk_score += 40.0

        # ── 3. Double extension ───────────────────────────────────
        if DOUBLE_EXT_PATTERN.search(filename):
            indicators["double_extension"] = True
            findings.append(
                f"Double extension detected: '{filename}' — classic trick to disguise executables"
            )
            risk_score += 30.0

        # ── 4. Script shebang ─────────────────────────────────────
        if data[:3] in (b"#!/", b"#! "):
            indicators["is_script"] = True
            findings.append("Script shebang (#!) detected — file may be an executable script")
            risk_score += 20.0

        # ── 5. Embedded URLs ──────────────────────────────────────
        urls = [u.decode("utf-8", errors="replace") for u in _URL_RE.findall(data)]
        if urls:
            indicators["embedded_urls"] = urls[:10]  # Cap to 10 for display
            findings.append(
                f"{len(urls)} URL(s) embedded in file content"
                + (f" (showing first 10)" if len(urls) > 10 else "")
            )
            # Suspicious: many embedded URLs in a non-HTML file
            if len(urls) > 5:
                risk_score += 10.0

        # ── 6. Embedded IPs ───────────────────────────────────────
        ips = list({ip.decode("utf-8", errors="replace") for ip in _IP_RE.findall(data)})
        if ips:
            indicators["embedded_ips"] = ips[:10]
            findings.append(f"{len(ips)} IP address(es) embedded in file")

    except Exception as e:
        logger.error(f"Generic analysis error on {filename}: {e}")
        findings.append(f"Generic analysis error: {type(e).__name__}")

    result.risk_score = min(100.0, round(risk_score, 1))
    result.findings = findings
    result.indicators = indicators
    return result
