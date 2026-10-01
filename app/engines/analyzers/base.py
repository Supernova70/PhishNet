"""
Base dataclass shared across all file-type analyzers.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class FileAnalysisResult:
    """
    Standardized result returned by every format-specific analyzer.

    Attributes:
        file_type      : Detected file type label (e.g. "PE32", "PDF", "OLE-Office")
        risk_score     : Aggregated risk for this file, 0–100
        findings       : Human-readable descriptions of each detected indicator
        indicators     : Machine-readable key-value map of raw findings
        mime_mismatch  : True when the actual MIME differs from the declared content_type
        score_breakdown: Explainable score contributions
                         [{"signal": str, "points": float, "detail": str}]
        vt_malicious   : VirusTotal malicious engine count (0 if not checked)
        vt_suspicious  : VirusTotal suspicious engine count
        vt_harmless    : VirusTotal harmless engine count
        vt_total       : Total VT engine count (0 means not checked)
        vt_error       : Error message if VT lookup failed or was skipped
    """

    file_type: str = "Unknown"
    risk_score: float = 0.0
    findings: List[str] = field(default_factory=list)
    indicators: Dict[str, Any] = field(default_factory=dict)
    mime_mismatch: bool = False
    score_breakdown: List[Dict[str, Any]] = field(default_factory=list)
    # VirusTotal hash lookup results (populated by AttachmentAnalyzer)
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_harmless: int = 0
    vt_total: int = 0
    vt_error: Optional[str] = None
