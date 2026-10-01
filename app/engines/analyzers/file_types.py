"""
File-type bucket classification for rule applicability gating.

YARA rules declare an optional ``applies_to`` meta listing the buckets the
rule makes sense for (e.g. PowerShell rules apply to scripts, not to PNGs).
Bucketing prefers magic/MIME (so a PE renamed to ``photo.png`` still counts
as ``executable``) and falls back to extension when magic is unavailable.

Buckets:
    executable, image, audio, video, pdf, office, script, html, text,
    archive, other
"""

import os
from typing import Optional, Set

PE_MIMES = {
    "application/x-dosexec",
    "application/x-msdownload",
    "application/x-executable",
}

PE_EXTS = {".exe", ".dll", ".com", ".sys", ".scr", ".drv", ".cpl"}

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".ico", ".svg", ".heic"}
AUDIO_EXTS = {".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".wma"}
VIDEO_EXTS = {".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm", ".m4v"}

OOXML_EXTS = {".docx", ".xlsx", ".pptx", ".dotx", ".xlsm", ".docm", ".pptm"}
OLE_EXTS = {".doc", ".xls", ".ppt", ".dot", ".xlt", ".pot"}
OFFICE_EXTS = OOXML_EXTS | OLE_EXTS

SCRIPT_EXTS = {
    ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".sh", ".bash", ".zsh", ".py", ".rb", ".pl",
    ".php", ".lua", ".jar",
}
HTML_EXTS = {".html", ".htm", ".mhtml", ".mht", ".xhtml"}
TEXT_EXTS = {".txt", ".csv", ".log", ".md", ".rtf", ".xml", ".json", ".yaml", ".yml", ".ini", ".cfg"}
ARCHIVE_EXTS = {".zip", ".7z", ".rar", ".gz", ".tar", ".bz2", ".xz", ".iso"}
PDF_EXTS = {".pdf"}


def classify_bucket(
    data: bytes,
    filename: str,
    mime: Optional[str] = None,
) -> str:
    """
    Classify a file into a rule-applicability bucket.

    Args:
        data    : file bytes (magic checks)
        filename: original name (extension fallback)
        mime    : detected MIME type from python-magic (preferred over ext)

    Returns one of the bucket names listed in the module docstring.
    """
    mime = (mime or "").lower().split(";")[0].strip()
    ext = os.path.splitext((filename or "").lower())[1]

    # ── 1. Magic/MIME first — a renamed file keeps its true content type ──
    if data[:2] == b"MZ" or mime in PE_MIMES:
        return "executable"
    if mime.startswith("image/"):
        return "image"
    if mime.startswith("audio/"):
        return "audio"
    if mime.startswith("video/"):
        return "video"
    if mime == "application/pdf":
        return "pdf"
    if "officedocument" in mime or mime in (
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/x-ole-storage",
    ):
        return "office"
    if mime in ("text/html", "application/xhtml+xml"):
        return "html"
    if mime in ("application/zip", "application/gzip", "application/x-7z-compressed", "application/x-rar-compressed"):
        # OOXML is a zip — extension check below keeps docx/xlsx as "office".
        if ext in OFFICE_EXTS:
            return "office"
        return "archive"

    # ── 2. Extension fallback (magic unavailable or generic MIME) ─────────────
    if ext in PE_EXTS:
        return "executable"
    if ext in IMAGE_EXTS:
        return "image"
    if ext in AUDIO_EXTS:
        return "audio"
    if ext in VIDEO_EXTS:
        return "video"
    if ext in PDF_EXTS:
        return "pdf"
    if ext in OFFICE_EXTS:
        return "office"
    if ext in SCRIPT_EXTS:
        return "script"
    if ext in HTML_EXTS:
        return "html"
    if ext in ARCHIVE_EXTS:
        return "archive"
    if ext in TEXT_EXTS:
        return "text"

    # ── 3. Generic text MIME ──────────────────────────────────────────────────
    if mime.startswith("text/"):
        return "text"

    return "other"


def parse_applies_to(value: str) -> Set[str]:
    """Parse an ``applies_to`` meta string into a bucket set."""
    return {part.strip() for part in value.split(",") if part.strip()}
