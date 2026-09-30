"""UrlResult ORM model — stores per-URL analysis results for each scan."""

from datetime import datetime
from typing import Optional, Any

from sqlalchemy import String, Integer, Float, Boolean, ForeignKey, DateTime, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models import Base


class UrlResult(Base):
    """
    Stores the result of analyzing a single URL found in an email.

    One Scan may have many UrlResult rows (one per unique normalized URL).
    The final_score column is indexed for fast risk-level filtering.

    Semester 2 placeholder columns (dynamic_score, redirect_chain, etc.) are
    added as nullable now so migration 0003+ can populate them without ALTER TABLE pain.
    """

    __tablename__ = "url_results"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scans.id"), index=True
    )

    # ── URL values ─────────────────────────────────────────────────────────────
    original_url: Mapped[str] = mapped_column(String(2048))
    normalized_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    is_shortener: Mapped[bool] = mapped_column(Boolean, default=False)

    # ── Scores ─────────────────────────────────────────────────────────────────
    heuristic_score: Mapped[float] = mapped_column(Float, default=0.0)
    vt_score: Mapped[float] = mapped_column(Float, default=0.0)
    final_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)

    # ── VirusTotal counters ────────────────────────────────────────────────────
    vt_malicious: Mapped[int] = mapped_column(Integer, default=0)
    vt_suspicious: Mapped[int] = mapped_column(Integer, default=0)
    vt_harmless: Mapped[int] = mapped_column(Integer, default=0)
    vt_total: Mapped[int] = mapped_column(Integer, default=0)
    vt_error: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    # ── Heuristic detail ───────────────────────────────────────────────────────
    heuristic_flags: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)

    # ── Timestamps ─────────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # ── Semester 2 placeholder columns (nullable — populated by future migration) ──
    dynamic_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    redirect_chain: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    dom_has_login_form: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    ssl_valid: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    playwright_screenshot_path: Mapped[Optional[str]] = mapped_column(
        String(1024), nullable=True
    )

    # ── Dynamic analysis detail (migration 0003) ─────────────────────────────────
    dynamic_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    dynamic_flags: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    dynamic_error: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    final_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    external_form_action: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    download_attempted: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    popup_attempted: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    dynamic_elapsed_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # ── Relationships ──────────────────────────────────────────────────────────
    scan: Mapped["Scan"] = relationship(back_populates="url_results")  # type: ignore[name-defined]
