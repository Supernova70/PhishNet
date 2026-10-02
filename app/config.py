"""
AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
— Centralized Configuration (SIH 26106)

All settings are loaded from environment variables (via .env file).
Uses Pydantic Settings for validation and type safety.
"""

import os
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ── App ──────────────────────────────────────────────
    APP_NAME: str = "AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform"
    APP_SHORT_NAME: str = "Phishing Guard 2.0"
    APP_VERSION: str = "3.0.0"
    DEBUG: bool = False

    # ── Database ─────────────────────────────────────────
    DATABASE_URL: str = "postgresql://phishing_user:phishing_pass@postgres:5432/phishing_guard"

    # ── VirusTotal ───────────────────────────────────────
    VIRUSTOTAL_API_KEYS: str = ""  # Comma-separated keys

    @property
    def vt_api_keys(self) -> List[str]:
        """Parse comma-separated VT keys into a list."""
        return [k.strip() for k in self.VIRUSTOTAL_API_KEYS.split(",") if k.strip()]

    # ── Security ─────────────────────────────────────────
    API_KEYS: str = ""   # comma-separated list of valid keys

    # ── Google sign-in (Sign in with Google + Gmail consent) ──
    # Created once in Google Cloud Console (see docs/MULTI_TENANT_PLAN.md P0).
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    # Must exactly match an Authorized redirect URI in the OAuth client.
    GOOGLE_REDIRECT_URI: str = "http://localhost:5173/api/auth/callback"
    GOOGLE_SCOPES: str = (
        "openid email profile https://www.googleapis.com/auth/gmail.readonly"
    )
    # Our own session cookie (HS256). Override with a long random value in prod.
    SESSION_SECRET: str = "phishing-guard-dev-session-secret-change-me"
    SESSION_TTL_HOURS: int = 168  # 7 days
    SESSION_COOKIE_SECURE: bool = False  # True behind HTTPS in production
    # Fernet key for stored OAuth refresh tokens / email bodies at rest:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # Empty → ephemeral per-process key (stored secrets unreadable after restart).
    TOKEN_ENCRYPTION_KEY: str = ""
    # Comma-separated Google emails granted role=admin (platform operator).
    ADMIN_EMAILS: str = ""

    @property
    def admin_emails(self) -> List[str]:
        """Lower-cased admin email list."""
        return [e.strip().lower() for e in self.ADMIN_EMAILS.split(",") if e.strip()]

    # ── Email (IMAP) ─────────────────────────────────────
    EMAIL_HOST: str = "imap.gmail.com"
    EMAIL_PORT: int = 993
    EMAIL_ADDRESS: str = ""
    EMAIL_PASSWORD: str = ""

    # ── Paths ────────────────────────────────────────────
    ATTACHMENT_DIR: str = "/app/uploads"
    MODEL_PATH: str = "/app/data/phishing_model.joblib"

    # ── Dynamic URL analysis ─────────────────────────────
    # Disabled by default: browser navigation must be an explicit deployment choice.
    DYNAMIC_URL_ENABLED: bool = False
    DYNAMIC_URL_NAVIGATION_TIMEOUT_SECONDS: int = 12
    DYNAMIC_URL_TOTAL_TIMEOUT_SECONDS: int = 20
    DYNAMIC_URL_SCAN_BUDGET_SECONDS: int = 45
    DYNAMIC_URL_MAX_PER_SCAN: int = 3
    DYNAMIC_URL_MAX_REDIRECTS: int = 8
    DYNAMIC_URL_RENDER_DELAY_MS: int = 1500
    DYNAMIC_URL_ALLOWED_PORTS: str = "80,443"
    DYNAMIC_URL_SCREENSHOT_DIR: str = "/app/uploads/url_screenshots"
    DYNAMIC_URL_SCREENSHOT_RETENTION_DAYS: int = 14
    DYNAMIC_URL_USER_AGENT: str = (
        "PhishingGuardDynamicAnalyzer/2.0 "
        "(defensive-security research; no interaction)"
    )

    @property
    def dynamic_url_allowed_ports(self) -> tuple[int, ...]:
        """Parse and validate the configured browser destination ports."""
        ports: list[int] = []
        for value in self.DYNAMIC_URL_ALLOWED_PORTS.split(","):
            value = value.strip()
            if not value:
                continue
            port = int(value)
            if not 1 <= port <= 65535:
                raise ValueError(f"Invalid dynamic URL port: {port}")
            ports.append(port)
        return tuple(ports or (80, 443))

    # ── Attachment Engine ────────────────────────────────
    # Maximum file size (bytes) the attachment engine will read into memory.
    # Files exceeding this are skipped and flagged in the breakdown.
    MAX_ATTACHMENT_BYTES: int = 52_428_800  # 50 MB

    # Set to True once app/integrations/virustotal.py is wired up.
    # When False, attachment analysis runs static-only (no VT hash lookups).
    ENABLE_VT_HASH_LOOKUP: bool = False

    # ── Header Forensics ─────────────────────────────────
    # Preserve raw RFC822 bytes (gzip) + full header block for evidence.
    PRESERVE_RAW_EMAIL: bool = True
    # Active DNS validation of SPF/DMARC/DKIM records (network lookups).
    # Disabled by default: tests and offline demos must not require DNS.
    HEADER_DNS_CHECKS_ENABLED: bool = False

    # ── Origin / IP intelligence (Week 2) ────────────────
    # ipwho.is free GeoIP API (no key). Cached in DB.
    GEOIP_PROVIDER: str = "ipwhois"        # ipwhois | maxmind | none
    MAXMIND_DB_PATH: str = ""
    IP_INTEL_CACHE_DAYS: int = 30
    # Auto-fill missing trace IPs in the background on first view.
    IP_INTEL_AUTO_ENRICH: bool = True

    # DNS blocklist reputation (off by default — DNS must be explicit).
    DNSBL_ENABLED: bool = False
    DNSBL_ZONES: str = "bl.spamcop.net"    # comma-separated

    # ── Domain intelligence (GET /domains/{domain}/intel + attribution) ──
    # Live DNS posture (MX/NS/SPF/DMARC) and RDAP registration lookups.
    # Offline by default: tests and demos must not require the network.
    DOMAIN_INTEL_DNS_ENABLED: bool = False
    DOMAIN_INTEL_RDAP_ENABLED: bool = False

    # ── Privacy / compliance ─────────────────────────────
    MASK_PII: bool = False
    RETENTION_DAYS: int = 90

    @property
    def raw_email_dir(self) -> str:
        """Directory for gzipped raw RFC822 evidence files."""
        if self.RAW_EMAIL_DIR:
            return self.RAW_EMAIL_DIR
        return os.path.join(self.ATTACHMENT_DIR, "raw_emails")

    RAW_EMAIL_DIR: str = ""

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton — call this everywhere."""
    return Settings()


# ── Future: durable worker queue ─────────────────────────────────────
# Redis will be added in Semester 2 for:
#   - VirusTotal result caching (reduce API quota usage)
#   - Celery task queue for async scan execution
#   - durable Playwright headless browser job queuing
# When ready, add: REDIS_URL: str = "redis://redis:6379/0"
# and add redis service back to docker-compose.yml
