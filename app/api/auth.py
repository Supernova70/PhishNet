"""Authentication routes — Google combined consent + own session cookies.

Public: /auth/config, /auth/google, /auth/callback, /auth/credential,
        /auth/logout.  /auth/me requires a session cookie.

Flow (one combined consent):
    GET  /auth/google      → 302 to Google (state in short-lived cookie)
    GET  /auth/callback    → code exchange, verify id_token, upsert user,
                             encrypt refresh token, set session cookie, "/"
    POST /auth/credential  → One Tap (returning users): verify ID token,
                             re-issue session (no new consent needed)
"""

import logging
import secrets
from datetime import datetime
from typing import Optional
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth import google_oauth
from app.auth.crypto import encrypt_secret
from app.auth.session import (
    COOKIE_NAME,
    SessionError,
    clear_session_cookie,
    create_session_token,
    decode_session_token,
    set_session_cookie,
)
from app.config import get_settings
from app.dependencies import get_current_user, get_db
from app.models.audit_log import AuditLog
from app.models.user import User
from app.permissions import effective_permissions

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

STATE_COOKIE = "phishnet_oauth_state"
GIS_CSRF_COOKIE = "g_csrf_token"


# ── helpers ────────────────────────────────────────────────────────────

def _login_error(message: str) -> RedirectResponse:
    return RedirectResponse(f"/login?error={quote(message)}", status_code=302)


def _audit(db: Session, user: User, action: str, detail: Optional[dict] = None) -> None:
    # user_id tags the row for per-account /audit listings (tenancy).
    db.add(AuditLog(user_id=user.id, actor=str(user.id), action=action,
                    entity_type="user", entity_id=user.id, detail_json=detail))


def _upsert_user(db: Session, payload: dict) -> User:
    """Create or refresh the local user from a verified Google ID token."""
    settings = get_settings()
    sub = payload["sub"]
    user = db.query(User).filter(User.google_sub == sub).first()
    email = (payload.get("email") or "").lower()
    if user is None:
        user = User(
            google_sub=sub,
            email=email,
            name=payload.get("name"),
            picture=payload.get("picture"),
        )
        db.add(user)
    else:
        user.email = email or user.email
        user.name = payload.get("name") or user.name
        user.picture = payload.get("picture") or user.picture
    if email and email in settings.admin_emails:
        user.role = "admin"
    user.last_login_at = datetime.utcnow()
    db.flush()
    return user


def _issue_session(response, user: User) -> None:
    set_session_cookie(response, create_session_token(user))


# ── schemas ────────────────────────────────────────────────────────────

class CredentialBody(BaseModel):
    credential: str
    g_csrf_token: Optional[str] = None


# ── routes ─────────────────────────────────────────────────────────────

@router.get("/config")
def auth_config() -> dict:
    """What the frontend needs to render sign-in (client id is public)."""
    settings = get_settings()
    return {
        "google_client_id": settings.GOOGLE_CLIENT_ID,
        "configured": bool(settings.GOOGLE_CLIENT_ID),
        "one_tap": bool(settings.GOOGLE_CLIENT_ID),
    }


@router.get("/google")
def google_sign_in() -> RedirectResponse:
    """Start the combined-consent authorization-code flow."""
    settings = get_settings()
    if not settings.GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=503, detail="Google sign-in not configured")
    state = secrets.token_urlsafe(32)
    response = RedirectResponse(
        google_oauth.build_authorization_url(state), status_code=302
    )
    response.set_cookie(
        STATE_COOKIE, state, max_age=600, httponly=True,
        samesite="lax", secure=settings.SESSION_COOKIE_SECURE, path="/",
    )
    return response


@router.get("/callback")
def google_callback(
    request: Request,
    db: Session = Depends(get_db),
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
):
    """Google redirect target — exchange code, verify identity, session in."""
    settings = get_settings()
    if error:
        logger.warning("google callback error: %s", error)
        return _login_error(f"google:{error}")
    cookie_state = request.cookies.get(STATE_COOKIE)
    if not code or not state or not cookie_state or not secrets.compare_digest(
        state, cookie_state
    ):
        return _login_error("invalid_state")

    try:
        token = google_oauth.fetch_token(code)
    except Exception as exc:  # httpx errors, non-2xx, malformed JSON
        logger.warning("token exchange failed: %s", exc)
        return _login_error("token_exchange_failed")

    id_token = token.get("id_token")
    if not id_token:
        return _login_error("missing_id_token")
    try:
        payload = google_oauth.verify_google_id_token(id_token)
    except Exception as exc:
        logger.warning("id_token verification failed: %s", exc)
        return _login_error("invalid_id_token")

    user = _upsert_user(db, payload)
    # Store the combined-consent refresh token (P3 Gmail sync consumes it).
    refresh_token = token.get("refresh_token")
    if refresh_token:
        user.gmail_refresh_token_enc = encrypt_secret(refresh_token)
        user.gmail_connected = True
        user.token_revoked_at = None
    _audit(db, user, "login", {"via": "google_code_flow"})
    db.commit()

    response = RedirectResponse("/", status_code=302)
    _issue_session(response, user)
    response.delete_cookie(STATE_COOKIE, path="/")
    return response


@router.post("/credential")
def google_credential(
    body: CredentialBody, request: Request, db: Session = Depends(get_db)
):
    """One Tap / Sign in with Google button credential (returning users)."""
    # Double-submit CSRF (Google's g_csrf_token cookie must match the body).
    csrf_cookie = request.cookies.get(GIS_CSRF_COOKIE)
    if not csrf_cookie or not body.g_csrf_token or not secrets.compare_digest(
        body.g_csrf_token, csrf_cookie
    ):
        raise HTTPException(status_code=403, detail="CSRF check failed")
    try:
        payload = google_oauth.verify_google_id_token(body.credential)
    except Exception as exc:
        logger.warning("credential verification failed: %s", exc)
        raise HTTPException(status_code=401, detail="Invalid Google credential")

    user = db.query(User).filter(User.google_sub == payload["sub"]).first()
    if user is None:
        # Accounts are created by the combined-consent flow only (it also
        # links Gmail); One Tap alone cannot grant mailbox access.
        raise HTTPException(
            status_code=401,
            detail="Account not found — use Sign in with Google",
        )
    user.last_login_at = datetime.utcnow()
    _audit(db, user, "login", {"via": "one_tap"})
    db.commit()

    response = JSONResponse(
        {
            "email": user.email,
            "role": user.role,
            "gmail_connected": bool(user.gmail_connected),
            "needs_gmail": not user.gmail_connected,
        }
    )
    _issue_session(response, user)
    return response


@router.get("/me")
def auth_me(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    data = user.to_dict()
    data["needs_gmail"] = not user.gmail_connected
    # Effective RBAC capabilities — resolved live (never from the JWT) so a
    # grant/revoke takes effect on the next poll without re-login.
    data["permissions"] = sorted(effective_permissions(db, user))
    return data


@router.post("/logout")
def logout(response: Response) -> dict:
    """Clear the session cookie (FastAPI merges injected-Response headers)."""
    clear_session_cookie(response)
    return {"ok": True}


# Re-export for tests that patch the callback flow pieces.
__all__ = ["router", "SessionError", "COOKIE_NAME", "decode_session_token"]
