"""RBAC permission registry and dependencies (R1).

Effective permissions for a user = ``ROLE_DEFAULTS[role] ∪ grants``.
``role=admin`` implicitly holds every registered permission; ``role=user``
starts empty and receives capabilities only via admin grants in the
``user_permissions`` table.

Grants are resolved from the DB on every check (one indexed query) — never
stored in the session JWT — so revoke → effective on the next request.
"""

from typing import Callable, Set

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.session import COOKIE_NAME, SessionError, decode_session_token
from app.dependencies import get_current_user, get_db
from app.models.user import User
from app.models.user_permission import UserPermission

# Capability registry — keep labels in sync with docs/RBAC_PLAN.md.
PERMISSIONS: dict[str, str] = {
    "system.settings": "View and edit Settings (thresholds, API keys)",
    "system.health": "View API Health dashboard + component detail",
    "users.manage": "Manage user accounts and grant permissions",
}

ROLE_DEFAULTS: dict[str, set[str]] = {
    "admin": set(PERMISSIONS),
    "user": set(),
}


def effective_permissions(db: Session, user: User) -> Set[str]:
    """Role defaults ∪ explicit grants (grants read live from DB)."""
    if user.role == "admin":
        return set(PERMISSIONS)
    perms = set(ROLE_DEFAULTS.get(user.role, set()))
    rows = (
        db.query(UserPermission.permission)
        .filter(UserPermission.user_id == user.id)
        .all()
    )
    perms.update(perm for (perm,) in rows)
    return perms


def user_can(db: Session, user: User, permission: str) -> bool:
    return permission in effective_permissions(db, user)


def require_permission(permission: str) -> Callable:
    """Dependency factory: 401 without a session, 403 without the grant.

    Endpoint existence is not a secret (unlike row tenancy, which 404s),
    so 403 with the missing capability name is safe and debuggable.
    """
    if permission not in PERMISSIONS:
        raise ValueError(f"Unknown permission: {permission}")

    def dependency(
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        if not user_can(db, user, permission):
            raise HTTPException(status_code=403, detail=f"Missing permission: {permission}")
        return user

    return dependency


def optional_permissions(request: Request, db: Session) -> Set[str]:
    """Permissions from the session cookie, or set() when anonymous/invalid.

    Used by /health: the probe contract (always 200) must hold for
    anonymous LB checks, while the detailed component block is revealed
    only to holders of ``system.health``.
    """
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return set()
    try:
        payload = decode_session_token(token)
    except SessionError:
        return set()
    user = db.get(User, payload.get("uid"))
    if user is None:
        return set()
    return effective_permissions(db, user)


__all__ = [
    "PERMISSIONS",
    "ROLE_DEFAULTS",
    "effective_permissions",
    "user_can",
    "require_permission",
    "optional_permissions",
]
