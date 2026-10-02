"""User management API — RBAC capability grants (R1).

Metadata only: accounts, roles, and permission grants. The tenancy rule
holds — no endpoint here ever returns another user's mail content, scans,
or any tenant row.

Guards:
  * Every grant must be a permission the actor themselves holds
    (escalation ceiling — a non-admin manager cannot mint capabilities they
    do not have).
  * Only ``role=admin`` may change roles (``PATCH /users/{id}/role``).
  * No self-demotion; no demoting an account listed in ADMIN_EMAILS
    (it is re-promoted on its next login); never demote the last admin.
  * Stripping your own ``users.manage`` grant is rejected (self-lockout).
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dependencies import get_db, require_admin
from app.models.audit_log import AuditLog
from app.models.user import User
from app.models.user_permission import UserPermission
from app.permissions import PERMISSIONS, effective_permissions, require_permission

router = APIRouter(prefix="/users", tags=["Users"])


# ── helpers ────────────────────────────────────────────────────────────

def _member(db: Session, user: User) -> dict:
    grants = [
        row[0]
        for row in db.query(UserPermission.permission)
        .filter(UserPermission.user_id == user.id)
        .all()
    ]
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "picture": user.picture,
        "role": user.role,
        "permissions": sorted(effective_permissions(db, user)),
        "grants": sorted(grants),
        "gmail_connected": bool(user.gmail_connected),
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }


def _target_or_404(db: Session, user_id: int) -> User:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    return target


def _audit(db: Session, actor: User, target: User, action: str,
           detail: Optional[dict] = None) -> None:
    # user_id tags the row to the acting admin's own /audit listing.
    db.add(AuditLog(
        user_id=actor.id, actor=str(actor.id), action=action,
        entity_type="user", entity_id=target.id, detail_json=detail,
    ))


# ── schemas ────────────────────────────────────────────────────────────

class PermissionSet(BaseModel):
    permissions: List[str] = Field(default_factory=list)


class RoleUpdate(BaseModel):
    role: str


# ── routes ─────────────────────────────────────────────────────────────

@router.get("")
def list_users(
    actor: User = Depends(require_permission("users.manage")),
    db: Session = Depends(get_db),
) -> dict:
    """List all accounts (metadata only) with effective permissions + grants."""
    rows = db.query(User).order_by(User.id).all()
    return {
        "count": len(rows),
        "users": [_member(db, u) for u in rows],
        "permission_catalog": PERMISSIONS,
    }


@router.put("/{user_id}/permissions")
def replace_permissions(
    user_id: int,
    body: PermissionSet,
    actor: User = Depends(require_permission("users.manage")),
    db: Session = Depends(get_db),
) -> dict:
    """Replace a user's explicit grants with ``body.permissions``."""
    target = _target_or_404(db, user_id)

    unknown = [p for p in body.permissions if p not in PERMISSIONS]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown permission(s): {', '.join(unknown)}")

    actor_holds = effective_permissions(db, actor)
    forbidden = [p for p in body.permissions if p not in actor_holds]
    if forbidden:
        raise HTTPException(
            status_code=403,
            detail=f"You cannot grant permission(s) you do not hold: {', '.join(forbidden)}",
        )

    current = {
        p for (p,) in db.query(UserPermission.permission)
        .filter(UserPermission.user_id == target.id).all()
    }
    requested = set(body.permissions)

    # Self-lockout guard: never let a manager strip their own user-management
    # capability (admins are unaffected — their role holds it implicitly).
    if target.id == actor.id and "users.manage" in current - requested \
            and actor.role != "admin":
        raise HTTPException(
            status_code=400,
            detail="Cannot remove your own users.manage permission (self-lockout)",
        )

    for perm in sorted(requested - current):
        db.add(UserPermission(user_id=target.id, permission=perm, granted_by=actor.id))
        _audit(db, actor, target, "permission_grant", {"permission": perm})

    for perm in sorted(current - requested):
        db.query(UserPermission).filter(
            UserPermission.user_id == target.id,
            UserPermission.permission == perm,
        ).delete(synchronize_session=False)
        _audit(db, actor, target, "permission_revoke", {"permission": perm})

    db.commit()
    db.refresh(target)
    return _member(db, target)


@router.patch("/{user_id}/role")
def change_role(
    user_id: int,
    body: RoleUpdate,
    actor: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """Change a user's role (admin only, with self/last-admin guards)."""
    if body.role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="role must be 'admin' or 'user'")

    target = _target_or_404(db, user_id)
    if target.role == body.role:
        return _member(db, target)

    if target.id == actor.id:
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    if body.role == "user":
        # ADMIN_EMAILS accounts are re-promoted on every login — demotion
        # would be silently reverted, so reject it up front.
        admin_emails = {e.lower() for e in get_settings().admin_emails}
        if target.email.lower() in admin_emails:
            raise HTTPException(
                status_code=400,
                detail="Target is in ADMIN_EMAILS — remove it there first",
            )
        other_admins = (
            db.query(User).filter(User.role == "admin", User.id != target.id).count()
        )
        if other_admins == 0:
            raise HTTPException(status_code=400, detail="Cannot demote the last admin")

    old_role = target.role
    target.role = body.role
    _audit(db, actor, target, "role_change", {"old_role": old_role, "new_role": body.role})
    db.commit()
    db.refresh(target)
    return _member(db, target)
