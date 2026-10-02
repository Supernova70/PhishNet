"""RBAC tests (R1): permission grants, endpoint gating, user management.

SQLite + isolated FastAPI app, offline. Users are created with real session
cookies (not dependency overrides) so /health's optional-auth slim/full
branching is exercised the same way production exercises it.
"""

from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.auth import router as auth_router
from app.api.health import router as health_router
from app.api.settings import router as settings_router
from app.api.users import router as users_router
from app.auth.session import COOKIE_NAME, create_session_token
from app.dependencies import get_db
from app.models import Base
from app.models.audit_log import AuditLog
from app.models.user import User
from app.models.user_permission import UserPermission
from app.permissions import PERMISSIONS, effective_permissions

ADMIN, BARE, MGR = 1, 2, 3


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/rbac.db")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    admin = User(id=ADMIN, google_sub="sub-admin", email="admin@rbac.test",
                 name="Admin", role="admin")
    bare = User(id=BARE, google_sub="sub-bare", email="bare@rbac.test",
                name="Bare", role="user")
    mgr = User(id=MGR, google_sub="sub-mgr", email="mgr@rbac.test",
               name="Mgr", role="user")
    session.add_all([admin, bare, mgr])
    # mgr holds system.settings + users.manage but NOT system.health
    # (proves each capability gates independently).
    session.add_all([
        UserPermission(user_id=MGR, permission="system.settings", granted_by=ADMIN),
        UserPermission(user_id=MGR, permission="users.manage", granted_by=ADMIN),
    ])
    session.commit()

    app = FastAPI()
    app.include_router(auth_router)
    app.include_router(health_router)
    app.include_router(settings_router)
    app.include_router(users_router)
    app.dependency_overrides[get_db] = lambda: session

    def client_for(user_id):
        client = TestClient(app)
        client.cookies.set(COOKIE_NAME, create_session_token(session.get(User, user_id)))
        return client

    yield {
        "app": app,
        "db": session,
        "anon": TestClient(app),
        "admin": client_for(ADMIN),
        "bare": client_for(BARE),
        "mgr": client_for(MGR),
    }
    session.close()


# ── effective permissions ──────────────────────────────────────────────

class TestEffectivePermissions:
    def test_admin_holds_everything_implicitly(self, env):
        assert effective_permissions(env["db"], env["db"].get(User, ADMIN)) == set(PERMISSIONS)

    def test_bare_user_starts_empty(self, env):
        assert effective_permissions(env["db"], env["db"].get(User, BARE)) == set()

    def test_grants_union_on_role_baseline(self, env):
        perms = effective_permissions(env["db"], env["db"].get(User, MGR))
        assert perms == {"system.settings", "users.manage"}
        assert "system.health" not in perms


# ── settings gating ────────────────────────────────────────────────────

class TestSettingsGate:
    def test_anon_get_401(self, env):
        assert env["anon"].get("/settings").status_code == 401

    def test_bare_user_get_403_names_permission(self, env):
        resp = env["bare"].get("/settings")
        assert resp.status_code == 403
        assert "system.settings" in resp.json()["detail"]

    def test_granted_user_get_200(self, env):
        assert env["mgr"].get("/settings").status_code == 200

    def test_admin_get_200(self, env):
        assert env["admin"].get("/settings").status_code == 200

    def test_bare_user_put_403(self, env):
        resp = env["bare"].put("/settings", json={"scan_threshold": 55})
        assert resp.status_code == 403

    def test_granted_user_put_200(self, env):
        with patch("app.api.settings.os.path.exists", return_value=False):
            resp = env["mgr"].put("/settings", json={"scan_threshold": 55})
        assert resp.status_code == 200
        assert resp.json()["scan_threshold"] == 55

    def test_bare_user_api_keys_403(self, env):
        resp = env["bare"].post(
            "/settings/api-keys", json={"provider": "virustotal", "api_key": "x"}
        )
        assert resp.status_code == 403

    def test_granted_user_api_keys_200(self, env, monkeypatch):
        monkeypatch.setenv("VT_API_KEY", "abcdefghijklmnop")
        with patch("app.api.settings.os.path.exists", return_value=False):
            resp = env["mgr"].post(
                "/settings/api-keys",
                json={"provider": "virustotal", "api_key": "abcdefghijklmnop"},
            )
        assert resp.status_code == 200
        assert resp.json()["configured"] is True


# ── health slim/full ───────────────────────────────────────────────────

class TestHealthGating:
    def test_probe_contract_anon_200_slim(self, env):
        resp = env["anon"].get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "components" not in data

    def test_session_without_permission_is_slim(self, env):
        data = env["bare"].get("/health").json()
        assert "components" not in data

    def test_settings_grant_does_not_imply_health(self, env):
        # mgr has system.settings + users.manage but not system.health
        data = env["mgr"].get("/health").json()
        assert "components" not in data

    def test_admin_sees_components(self, env):
        data = env["admin"].get("/health").json()
        assert "components" in data
        assert "virustotal" in data["components"]

    def test_granted_health_holder_sees_components(self, env):
        env["db"].add(UserPermission(user_id=BARE, permission="system.health",
                                     granted_by=ADMIN))
        env["db"].commit()
        data = env["bare"].get("/health").json()
        assert "components" in data


# ── /auth/me permissions ──────────────────────────────────────────────

class TestMePermissions:
    def test_bare_returns_empty(self, env):
        assert env["bare"].get("/auth/me").json()["permissions"] == []

    def test_mgr_returns_effective_set(self, env):
        data = env["mgr"].get("/auth/me").json()
        assert data["permissions"] == ["system.settings", "users.manage"]

    def test_admin_returns_all(self, env):
        assert env["admin"].get("/auth/me").json()["permissions"] == sorted(PERMISSIONS)


# ── users API access ──────────────────────────────────────────────────

class TestUsersAccess:
    def test_anon_401(self, env):
        assert env["anon"].get("/users").status_code == 401

    def test_bare_403(self, env):
        assert env["bare"].get("/users").status_code == 403

    def test_granted_mgr_lists_metadata_only(self, env):
        data = env["mgr"].get("/users").json()
        assert data["count"] == 3
        assert data["permission_catalog"] == PERMISSIONS
        member = next(u for u in data["users"] if u["id"] == BARE)
        assert member["role"] == "user"
        assert member["permissions"] == []
        assert member["grants"] == []
        assert set(member) <= {"id", "email", "name", "picture", "role",
                               "permissions", "grants", "gmail_connected",
                               "created_at", "last_login_at"}

    def test_admin_lists(self, env):
        assert env["admin"].get("/users").status_code == 200

    def test_missing_user_404(self, env):
        resp = env["admin"].put("/users/9999/permissions",
                                json={"permissions": []})
        assert resp.status_code == 404


# ── granting + revoking ────────────────────────────────────────────────

class TestGrants:
    def test_grant_takes_effect_immediately_no_relogin(self, env):
        assert env["bare"].get("/settings").status_code == 403
        resp = env["mgr"].put(f"/users/{BARE}/permissions",
                              json={"permissions": ["system.settings"]})
        assert resp.status_code == 200
        # same cookie, no re-login — permission is live
        assert env["bare"].get("/settings").status_code == 200

    def test_revoke_takes_effect_immediately(self, env):
        env["mgr"].put(f"/users/{BARE}/permissions",
                       json={"permissions": ["system.settings"]})
        assert env["bare"].get("/settings").status_code == 200
        env["mgr"].put(f"/users/{BARE}/permissions", json={"permissions": []})
        assert env["bare"].get("/settings").status_code == 403

    def test_cannot_grant_beyond_own_holds(self, env):
        # mgr does not hold system.health
        resp = env["mgr"].put(f"/users/{BARE}/permissions",
                              json={"permissions": ["system.health"]})
        assert resp.status_code == 403
        assert "system.health" in resp.json()["detail"]

    def test_unknown_permission_400(self, env):
        resp = env["mgr"].put(f"/users/{BARE}/permissions",
                              json={"permissions": ["does.not.exist"]})
        assert resp.status_code == 400

    def test_bare_cannot_manage(self, env):
        resp = env["bare"].put(f"/users/{BARE}/permissions",
                               json={"permissions": ["system.settings"]})
        assert resp.status_code == 403

    def test_admin_can_grant_anything(self, env):
        resp = env["admin"].put(f"/users/{BARE}/permissions",
                                json={"permissions": ["system.health", "users.manage"]})
        assert resp.status_code == 200
        assert resp.json()["permissions"] == ["system.health", "users.manage"]

    def test_self_lockout_guard_for_non_admin_manager(self, env):
        resp = env["mgr"].put(f"/users/{MGR}/permissions",
                              json={"permissions": ["system.settings"]})
        assert resp.status_code == 400
        assert "self-lockout" in resp.json()["detail"]

    def test_grant_revoke_audited(self, env):
        env["mgr"].put(f"/users/{BARE}/permissions",
                       json={"permissions": ["system.settings"]})
        env["mgr"].put(f"/users/{BARE}/permissions", json={"permissions": []})
        actions = [row.action for row in env["db"].query(AuditLog)
                   .order_by(AuditLog.id).all()]
        assert "permission_grant" in actions
        assert "permission_revoke" in actions
        row = env["db"].query(AuditLog).filter_by(action="permission_grant").first()
        assert row.entity_id == BARE and row.user_id == MGR
        assert row.detail_json["permission"] == "system.settings"


# ── role changes ───────────────────────────────────────────────────────

class TestRoleChanges:
    def test_non_admin_cannot_change_roles(self, env):
        resp = env["mgr"].patch(f"/users/{BARE}/role", json={"role": "admin"})
        assert resp.status_code == 403

    def test_promote_and_demote(self, env):
        resp = env["admin"].patch(f"/users/{BARE}/role", json={"role": "admin"})
        assert resp.status_code == 200
        assert resp.json()["role"] == "admin"
        # admin baseline: promoted user now holds everything without grants
        assert env["bare"].get("/settings").status_code == 200

        # promote a second admin first so demoting BARE isn't "last admin"
        env["admin"].patch(f"/users/{MGR}/role", json={"role": "admin"})
        resp = env["admin"].patch(f"/users/{BARE}/role", json={"role": "user"})
        assert resp.status_code == 200
        assert resp.json()["role"] == "user"
        # no explicit grants on BARE → access revoked with the role
        assert env["bare"].get("/settings").status_code == 403

    def test_self_demotion_forbidden(self, env):
        resp = env["admin"].patch(f"/users/{ADMIN}/role", json={"role": "user"})
        assert resp.status_code == 400

    def test_admin_emails_target_forbidden(self, env):
        # promote first — the guard only fires on an actual demotion
        env["admin"].patch(f"/users/{BARE}/role", json={"role": "admin"})
        env["db"].get(User, BARE).email = "configured-admin@rbac.test"
        env["db"].commit()
        with patch("app.api.users.get_settings") as gs:
            gs.return_value.admin_emails = ["configured-admin@rbac.test"]
            resp = env["admin"].patch(f"/users/{BARE}/role", json={"role": "user"})
        assert resp.status_code == 400
        assert "ADMIN_EMAILS" in resp.json()["detail"]

    def test_invalid_role_400(self, env):
        resp = env["admin"].patch(f"/users/{BARE}/role", json={"role": "superuser"})
        assert resp.status_code == 400

    def test_role_change_audited(self, env):
        env["admin"].patch(f"/users/{BARE}/role", json={"role": "admin"})
        row = env["db"].query(AuditLog).filter_by(action="role_change").first()
        assert row is not None
        assert row.detail_json == {"old_role": "user", "new_role": "admin"}
