# PhishNet RBAC — Role-Based Access Control Plan (APPROVED 2026-10-02)

Hide the **System** section (Settings + API Health) from non-privileged
accounts, and give the platform admin a GUI to grant those capabilities to
other users — a high-level account managing lower-level accounts.

Also fixes two live holes found during the audit:

1. `GET /api/settings` is fully anonymous in prod (leaks VT key preview).
2. `GET /api/health` anonymous leaks VT rotation stats, key call counts,
   model path, DB detail.

## Locked decisions

| Decision | Choice |
|---|---|
| Model | **Permission grants, not a role ladder.** `users.role` stays the baseline tier (`admin` = superuser, `user` = baseline); fine-grained capability strings live in `user_permissions` rows. Admin toggles capabilities per user in the GUI |
| Why not admin/manager/user roles | Ladder cannot express "settings but not health"; every new capability needs a role reshuffle. Grant table = one registry string, zero schema change |
| Escalation guard | You can only grant permissions **you yourself hold**. Only `role=admin` can change roles. Self-demotion and demoting the last admin are forbidden |
| Session | Permissions resolved from DB per request (one indexed query), **not** in the JWT — grants/revokes effective immediately, no re-login |
| Tenancy | Admin user list is **metadata only** (email, name, role, permissions, Gmail flag, timestamps). No endpoint ever returns another user's mail content |
| Fail mode | Missing permission → **403** with `{"detail": "Missing permission: <perm>"}` (endpoint existence is not a secret — unlike row tenancy which uses 404) |

## Permission registry (code, `app/permissions.py`)

```python
PERMISSIONS = {
    "system.settings": "View and edit Settings (thresholds, API keys)",
    "system.health":   "View API Health dashboard + component detail",
    "users.manage":    "Manage user accounts and grant permissions",
}
ROLE_DEFAULTS = {"admin": all three, "user": set()}
```

Effective permissions = `ROLE_DEFAULTS[role] ∪ grants(user_id)`.

## Data model — migration `0012_user_permissions.py`

```sql
user_permissions(
  id          SERIAL PK,
  user_id     INT FK→users.id ON DELETE CASCADE, INDEX,
  permission  VARCHAR(64),
  granted_by  INT FK→users.id NULL,
  created_at  TIMESTAMP,
  UNIQUE(user_id, permission)
)
```

Additive; no backfill (admin is implicit). Downgrade drops the table.

## Backend surface

| Endpoint | Today | After |
|---|---|---|
| `GET /settings` | **anonymous** | `require_permission("system.settings")` |
| `PUT /settings` | `require_admin` | `require_permission("system.settings")` |
| `POST /settings/api-keys` | `require_admin` | `require_permission("system.settings")` |
| `GET /health` | anonymous, full detail | always 200; slim `{status, version, response_time_ms}` for everyone, `components` only with `system.health` (nginx probe + offline banner contract preserved) |
| `GET /users` | — | `require_permission("users.manage")` — list accounts (metadata) |
| `PUT /users/{id}/permissions` | — | `require_permission("users.manage")` — replace grant set; each grant ⊆ actor's own holds |
| `PATCH /users/{id}/role` | — | `require_admin` + self/last-admin guards |
| `GET /auth/me` | role only | += `permissions: string[]` (full effective set) |

Audit: every grant/revoke/role-change appends `audit_log` rows
(`permission_grant` / `permission_revoke` / `role_change`).

## Frontend

- `AuthUser` += `permissions: string[]`; helper `can(user, perm)`
  (admin gets all — server already returns the full list).
- **Sidebar**: `systemItems` filtered per permission — Settings iff
  `system.settings`, API Health iff `system.health`, new **Users** item iff
  `users.manage`. Section hidden when empty. Bottom System Status panel
  (DB/ML dots) gated behind `system.health`.
- **Routes**: `RequirePermission` wrapper on `/settings`, `/system-health`,
  `/users` → redirect `/` when missing. Pages handle 403 gracefully too
  (mid-session revocation).
- **`UsersPage.tsx`** (`/users`): table of accounts — avatar, email, name,
  role badge, Gmail status, last login, per-permission toggle switches.
  Self-lockout hints: cannot remove own `users.manage`.

## Tests (`tests/test_rbac.py`, ~15 cases)

- Settings GET: anon 401 / bare user 403 / granted 200; PUT same matrix.
- Health: anon slim (no `components` key) / `system.health` holder full /
  probe keeps `status`.
- `/users`: anon 401 / user 403 / admin 200.
- Grant → target gains access immediately; revoke → loses it.
- Grantor cannot grant a permission they do not hold.
- Self-demotion + last-admin demotion guarded (400/403).
- `audit_log` rows written for grant/revoke/role_change.
- `/auth/me` returns `permissions`.

Existing suites stay green (test users are admin; `TestAdminGate` user B has
no grants → still 403).

## Phases (house process: gates → deploy → verify → commit+push each → graphify)

| Phase | Deliverables |
|---|---|
| **R1** Backend | mig 0012, `app/permissions.py`, endpoint gating + slim health, `users` API, `/auth/me` permissions, tests → pytest 75% gate → deploy → curl matrix verify → commit+push |
| **R2** Frontend | `can()`, sidebar/route gating, `UsersPage`, 403 states → tsc/lint/build gate → deploy → commit+push |
| **R3** Live verify | Playwright: admin sees System+Users → grant `system.settings` to user B → B gains Settings → revoke → disappears. Screenshots `rbac_*.png` → push |

## Out of scope (recorded)

- P4 privacy items (export/delete, body encryption) — separate workstream.
- API-key (`X-API-Key`) machine path — unchanged (`ApiKeyMiddleware`).
- Row-level content tenancy — already enforced (P2); RBAC adds capability
  layer only.
