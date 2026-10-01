# PhishNet Multi-Tenant Platform — Plan (APPROVED 2026-10-01)

Turn the single-mailbox dashboard into a multi-user platform where people sign
in with Google, link their own Gmail, and get private per-user analysis — at
**zero recurring cost**.

## Locked decisions

| Decision | Choice |
|---|---|
| OAuth origin | Free subdomain (DuckDNS / js.org) + Let's Encrypt HTTPS = $0 |
| Privacy bar | **Realistic**: server scans mail but never exposes it — no admin UI/API path to user content, encryption at rest, audit trail, one-click deletion |
| Sign-in flow | **One combined consent**: single Google click = sign-in identity + `gmail.readonly` + refresh token |
| Existing data | Backfilled to the platform admin account (`ADMIN_EMAILS` env) |

## 1. Research findings (verified 2026-10-01)

**Cost = $0:**

- Google Cloud OAuth client + Sign in with Google / One Tap: free, no card
- Gmail API: *"All standard use of the Gmail API is available at no additional
  cost"* — 80M quota units/day, `messages.get` = 5 units
- Restricted-scope verification: free (screencast + privacy policy + time)
- Let's Encrypt: free · Authlib / PyJWT / cryptography: OSS
- Runs on the existing AWS box + Postgres

**Hard constraints:**

1. **Google rejects raw IP origins** (`Host: raw IP addresses are not allowed`;
   localhost exempt for dev). One Tap also requires HTTPS → free subdomain.
2. **`gmail.readonly` is a restricted scope.** Consent screen in *Testing*:
   up to 100 test users, no verification. Beyond → free verification review.
3. **Testing-mode refresh tokens expire in 7 days** (official Google docs).
   Fix: **Publish App → In production** makes tokens long-lived immediately;
   users see an "unverified app" warning until the free verification completes.
4. **Combined consent = authorization-code flow** — refresh tokens are only
   issued on a server-side code exchange (never to browser JS).
5. **Ingestion = Gmail API `messages.get(format=RAW)`** → returns full RFC822 →
   existing MIME parse/store pipeline reuses almost untouched. Chosen over
   IMAP XOAUTH2 (needs the far scarier full `mail.google.com` scope).
   `fetch_state` upgrades from IMAP UID to Gmail `historyId`.
6. **Baseline**: 14 tables, zero owner columns; mailbox creds process-global;
   no login route, no 401 handling.

## 2. Target architecture

### 2.1 Auth flow (one combined consent)

```
/login → "Sign in with Google"
  → GET /api/auth/google  (302 accounts.google.com/o/oauth2/v2/auth
       response_type=code
       scope=openid email profile …/gmail.readonly
       access_type=offline  prompt=consent  state=<CSRF>)
  → user sees ONE consent screen
  → GET /api/auth/callback?code&state
       backend: exchange code (Authlib) → access + refresh + id_token
       verify id_token (JWKS sig, aud, iss, exp, email_verified)
       upsert users row (google_sub unique)
       encrypt refresh token (Fernet / TOKEN_ENCRYPTION_KEY)
       issue own session JWT → httpOnly Secure SameSite=Lax cookie
       audit_log(actor=user, action=login)
  → redirect /  (mailbox linked in the same click)
```

- **Returning users**: Google One Tap on `/login` → `credential` (ID token) →
  `POST /api/auth/credential` → same session cookie; refresh token already
  stored. If revoked → "Reconnect Gmail" banner.
- Session: own HS256 JWT (7 days) in httpOnly cookie — JS never touches it.
- CSRF: OAuth `state` cookie + SameSite=Lax; GIS double-submit `g_csrf_token`.
- New deps: `Authlib` (code flow), `PyJWT[crypto]` (session + ID verify),
  `cryptography` (Fernet).

### 2.2 Tenancy — shared schema, row-level ownership

- `users` table: `id, google_sub (unique), email, name, picture, role,
  gmail_refresh_token_enc, gmail_connected, token_revoked_at, timestamps`.
- `user_id` FK on owner tables: `emails`, `alerts`, `campaigns`, `fetch_state`,
  `audit_log`, `evidence_chain`, `attachments`. Children (`verdicts`,
  `url_results`, `email_sources`, `received_hops`, `auth_results`,
  `indicators`) scope through parent joins. `ip_intil` stays global (cache).
- Enforcement: `get_current_user` dependency + `scoped()` query helpers;
  cross-tenant access → **404** (no existence leaks). Isolation test suite.
- New files: `uploads/<user_id>/<email_id>/…`; existing files stay put.
- Migration backfills all existing rows → admin user (`ADMIN_EMAILS`).

### 2.3 Ingestion (no per-user .env config)

- `app/ingestion/gmail.py` — `GmailApiAdapter`: refresh stored token →
  `users.messages.list` (historyId delta) → `messages.get(format=RAW)` →
  existing `_parse_and_store`.
- Legacy IMAP adapter kept for the platform mailbox (no feature removal).
- Triggers: Fetch button (per signed-in user) + `worker` compose service
  (APScheduler, single instance — uvicorn runs 2 workers).
- Token lifecycle: auto-refresh; `invalid_grant` → `token_revoked_at` +
  reconnect banner.

### 2.4 Privacy (realistic tier)

| Guarantee | Mechanism |
|---|---|
| Admin cannot read user mail via product | `role=admin` gets no endpoint returning others' bodies/attachments; metadata only |
| No accidental exposure | bodies encrypted at rest (Fernet), refresh tokens encrypted, mail never in logs (hygiene test) |
| User sovereignty | export (zip) + hard-delete account + disconnect Gmail |
| Accountability | `audit_log.user_id`; login/fetch/scan/export/delete recorded |
| Third-party leakage control | per-user VT hash-lookup toggle |
| Honest docs | "What we can and cannot see" — server processes plaintext to scan; protection is exposure/tenancy/DB-theft, not host-level admin |

## 3. Schema change summary (migration `0010` + `0011`)

```
0010  users (new): google_sub, email, name, picture, role,
      gmail_refresh_token_enc, gmail_connected, token_revoked_at,
      created_at, last_login_at
0011  user_id FK+index: emails, alerts, campaigns, fetch_state,
      audit_log, evidence_chain, attachments   (backfill → admin)
```

## 4. API surface

- New: `GET /api/auth/config`, `GET /api/auth/google`, `GET /api/auth/callback`,
  `POST /api/auth/credential`, `GET /api/auth/me`, `POST /api/auth/logout`,
  `GET /api/account/export`, `DELETE /api/account`,
  `POST /api/account/gmail/disconnect`.
- Every existing endpoint gains `Depends(get_current_user)` → 401 w/o cookie.
  `/health`, `/docs`, `/auth/*` stay public. `X-API-Key` middleware kept as
  machine path. `PUT /api/settings` (.env writer) becomes admin-only.
- Public routes → axios 401 interceptor → `/login`.

## 5. Frontend

- `/login` (outside Layout): GIS script, branded card, combined-consent
  button, One Tap auto-prompt, error display from `?error=`.
- `AuthProvider` guard: boot `GET /api/auth/me`; no session → `/login`.
- Header: avatar + menu (email, role, Logout; later Export/Delete/Disconnect).
- Reconnect banner when `gmail_connected=false` / `token_revoked_at`.

## 6. Infra / config

- **Google console (once)**: project → enable Gmail API → consent screen
  (External, scopes openid/email/profile/gmail.readonly, test users) →
  **Publish App** → Web client (origins + `…/api/auth/callback` redirect).
- New env (never committed): `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`,
  `GOOGLE_REDIRECT_URI`, `SESSION_SECRET`, `TOKEN_ENCRYPTION_KEY`,
  `ADMIN_EMAILS`, `SESSION_COOKIE_SECURE`.
- nginx/certbot for the free subdomain; `/health` LB probe unchanged.
- New compose service `worker` (`python -m app.worker`).

## 7. Phases (each: gates → deploy → Playwright verify → commit+push → graphify)

| Phase | Deliverables |
|---|---|
| **P0** Prerequisites | Free subdomain + HTTPS; GCP console setup; env keys |
| **P1** Auth core | users + mig 0010; combined-consent endpoints; session cookie; `/login` + guard + avatar; axios 401; mocked-Google tests |
| **P2** Tenancy | user_id columns + backfill; scoped() everywhere; isolation test suite; per-user fetch_state; audit wiring |
| **P3** Gmail sync | Gmail API adapter; encrypted refresh tokens + reconnect UX; worker service; live E2E with real account |
| **P4** Privacy | body encryption at rest; export/delete; VT toggle; log-hygiene test; admin enforcement tests; visibility doc |
| **P5** Scale/ops | per-user quotas; worker staggering; backups; optional RLS; sync monitoring |

Gates every phase: backend `pytest --cov-fail-under=75`, frontend
`tsc && lint && build`, prod deploy, Playwright evidence, per-commit pushes.

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| 7-day refresh expiry (Testing) | P0: Publish App immediately; `token_revoked_at` + reconnect banner anyway |
| "Unverified app" warning | Free verification after P3 (screencast + privacy policy) |
| 100 test-user cap | Verification lifts it; launch scale < 100 |
| Free subdomain latency/revocation | duckdns fallback; promote to owned domain later (env + console origins only) |
| VT quota shared across users | 9-key pool + per-user quotas; per-user keys later |
| E2EE scope creep | Explicitly out of scope; roadmap only |

## 9. Roadmap

Verification → owned domain → non-Gmail IMAP adapters → org/team tenants
(`org_id` layer) → client-side scanning research (true E2EE) → Celery (G3).
