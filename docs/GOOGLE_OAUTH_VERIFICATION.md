# Google OAuth Verification — Data Access Answers & Demo Video (gmail.readonly)

Goal: remove the "Google hasn't verified this app" / tester warning screen by
completing brand verification → data access verification → publishing the
consent screen to **In production**.

Status of this project as of 2026-10-02: consent screen in **Testing**, one
restricted scope (`https://www.googleapis.com/auth/gmail.readonly`) plus the
non-sensitive sign-in scopes (`openid email profile`). Source of truth for the
requested scopes: `GOOGLE_SCOPES` in `app/config.py:45`.

---

## 1. Why the warnings appear

| Consent screen status | What users see |
|---|---|
| Testing (current) | Tester warning screen for every login, **refresh tokens expire in 7 days** (weekly re-login for Gmail sync), test-user cap |
| Submitted, unverified | Unverified-app screen until review completes |
| Verified + **In production** | Normal consent screen, warnings gone, refresh tokens long-lived |

Verification is only required if the app is offered to the public. To remove
the warnings for everyone, submit and publish.

---

## 2. Prerequisites (do these first, in order)

1. **APIs enabled**: Gmail API + Identity toolkit/APIs & Services on the project.
2. **Branding published** (hard prerequisite — Verification Center refuses
   data-access requests otherwise):
   - `console.developers.google.com/auth/branding`
   - App name **PhishNet** (must match what the video shows), logo, app
     homepage `https://phishing-guard.duckdns.org`, privacy policy URI
     `https://phishing-guard.duckdns.org/privacy-policy.html`, user support
     email + developer contact emails (must be monitored — Google emails
     here during review).
   - Click **Verify Branding** → automated review minutes → **Publish
     branding** within 7 days of passing.
3. **Domain verification** in Google Search Console for `duckdns.org` /
   `phishing-guard.duckdns.org`, using a Google account that is Owner/Editor
   on the Cloud project. Easiest: URL-prefix property
   `https://phishing-guard.duckdns.org/` + HTML-token file served by nginx;
   or a DNS TXT record on the DuckDNS domain for a domain property.
4. **Homepage requirements** (already met, re-check): public, describes the
   app, links to privacy policy + terms. Login page carries both links
   (`frontend/src/pages/LoginPage.tsx:255,264`).
5. **Privacy policy** (already met, re-check): hosted on the same domain,
   discloses the exact scope, links the Google API Services User Data Policy
   and the Limited Use requirements
   (`frontend/public/privacy-policy.html` §6). Do not change its meaning
   without re-reading the Limited Use rules.
6. **Scope hygiene**: declare exactly what the code requests — nothing more.
   Data Access page must list `openid`, `email`, `profile`,
   `gmail.readonly` and no stale scopes (an unrequested declared scope or an
   undeclared requested scope both re-trigger the warning screen).
7. **Do not add new scopes** between submission and approval.

---

## 3. Data Access answers

### 3a. "What features will you use?"

This question asks for the app's **permitted application type** — pick from
Google's approved Gmail use cases
(`developers.google.com/workspace/workspace-api-user-data-developer-policy`):

1. Built-in and web email clients that let users read and process email via a
   user interface.
2. Applications that automatically back up email.
3. Applications that enhance the email experience for productivity.
4. Applications that use information from emails to provide **reporting or
   monitoring services for the benefit of users**.

**Select the options matching 1 and 4** — PhishNet shows the user their
messages in a web inbox (read/process via UI) and monitors message content
for phishing (reporting/monitoring for the user's benefit). If the console's
checkbox labels don't map cleanly to those two, **select nothing** — Google
explicitly permits submitting with no selection and classifies the app type
themselves (Restricted scope verification doc, "Permitted application types").

Do not select anything implying automatic backup, sending, or marketing use.

### 3b. "How will the scopes be used?" (justification)

Paste-ready text — plain, specific to this codebase, no marketing filler:

> PhishNet is a phishing-detection web application. When a user signs in with
> their Google account, the same consent screen requests
> `https://www.googleapis.com/auth/gmail.readonly`. With that grant the app
> calls the Gmail API (`users.messages.list`, then `users.messages.get` with
> `format=raw`) to retrieve the user's most recent received messages. Each
> message is parsed and scanned locally: a scikit-learn classifier scores the
> text, YARA rules and header authentication checks (SPF/DKIM/DMARC) flag
> indicators, and suspicious URLs or file hashes are checked against
> VirusTotal at the user's option. The scan verdict, score breakdown and
> evidence are displayed back to the user in the app's inbox and scan-result
> pages, so the user can identify which of their own messages are phishing
> attempts. Messages are stored encrypted in a per-account database scope;
> full message bodies are never sent to third parties, the data is never
> sold, shared or used for advertising, and it is never used to train
> machine-learning models. Users can revoke access at any time from
> myaccount.google.com/permissions, and can request deletion of their account
> and all stored messages, which we complete within 30 days.
>
> `gmail.metadata` is not sufficient for this app: it returns headers and
> labels but no message bodies, and phishing detection depends on body
> content — the wording of the lure, the links it contains, and the text of
> the request. We request no write scope at all: no `gmail.send`,
> `gmail.modify`, `gmail.compose` or `mail.google.com`. The access is
> strictly read-only and limited to messages the user has chosen to scan.

Why this passes review: names the real endpoints, the real features shown in
the UI, concrete storage/retention/revocation behavior, an explicit
"why not the narrower scope" paragraph (required for restricted scopes), and
matches what the privacy policy already discloses. If Google's reviewer
cross-checks the video against this text, the two line up feature for feature.

**Documentation links (up to 3):**
1. `https://phishing-guard.duckdns.org/` (homepage)
2. `https://phishing-guard.duckdns.org/privacy-policy.html`
3. `https://github.com/Supernova70/PhishNet` (README describing the scanner)

---

## 4. Demo video

Official requirements (support.google.com/cloud/answer/13804565):

- End-to-end flow **including the OAuth grant**.
- The consent screen fully visible, **English** selected (language toggle,
  bottom-left), app name matching the submission, and the **same exact
  scopes** as declared.
- Address bar of the consent screen must show the OAuth **client ID**.
- Functionality that uses each requested scope, demonstrated in the same app
  (name/branding) that was submitted.
- Text or voice narration calling out these points is explicitly recommended.
- Upload to YouTube Studio, **Visibility: Unlisted**, paste link in the
  YouTube field.

Recording context (from your console notice): the app is already on public
infrastructure, so record in the current **Testing** status with your test
account — the unverified/tester warning screen **will appear and must be
shown** in the video. That is expected, not a defect.

### Shot list (~2–3 minutes)

| # | Shot | Callout (on-screen text) |
|---|---|---|
| 1 | Login page of PhishNet (app name + branding visible) | "PhishNet — end-to-end demo" |
| 2 | Click **Sign in with Google** → full consent screen appears | "Consent screen: app name PhishNet; scope = Read your email messages and settings" |
| 3 | Zoom on address bar showing `client_id=` | "OAuth client ID matches the submitted project" |
| 4 | Language toggle bottom-left = English | "Language: English" |
| 5 | Tester/unverified warning screen → Advanced → continue | "Expected warning: app is in Testing status" |
| 6 | Land on dashboard → click **Fetch Emails** → messages appear in inbox | "gmail.readonly: messages fetched via Gmail API" |
| 7 | Open a message / run scan → verdict, score, evidence shown | "Scanned locally — classifier, YARA, SPF/DKIM/DMARC, URL reputation" |
| 8 | Scan Results page (scores, threat charts) | "Scan output uses the fetched messages — read-only, per-account" |
| 9 | Settings page showing VT key config (optional) | "No send/modify scopes are requested" |
| 10 | Optional: myaccount.google.com/permissions revoke | "User can revoke access at any time" |

Rules of thumb: one continuous screen recording (cuts OK), no unrelated
browser tabs, keep the cursor on the named controls, narration or captions
naming each requirement as it is satisfied.

---

## 5. Security assessment (the long pole)

Because PhishNet **stores Gmail data on a server**, the restricted-scope rules
require a security assessment — CASA Tier 2 via the
[App Defense Alliance](https://appdefensealliance.dev/casa) — annual Letter of
Assessment. Google's verification flow will email next steps after the data
access submission; the process can take **several weeks**. Budget for it in
the timeline.

Controls the assessor will look for — current state in this repo:

| Requirement | Status |
|---|---|
| HTTPS in transit | ✅ nginx TLS |
| OAuth refresh tokens encrypted at rest | ✅ Fernet (`TOKEN_ENCRYPTION_KEY`) |
| User data encrypted at rest | ⚠️ confirm the database volume (EBS) is encrypted |
| Key material managed, not in source | ⚠️ keys live in `.env.prod` on the host — consider a secrets manager/HSM-equivalent |
| OWASP-top-10 hygiene | ✅ (input validation, SSRF/ traversal tests, session hardening) |
| Incident notification to security@google.com | 📝 add to runbook |
| Data deletion on user request | ✅ documented (email request, ≤30 days) |

---

## 6. Compliance notes that must stay true

- **Limited Use**: no selling, no ads, no credit scoring, no human reading of
  messages without consent, no transfer outside the stated purpose. The
  attestation sentence is already in the privacy policy §6.
- **Never train a model** (foundation/generalized or otherwise) on message
  content or derivatives of it — this is a hard Gmail/Workspace policy rule
  with a dedicated reviewer question. PhishNet's classifier is trained offline
  on public corpora; keep it that way and answer the AI question accordingly
  ("no Google user data is used to train or improve AI/ML models").
- **In-product disclosure**: the sign-in flow must explain the Gmail access
  request near the consent button (not only in the privacy policy). ✅ Already
  present on the login card under the button: "Connect your Gmail securely for
  read-only phishing analysis" + "Phishing Guard scans your emails for threats
  without sending, deleting, or modifying your email"
  (`frontend/src/pages/LoginPage.tsx:241,247`).
- **Annual recertification** + re-assessment; Google emails the developer
  contacts when it is due.
- Keep the consent screen in **Testing** until approval day, then click
  **Publish app** → status **In production** → warning screens gone.

## 7. Submission runbook

1. `console.developers.google.com/auth/branding` → Verify → Publish branding.
2. Search Console → verify `phishing-guard.duckdns.org`.
3. `console.developers.google.com/auth/scopes` (Data access) → confirm scope
   list = exactly the four scopes above.
4. `console.developers.google.com/auth/verification` (Verification Center) →
   Data access → fill: features selection (§3a), justification (§3b),
   3 doc links, YouTube unlisted link (§4).
5. Watch **both** the console and the developer contact inbox for Trust &
   Safety follow-ups (use-case questions, AI question from §6).
6. On approval: consent screen → **Publish app**. Then re-test a fresh
   Google login: no warning screen.
7. Expect CASA Tier 2 assessment instructions by email (§5) — complete to
   keep restricted-scope access past the grace window.
