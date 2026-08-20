# Dynamic URL Analysis Engine — 8-Week Capstone Implementation Plan

## 1. Project objective

Upgrade Phishing Guard's URL engine from string/reputation-only analysis to safe, explainable browser-based analysis.

At the end of eight weeks, the system should be able to:

1. extract and statically score URLs exactly as it does today;
2. decide, using a tested policy, which URLs justify dynamic analysis;
3. open eligible URLs in an isolated Playwright Chromium context;
4. observe redirects and the rendered DOM without clicking or submitting anything;
5. block requests to unsafe/internal destinations, including redirect targets;
6. persist static, VirusTotal, and dynamic evidence separately;
7. merge the evidence into an explainable final URL score;
8. run scans without holding the HTTP request open; and
9. display the dynamic evidence in the existing URL and scan-detail pages.

This is an evidence-collection engine, not a fully secure malware sandbox. The final report and demo must say this clearly.

### Implementation status — 20 August 2026

Weeks 1–4 are implemented:

- [x] configuration, result contracts, adapter boundary, and policy gate;
- [x] Public Suffix List domain comparison;
- [x] SSRF-focused URL/DNS/IPv4/IPv6 validation;
- [x] validated no-follow redirect preflight;
- [x] HTTP 202 background scan execution with task-owned DB sessions;
- [x] frontend polling for pending/running scans;
- [x] Playwright Chromium adapter with fresh contexts and bounded cleanup;
- [x] redirect, rendered DOM, TLS, popup/download, screenshot, and error evidence;
- [x] explainable dynamic scoring and static-score fallback;
- [x] offline unit tests plus a harmless local Chromium integration test.

Weeks 5–8 remain the next milestone: richer persisted fields/API typing/UI evidence, evaluation, retention tooling, hardening, and final presentation work.

## 2. What exists today

### Current end-to-end path

```text
POST /scans/{email_id}
        |
        v
create Scan row (pending)
        |
        v
ScanService.run_scan_by_id()                 currently synchronous
        |
        +--> TextAnalyzer
        |
        +--> UrlAnalyzer
        |      1. extract href/src/action/text URLs
        |      2. normalize and deduplicate
        |      3. reject a few literal local IPv4 forms
        |      4. apply 10 static rules
        |      5. optionally query VirusTotal sequentially
        |      6. final URL score = max(static, VT)
        |
        +--> AttachmentAnalyzer
        |
        v
persist UrlResult rows + Verdict.breakdown JSON
        |
        v
React pages read URL evidence from Verdict.breakdown
```

### Reusable parts

- `app/engines/url_analyzer.py` already has extraction, normalization, ten heuristic rules, VT lookup, and plain dataclass results.
- `app/services/scan_service.py` already owns orchestration, per-URL persistence, and verdict construction.
- `app/models/url_result.py` already reserves `dynamic_score`, `redirect_chain`, `dom_has_login_form`, `ssl_valid`, and `playwright_screenshot_path`.
- `frontend/src/hooks/usePollScan.ts` already knows how to poll pending/running scans.
- `frontend/src/pages/UrlAnalysis.tsx` and `ScanDetail.tsx` already have expandable per-URL evidence views.

### Important gaps and technical debt

1. The scan API is synchronous. Adding browser navigation inside the current request would create long, fragile requests.
2. URL safety checking only detects a few literal IPv4 cases. It does not cover DNS resolution, IPv6, link-local, multicast, reserved addresses, cloud metadata endpoints, credentials in URLs, or redirect targets.
3. The engine uses a naive last-two-label registered-domain calculation. It will mishandle domains such as `example.co.uk`; use the Public Suffix List through `tldextract`.
4. VirusTotal calls run sequentially and can add up to ten seconds per URL.
5. Dynamic columns exist but are not returned by the engine, written by `ScanService`, or exposed to the frontend.
6. `VerdictOut.breakdown` is typed as `Any`, so backend/frontend contract drift is easy.
7. The URL pages read copied evidence from `Verdict.breakdown`, not a dedicated typed URL-result API.
8. A Playwright browser context isolates cookies and storage, but it is not an OS or network security sandbox.

## 3. Scope decisions

### In scope

- Playwright Chromium, using the Python async API.
- Safe navigation and request interception.
- Redirect-chain and final-URL capture.
- Rendered password/login-form detection.
- Cross-domain form-action detection.
- TLS/navigation error capture.
- Download-attempt and popup-attempt observation, without accepting them.
- Screenshot evidence for successfully rendered pages.
- Feature flags, timeouts, URL caps, persistence, API/UI changes, tests, metrics, and documentation.
- FastAPI background-task execution as the semester-sized async boundary.

### Out of scope for these eight weeks

- Clicking buttons, filling fields, submitting forms, or logging in.
- Saving or executing downloads.
- Visiting already-confirmed malicious URLs merely to obtain a screenshot.
- Attachment detonation, Sysmon, Windows VMs, Redis, Celery, Kafka, Kubernetes, or a distributed crawler.
- Claiming production-grade containment without a separate egress-controlled sandbox.

## 4. Target architecture

```text
Client
  |
  | POST /scans/{email_id}
  v
FastAPI creates Scan(pending) and returns HTTP 202 + scan_id
  |
  +--> background scan function opens its own SQLAlchemy session
          |
          v
      Static URL analyzer + optional VT
          |
          v
      Dynamic policy gate
          |
          +--> skip: low value / already malicious / unsafe / over budget
          |
          +--> run: DynamicUrlAnalyzer
                    |
                    v
              BrowserAdapter interface
                    |
                    v
              PlaywrightBrowserAdapter
              - fresh context per URL
              - context-wide request route
              - DNS/IP validation per request
              - downloads disabled
              - service workers blocked
              - dialogs dismissed
              - strict time/URL budgets
                    |
                    v
              BrowserObservation (facts only)
                    |
                    v
              pure dynamic scorer (facts -> score + flags)
          |
          v
      persist UrlResult evidence + typed verdict breakdown
          |
          v
Client polls GET /scans/{scan_id} and renders evidence
```

The separation between observation and scoring is essential:

- `BrowserAdapter` collects facts.
- `DynamicUrlAnalyzer` applies policy and orchestration.
- a pure scorer converts facts to points and explanations.
- `ScanService` maps plain result objects to SQLAlchemy models.

This design makes most tests deterministic and runnable without internet or Chromium.

## 5. Core contracts

Create `app/engines/dynamic/models.py`:

```python
from dataclasses import dataclass, field

@dataclass
class BrowserObservation:
    attempted: bool = False
    final_url: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    page_title: str | None = None
    has_password_input: bool = False
    has_login_form: bool = False
    external_form_action: bool = False
    download_attempted: bool = False
    popup_attempted: bool = False
    tls_error: bool = False
    screenshot_path: str | None = None
    elapsed_ms: int = 0
    error_code: str | None = None
    error_detail: str | None = None

@dataclass
class DynamicUrlResult:
    status: str  # skipped | complete | timeout | blocked | error
    dynamic_score: float = 0.0
    dynamic_flags: list[str] = field(default_factory=list)
    observation: BrowserObservation = field(default_factory=BrowserObservation)
```

Define a `BrowserAdapter` protocol with one method:

```python
class BrowserAdapter(Protocol):
    async def observe(self, url: str, *, scan_id: int) -> BrowserObservation: ...
```

Production uses `PlaywrightBrowserAdapter`; unit tests use `FakeBrowserAdapter`.

## 6. Dynamic-analysis policy

Implement the policy as a pure function and test every branch.

### Never visit when

- dynamic analysis is disabled;
- the scheme is not HTTP or HTTPS;
- the URL contains username/password credentials;
- the host or any resolved A/AAAA address is non-public;
- VirusTotal has at least one malicious detection;
- the static score is already `>= 70`;
- the scan has reached its dynamic URL count or time budget; or
- the same normalized URL was already analyzed for this scan.

Already-malicious URLs do not need browser confirmation, and avoiding them reduces risk.

### Visit when

- `20 <= static_or_vt_score < 70`; or
- the URL is a known shortener; or
- flags contain embedded redirect, brand impersonation, IP hostname, or credential obfuscation.

### Budget

- maximum 3 dynamic URLs per email;
- maximum 12 seconds per navigation;
- maximum 20 seconds total browser work per URL;
- maximum 45 seconds total dynamic URL work per scan;
- maximum 8 main-frame redirects;
- maximum one page; close any popup immediately.

Make all values configurable. Defaults must keep dynamic analysis disabled until explicitly enabled.

## 7. Safe URL validation

Create `app/security/url_safety.py` and keep it independent from Playwright.

Validation order:

1. Parse with `urllib.parse.urlsplit`.
2. Allow only `http` and `https`.
3. Reject missing hosts, embedded credentials, malformed ports, and disallowed ports.
4. Normalize IDNs to ASCII using IDNA.
5. If the host is an IP literal, classify it with `ipaddress.ip_address`.
6. If the host is a domain, resolve every A and AAAA address.
7. Reject if any result is loopback, private, link-local, multicast, unspecified, reserved, or otherwise non-global.
8. Explicitly block common metadata endpoints, including `169.254.169.254` and IPv6 link-local ranges.
9. Resolve HTTP redirects with a no-follow preflight and validate every `Location` before Chromium navigation. Use context-wide routing for subsequent browser and JavaScript requests. Playwright routing alone does not reliably pause every HTTP 3xx hop.

Unit tests must include IPv4, IPv6, integer/hex-like IP representations if accepted by the parser, IDN hosts, userinfo, ports, DNS failures, mixed public/private DNS answers, and redirect-to-private cases.

Important limitation: application-level DNS checks reduce SSRF risk but do not eliminate DNS rebinding/time-of-check-to-time-of-use races. For real malicious internet URLs, run the browser in a separate container/VM with egress firewall rules that deny host, LAN, database, and metadata networks. The semester demo should use controlled harmless pages.

## 8. Browser behavior

Create `app/integrations/playwright_browser.py` using `playwright.async_api`.

For each eligible URL:

1. launch or acquire Chromium;
2. create a fresh context with `accept_downloads=False`, `service_workers="block"`, and `ignore_https_errors=False`;
3. register a context-level `route("**/*", handler)` before opening the page;
4. run the validated no-follow redirect preflight, then validate and route browser/JavaScript requests; abort unsafe requests;
5. record only main-frame navigation requests for the redirect chain;
6. dismiss dialogs and immediately close extra pages/popups;
7. navigate with a strict timeout and `wait_until="domcontentloaded"`;
8. wait a small bounded render window, such as 1–2 seconds, instead of waiting forever for `networkidle`;
9. inspect DOM locators without clicking:
   - `input[type=password]`;
   - forms containing password inputs;
   - the resolved `form.action` domain;
10. capture title, final URL, TLS/navigation errors, attempted downloads, and screenshot;
11. close page, context, browser, and Playwright in `finally` blocks.

For performance, Week 3 may launch Chromium per URL. Week 6 may optimize to one browser process per scan while still creating a new context per URL. Do not share contexts between URLs.

## 9. Explainable scoring

Keep `score_observation(observation, original_url)` pure.

| Dynamic evidence | Points |
|---|---:|
| Final registrable domain differs after redirects | 25 |
| Three or more main-frame redirects | 10 |
| Password input in rendered DOM | 30 |
| Form containing password input posts to another registrable domain | 30 |
| TLS/certificate navigation failure | 20 |
| Download attempted without user interaction | 25 |
| Popup attempted without user interaction | 10 |

Cap `dynamic_score` at 100. Save one human-readable flag per matched rule.

For the semester MVP:

```text
per_url_final_score = max(heuristic_score, vt_score, dynamic_score)
engine_url_score    = max(per_url_final_score for all URLs)
```

Using `max` preserves the existing behavior and prevents a browser failure from lowering a known static risk. After evaluation, weighted fusion can be a future experiment, not a Week-1 assumption.

## 10. Persistence and API changes

Keep the existing columns and add migration `0003_dynamic_url_evidence.py` for:

- `dynamic_status` string;
- `final_url` string;
- `dynamic_flags` JSON;
- `external_form_action` boolean;
- `download_attempted` boolean;
- `popup_attempted` boolean;
- `dynamic_error_code` string;
- `dynamic_error_detail` string;
- `dynamic_elapsed_ms` integer;
- `dynamic_analyzed_at` datetime.

Do not put raw HTML, cookies, request bodies, form values, or arbitrary page content in the database.

Replace the untyped URL portion of `VerdictOut.breakdown` with Pydantic models, or add a typed `UrlResultOut` response. The frontend must receive static score, VT score, dynamic score, final score, status, redirects, flags, form/TLS/download evidence, screenshot URL, elapsed time, and safe error codes.

Screenshots should be stored under:

```text
uploads/url_screenshots/<scan_id>/<sha256(normalized_url)>.png
```

Expose them through a controlled API/static mount, not raw filesystem paths. Add retention cleanup as a separate command; never delete screenshots inside a scan request.

## 11. Minimal asynchronous execution

In Week 2, change `POST /scans/{email_id}` to:

1. create `Scan(status="pending")`;
2. schedule a FastAPI `BackgroundTasks` function using only `scan_id`;
3. return HTTP 202 immediately;
4. inside the task, create a new `SessionLocal()` and call `run_scan_by_id(scan_id)`;
5. commit `complete` or `error` state and always close the session.

The existing polling hook can then be used as intended.

Be precise in the report: FastAPI background tasks improve HTTP responsiveness but are not durable. A process restart can lose work. Celery/Redis or another durable queue is the future scaling path, not required for this semester MVP.

## 12. Eight-week schedule and teacher reviews

### Weeks 1–2 — Review 1: architecture, safety gate, and async foundation

#### Week 1: baseline and contracts

- Run and record the current focused and full test suites.
- Draw the current and target URL-engine sequence diagrams.
- Refactor registered-domain comparison to `tldextract` with offline snapshot/cache behavior understood.
- Add configuration:
  - `DYNAMIC_URL_ENABLED=False`
  - navigation/total/scan budgets
  - URL count cap
  - screenshot directory and retention
  - allowed ports
- Add `BrowserObservation`, `DynamicUrlResult`, and `BrowserAdapter`.
- Implement and unit-test `should_run_dynamic_url()`.
- Define stable error codes such as `unsafe_target`, `dns_failure`, `navigation_timeout`, `tls_error`, and `browser_failure`.

#### Week 2: SSRF guard and non-blocking scan endpoint

- Implement `url_safety.py` with DNS/IP/IPv6 tests.
- Add redirect-target validation as a browser-adapter requirement.
- Convert scan trigger to HTTP 202 + background task + new DB session.
- Connect the existing polling UI and test pending -> running -> complete/error transitions.
- Confirm feature-flag-off behavior produces the same scores as the current system.

#### Teacher review 1 demonstration

Show:

1. current-vs-target architecture;
2. policy test matrix;
3. SSRF tests blocking localhost, private IPv4, IPv6 link-local, and a public-to-private redirect;
4. the API returning 202 while polling reports status; and
5. a written threat model and scope boundary.

Deliverables: architecture diagram, test report, policy table, API recording/screenshots, and a two-page design note.

### Weeks 3–4 — Review 2: working Playwright MVP

#### Week 3: observation adapter

- Add `playwright` and Chromium installation to project/Docker setup.
- Implement context lifecycle and `finally` cleanup.
- Add context-wide routing before navigation.
- Block service workers and downloads; dismiss dialogs; close popups.
- Capture final URL, main-frame redirect chain, title, TLS/navigation error, and elapsed time.
- Use a fake adapter for unit tests.

#### Week 4: DOM evidence and pure scorer

- Detect password inputs and login forms after JavaScript rendering.
- Resolve form action and compare registrable domains.
- Record download/popup attempts without interacting.
- Implement score rules and test every rule, combinations, and the 100-point cap.
- Add screenshot creation with hashed filenames.
- Build controlled harmless demo pages/scenarios:
  - clean page;
  - JavaScript-rendered password form;
  - cross-domain form action;
  - redirect chain;
  - attempted auto-download;
  - timeout page;
  - blocked redirect target.

#### Teacher review 2 demonstration

Run one controlled suspicious URL through Playwright and show the redirect chain, rendered login detection, screenshot, dynamic flags, and cleanup. Also show that no buttons/forms were touched and unsafe requests were aborted.

Deliverables: live MVP, unit/integration test results, browser lifecycle diagram, and sample structured observations.

### Weeks 5–6 — Review 3: full product integration

#### Week 5: engine and database integration

- Add migration 0003 and ORM fields.
- Call the dynamic analyzer after static/VT scoring only when policy permits.
- Enforce per-email URL/time budgets.
- Persist success, skip, block, timeout, and error states.
- Merge final score with `max(static, VT, dynamic)`.
- Keep static/VT results when Playwright fails.
- Make reruns idempotent so a scan does not create duplicate URL rows.

#### Week 6: typed API and frontend evidence

- Add typed Pydantic URL-result contracts.
- Extend React types.
- Update `UrlAnalysis.tsx` with static/dynamic/final score columns and dynamic-status filtering.
- Update `ScanDetail.tsx` with redirect timeline, DOM/TLS/download flags, elapsed time, errors, and screenshot thumbnail.
- Add a safe screenshot-serving endpoint.
- Improve browser lifecycle only if measurement shows startup is a bottleneck: reuse browser process per scan, never contexts.

#### Teacher review 3 demonstration

Submit an email containing clean, suspicious, and already-malicious test URLs. Show policy decisions, asynchronous status, per-URL persisted evidence, graceful timeout behavior, and final UI results.

Deliverables: migration, API schema, integrated UI, end-to-end recording, and database evidence query.

### Weeks 7–8 — Review 4: evaluation, hardening, and presentation

#### Week 7: evaluation and failure testing

- Create a versioned, harmless behavioral test corpus of at least 20 scenarios.
- Record static-only and static+dynamic outcomes.
- Measure:
  - policy eligibility rate;
  - dynamic completion, blocked, timeout, and error rates;
  - rule-level true/false positives on controlled scenarios;
  - per-URL median and p95 latency;
  - per-scan latency;
  - screenshot success rate;
  - added memory/CPU during browser runs.
- Test browser crash, DNS failure, connection refusal, TLS error, redirect loop, popup, auto-download, and database failure paths.
- Run migrations on a fresh database and upgrade an existing database copy.

#### Week 8: polish and defend the work

- Fix evaluation findings; freeze scope early in the week.
- Add structured logs with `scan_id`, URL hash, dynamic status, elapsed time, and error code. Do not log secrets or full query strings.
- Add screenshot cleanup command and operational runbook.
- Update README, architecture diagram, API examples, and threat model.
- Prepare a five-minute demo and backup screen recording.
- Prepare viva/interview answers and conduct at least two mock explanations.
- Tag a release and record exact test/metric results.

#### Teacher review 4 demonstration

Present the baseline, problem, architecture, security controls, live end-to-end result, evaluation table, limitations, and next steps. Demonstrate one failure case as well as one success case.

Deliverables: final release, report chapter, metrics table, threat model, demo video, slides, and resume bullet with measured values.

## 13. Test strategy

### Unit tests — fast and offline

- policy matrix;
- URL normalization and public-suffix comparison;
- URL safety and DNS classification;
- observation scoring;
- timeout/error mapping;
- score merge behavior;
- screenshot path generation;
- feature flag disabled behavior.

### Adapter contract tests

Run the same expectations against fake and Playwright adapters:

- returns a `BrowserObservation`;
- respects timeout;
- closes resources after success and failure;
- never returns raw page secrets;
- reports blocked requests consistently.

### Integration tests

- controlled pages for redirects and DOM changes;
- mocked VT using `httpx.MockTransport` or `respx`;
- database persistence of every dynamic status;
- HTTP 202 and polling lifecycle;
- screenshot API authorization/path handling.

### End-to-end tests

- email -> scan -> static gate -> browser -> database -> API -> UI;
- mixed URLs with maximum-three budget;
- browser unavailable still produces a completed static verdict;
- timeout does not leave the scan permanently running.

Do not make live malicious URLs part of automated tests.

## 14. Evaluation design

Use controlled behavior pages rather than claiming that synthetic pages prove real-world phishing accuracy. Maintain a manifest with scenario ID, expected observations, expected rules, and expected score range.

Recommended evaluation table:

| Scenario | Static score | Dynamic score | New evidence | Final score | Expected result | Latency |
|---|---:|---:|---|---:|---|---:|
| Clean HTTPS page | 0 | 0 | none | 0 | safe | measured |
| JS login on neutral URL | low | 30 | password input | 30 | suspicious | measured |
| Cross-domain credential form | low | 60 | password + external action | 60 | suspicious | measured |
| Multi-hop domain change | medium | 35 | redirect evidence | max | suspicious | measured |
| Redirect to private IP | medium | 0 | blocked | static | blocked safely | measured |

The report should distinguish:

- detection effectiveness on the controlled corpus;
- operational reliability/latency; and
- security-control coverage.

## 15. Risk register

| Risk | Impact | Mitigation | Evidence for teacher |
|---|---|---|---|
| SSRF/internal network access | critical | pre-resolve A/AAAA, validate every request, deny non-global IPs, controlled demos, document network sandbox limitation | blocking tests + threat model |
| Browser process hangs | high | per-navigation, per-URL, and per-scan budgets; cleanup in `finally` | timeout test |
| API becomes slow | high | HTTP 202 background execution and polling | timing demo |
| Background task lost on restart | medium | documented limitation; scan recovery command/future durable queue | limitation slide |
| Playwright unavailable | medium | feature flag and static fallback | failure demo |
| Too many URLs in one email | high | deduplication, priority order, maximum 3 visits | budget test |
| False positives from one DOM signal | medium | separate evidence flags, evaluation corpus, no hidden model | comparison table |
| Sensitive screenshot retention | medium | hashed path, controlled serving, retention command, no form interaction | storage design |
| Scope expansion | high | URL-only definition; defer attachments/distributed queue | backlog |

## 16. What to learn and be able to explain

### By Review 1

- static versus dynamic analysis;
- FastAPI request lifecycle and background-task limitations;
- SQLAlchemy session ownership;
- SSRF, DNS rebinding, IPv4/IPv6 address classes;
- dependency inversion through `BrowserAdapter`;
- why feature flags default to off.

### By Review 2

- browser, context, and page lifecycle;
- why contexts isolate cookies but not the host network;
- request routing and why it must be context-wide;
- service-worker interception issues;
- DOM after JavaScript rendering versus raw HTML;
- why the engine observes but does not interact.

### By Review 3

- Alembic migrations and nullable rollout;
- dataclass-to-ORM mapping;
- typed API contracts;
- score fusion and graceful degradation;
- idempotency and time budgets;
- frontend polling and evidence visualization.

### By Review 4

- experimental design and honest metrics;
- threat-model assumptions and limitations;
- p50 versus p95 latency;
- unit, integration, and end-to-end test boundaries;
- what would change for production: durable queue, dedicated sandbox worker, network egress policy, observability, and scale testing.

## 17. Interview explanation template

Use this four-part answer:

1. **Problem:** “Our first version analyzed only URL text and VirusTotal reputation, so it could miss JavaScript-rendered login forms and runtime redirects.”
2. **Design:** “I added a policy-gated Playwright stage behind the static engine, with a browser-adapter boundary and pure explainable scoring.”
3. **Security/reliability:** “Every request and redirect is checked against public IP rules, contexts are ephemeral, downloads and interaction are disabled, work is time-budgeted, and failures preserve the static verdict.”
4. **Evidence:** “I evaluated it on a versioned controlled corpus and measured observation accuracy, blocked/timeout rates, and p50/p95 latency.”

Be ready to explain why `max(static, VT, dynamic)` was chosen for the MVP, why a background task is not a durable queue, and why Playwright context isolation is not the same as a malware sandbox.

## 18. Resume bullet template

Do not fill in numbers until Week 7 measurements exist:

> Built a policy-gated dynamic URL analysis engine in FastAPI and Playwright that captured JavaScript-rendered login forms, cross-domain form actions, redirects, TLS failures, and download attempts; added SSRF controls, asynchronous scan execution, evidence persistence, React visualization, and **X** automated tests, achieving **Y%** expected-observation coverage on **N** controlled scenarios with **Z s** p95 analysis latency.

## 19. Definition of done

- Existing static behavior remains available and tested.
- Dynamic analysis is off by default and controlled by configuration.
- Policy and URL-safety modules have complete branch-focused unit tests.
- Eligible controlled URLs produce structured evidence and screenshots.
- Unsafe requests and redirects are blocked.
- Browser timeouts/crashes never erase the static verdict or strand a scan.
- Scan trigger returns 202 and the frontend polls to a terminal status.
- Dynamic evidence is migrated, persisted, typed, and displayed.
- At least 20 harmless behavioral scenarios are evaluated.
- Full test suite and fresh/existing database migration checks pass.
- Final documentation states containment limitations honestly.
- Demo, backup recording, teacher artifacts, interview answers, and measured resume bullet are complete.

## 20. Primary references

- Playwright Python browser contexts: https://playwright.dev/python/docs/api/class-browsercontext
- Playwright Python network interception: https://playwright.dev/python/docs/network
- Playwright Python browser lifecycle: https://playwright.dev/python/docs/api/class-browser
- Playwright Python screenshots: https://playwright.dev/python/docs/screenshots
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- Python `ipaddress`: https://docs.python.org/3/library/ipaddress.html
- FastAPI background tasks: https://fastapi.tiangolo.com/tutorial/background-tasks/
- SQLAlchemy session basics: https://docs.sqlalchemy.org/en/20/orm/session_basics.html
- Alembic tutorial: https://alembic.sqlalchemy.org/en/latest/tutorial.html
