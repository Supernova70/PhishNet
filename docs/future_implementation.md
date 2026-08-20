# Future Implementation Guide — Dynamic Analysis Without Redis

## Purpose

This document is the implementation and study plan for the remaining capstone work. It intentionally **does not use Redis, Celery, or a separate queue**. The goal is a small system whose code you can explain, test, and change confidently in an interview.

Implement the phases in order. Do not begin VM-based attachment detonation until the dynamic URL feature and offline attachment-event scorer are tested.

## Current Baseline

The static-analysis pipeline is already complete:

1. `app/services/scan_service.py` runs text, URL, and attachment engines, persists the per-URL rows, then creates a final verdict.
2. `app/engines/url_analyzer.py` extracts URLs, applies ten explainable heuristics, optionally checks VirusTotal, and returns the highest URL score.
3. `app/engines/attachment_analyzer.py` routes files to PE/PDF/Office/generic analyzers, applies YARA to every file, and returns the highest attachment score.
4. `app/models/url_result.py` and migration `alembic/versions/0002_add_url_results.py` already reserve most dynamic-URL columns: `dynamic_score`, `redirect_chain`, `dom_has_login_form`, `ssl_valid`, and `playwright_screenshot_path`.

### Deliberate Simplifications

- **No Redis:** VirusTotal calls are not cached between scans. This is acceptable for a capstone demo; respect the free-tier rate limit and use mock responses in tests.
- **No Celery:** keep the existing FastAPI background-task flow. Dynamic work runs only for a small number of ambiguous items and has strict timeouts.
- **No automatic malware execution in the main app:** the application only analyzes browser behaviour and later consumes sandbox evidence. It never executes attachments itself.

## Target Design

```text
Email -> existing static engines -> dynamic-policy decision
                                      |
                     +----------------+----------------+
                     |                                 |
              Dynamic URL (Playwright)       Dynamic attachment evidence
                     |                         (offline Sysmon fixtures first)
                     v                                 v
              persist per-URL evidence          persist per-file evidence
                     \                                 /
                      \---- final verdict + audit ----/
```

The important design principle is **policy before expensive work**. Static analysis decides whether dynamic analysis is justified; dynamic analysis enriches the evidence rather than replacing static analysis.

## Phase 0 — Prepare a Safe, Testable Foundation

### Learn first

- Python dataclasses, dependency injection, exceptions, and `pathlib`.
- SQLAlchemy models and Alembic migrations.
- `pytest`, fixtures, mocks, and `unittest.mock.patch`.

### Implement

1. Add configuration flags in `app/config.py`:
   - `DYNAMIC_URL_ENABLED: bool = False`
   - `DYNAMIC_ATTACHMENT_ENABLED: bool = False`
   - `DYNAMIC_URL_TIMEOUT_SECONDS: int = 15`
   - `DYNAMIC_URL_TOTAL_BUDGET_SECONDS: int = 25`
   - `DYNAMIC_SCREENSHOT_RETENTION_DAYS: int = 14`
2. Add one pure policy function per feature. A policy function accepts static evidence and returns only `True` or `False`; it must not use the network or database.
3. Make the default behaviour unchanged: if a flag is false, the current static pipeline produces the same result as today.

### Definition of done

- Existing tests still pass.
- Unit tests prove both disabled flags skip all dynamic code.
- Every external operation has a timeout and caught error path.

## Phase 1 — Dynamic URL Analysis MVP

### What it should do

For a URL whose existing static score is in the ambiguous range `30 <= score < 70`, or which is a shortener, open one isolated browser context and collect:

- ordered redirect chain;
- final URL;
- whether the final DOM contains a password field;
- whether a form posts to another registrable domain;
- whether the browser reported an HTTPS/certificate navigation error;
- an optional screenshot; and
- a structured error string if the visit could not finish.

Never dynamically visit a URL already marked malicious by VirusTotal. Do not click buttons, submit forms, accept dialogs, or download files.

### Files to add or change

| File | Responsibility |
|---|---|
| `app/engines/dynamic/__init__.py` | Dynamic-analysis package marker. |
| `app/engines/dynamic/dynamic_url_analyzer.py` | Dataclasses, policy, scoring, and orchestration. Keep scoring helpers pure. |
| `app/integrations/browser.py` | Small Playwright wrapper that creates and closes one browser/context/page per URL. |
| `app/config.py` | Feature flags, timeouts, and screenshot settings. |
| `app/engines/url_analyzer.py` | Calls the dynamic analyzer only after static/VT scoring and only when policy allows. |
| `app/services/scan_service.py` | Persists dynamic URL fields and exposes them in the verdict breakdown. |
| `app/models/url_result.py` | Add `dynamic_flags` and `dynamic_error` after the migration is created. |
| `alembic/versions/0003_url_dynamic_columns.py` | Adds nullable `dynamic_flags` JSON and `dynamic_error` string columns. |
| `tests/test_dynamic_url_analyzer.py` | Tests policy and scoring without a live browser. |

### Suggested contracts

```python
@dataclass
class DynamicUrlResult:
    visited: bool
    dynamic_score: float
    redirect_chain: list[str]
    final_url: str | None
    dom_has_login_form: bool
    ssl_valid: bool | None
    screenshot_path: str | None
    dynamic_flags: list[str]
    error: str | None
```

Keep `DynamicUrlResult` independent from SQLAlchemy. The engine returns this plain object; `ScanService` maps it into `UrlResult`. This separation makes tests simple and lets you explain the boundary clearly.

### Explainable scoring rubric

| Evidence | Points |
|---|---:|
| Redirect ends on a different registrable domain | 30 |
| Final page has a password input | 35 |
| Login form action posts to another registrable domain | 25 |
| Certificate/navigation error | 20 |
| Download was requested or attempted | 25 |

Cap the total at 100. The per-URL result becomes `max(static_final_score, dynamic_score)`. Store each matching rule in `dynamic_flags`; do not store only a number.

### Browser-safety requirements

1. Reuse the existing local-IP check concept, but strengthen it with Python's `ipaddress` module. Block loopback, private, link-local, multicast, unspecified, and reserved IP addresses, including IPv6.
2. Resolve HTTP redirects with a no-follow preflight and validate every `Location` before Chromium navigation. Then use Playwright context routing for browser/JavaScript requests. Routing alone does not reliably pause every HTTP 3xx hop.
3. Use a fresh browser context with no persisted cookies/storage, `accept_downloads=False`, JavaScript dialogs dismissed, one tab, and a fixed user agent.
4. Apply navigation and total budgets. On timeout or browser failure, return `DynamicUrlResult(visited=False, dynamic_score=0, error=...)`; never fail the whole scan.
5. Store screenshots below `uploads/screenshots/<scan_id>/` with a SHA-256-derived filename. Do not use a user-supplied filename in a path.

### Implementation order

1. Write tests for `should_run_dynamic_url(static_score, is_shortener, vt_malicious)`.
2. Write pure helpers for registrable-domain comparison, password-field detection, third-party form-action detection, and score calculation.
3. Add a fake browser adapter in tests that returns known redirect/DOM data.
4. Add the Playwright adapter only after the pure tests pass.
5. Add the migration, ORM fields, and `ScanService` persistence.
6. Update `frontend/src/types/index.ts`, `frontend/src/pages/UrlAnalysis.tsx`, and `frontend/src/pages/ScanDetail.tsx` to show the evidence.
7. Add screenshot cleanup as an explicit command or startup task. Do not delete files during a request.

### Demo scenario

Use locally controlled harmless pages: one redirect page, one page containing a dummy password form, and one clean page. Explain that production URLs are sensitive inputs and the browser rules prevent SSRF-style access to internal services.

## Phase 2 — Attachment Dynamic Analysis, Safe MVP

### Scope for the first deliverable

Do **not** start by detonating attachments. First build the evidence-processing half: parse saved Sysmon XML/JSON fixtures, normalize events, calculate an explainable score, and display the result. This is fully valuable, easy to test, and safe to demonstrate.

### Files to add

| File | Responsibility |
|---|---|
| `app/engines/dynamic/sysmon_parser.py` | Converts sample Sysmon XML/JSON into normalized dictionaries. |
| `app/engines/dynamic/behavior_scorer.py` | Pure event-to-flags-and-score rules. |
| `app/engines/dynamic/dynamic_attachment_analyzer.py` | Accepts normalized events and returns a result object; no VM calls in MVP. |
| `app/models/attachment_dynamic_result.py` | ORM model for dynamic attachment evidence. |
| `alembic/versions/0004_attachment_dynamic_results.py` | New evidence table and indexes. |
| `tests/fixtures/sysmon/` | Harmless, synthetic/captured event samples. |
| `tests/test_sysmon_parser.py` | Parser tests. |
| `tests/test_behavior_scorer.py` | Deterministic scoring tests. |

### Suggested contract

```python
@dataclass
class DynamicAttachmentResult:
    analyzed: bool
    dynamic_score: float
    behavior_flags: list[str]
    sysmon_events: list[dict]
    processes_created: list[str]
    network_connections: list[str]
    error: str | None
```

### Minimal scoring rubric

| Sysmon evidence | Points |
|---|---:|
| Office application launches a script shell | 35 |
| Process launches from a user-writable/temp directory | 15 |
| Network connection to a bare IP or unusual port | 25 |
| Startup-folder file creation | 30 |
| Run-key persistence event | 30 |
| High-entropy or suspicious DNS query | 15 |

Use event IDs such as 1 (process creation), 3 (network connection), 11 (file creation), 12/13 (registry), and 22 (DNS). Cap at 100 and store all evidence that contributed to the score.

### Trigger and merge policy

- Eligible types: PE (`.exe`, `.dll`, etc.) and macro-bearing Office documents.
- Trigger only if static score is `30 <= score < 70`, or YARA matched without a clearly dangerous static verdict.
- Do not analyze the same SHA-256 more than once per scan. Later, the evidence table can also support a simple PostgreSQL lookup by SHA-256; Redis is unnecessary.
- When dynamic evidence exists, calculate per-file risk as `0.4 * static_score + 0.6 * dynamic_score`. Otherwise retain the static score.
- If dynamic analysis is unavailable for an ambiguous eligible file, keep the static score but include `dynamic_error` in the breakdown and classify ambiguity conservatively as suspicious.

### Definition of done

- The parser handles missing fields and unknown event IDs without raising.
- Scoring is deterministic and has unit tests for every rule and score cap.
- The frontend can show a textual process/network/flag summary.
- All fixtures are harmless. Use EICAR or synthetic events for demonstrations; do not download or execute real malware.

## Phase 3 — Optional Isolated Sandbox Integration

Only attempt this phase after Phases 1 and 2 are complete and reviewed by your supervisor.

### Safe architecture

1. A separate sandbox controller runs outside the main app and exposes a tiny authenticated job API.
2. The main app submits a file reference/hash and polls for **evidence only**. It never runs a received file.
3. A disposable Windows VM with Sysmon starts from a clean snapshot for each job, has no route to the project database, private network, or home/college LAN, and is reverted after collection.
4. Begin with a manual workflow: collect Sysmon logs from a benign test program, place them in `tests/fixtures/sysmon/`, and feed them through Phase 2. Automate only after this works.

For the final report, document isolation, authorization, timeout, snapshot ID, submitted hash, event collection time, and failure behaviour. A small, well-tested offline MVP is better than a fragile live detonation feature.

## Phase 4 — UI, API, Documentation, and Final Validation

1. Extend API response schemas only with evidence already persisted in the database.
2. In URL views, show static score, dynamic score, redirect chain, login-form flag, SSL state, screenshot, and error state.
3. In attachment views, show static score, dynamic score, flags, processes, and network connections.
4. Add an architecture diagram showing static policy -> dynamic evidence -> persistence -> verdict.
5. Run focused tests first, then the complete suite. Verify migrations against a fresh local database.

## No-Redis Alternatives

Do not add infrastructure merely to cache data. Use these options in order:

1. **No cache (recommended now):** easiest to understand; enable VT only for controlled demos.
2. **PostgreSQL evidence reuse (later):** query the existing/added evidence by normalized URL or SHA-256 with an expiry timestamp. It is auditable and uses a database you already operate.
3. **In-process short-lived cache (optional):** a small bounded dictionary with TTL for one API process only. Do not rely on it for correctness and do not describe it as distributed caching.

Redis becomes worthwhile only when you intentionally need multiple workers, cross-process task queues, or high-volume caching. Those are not necessary to meet this capstone's learning goals.

## Study Plan and Primary Material

Study each item immediately before its phase, then explain it aloud using your own code.

| Topic | Why it matters here | Material |
|---|---|---|
| Playwright Python setup and isolation | Browser lifecycle and isolated contexts | [Playwright Python installation](https://playwright.dev/python/docs/intro) |
| Browser network interception | Observe, route, and abort unsafe requests | [Playwright network guide](https://playwright.dev/python/docs/network) |
| SSRF | Why URL analysis must block internal/private destinations | [OWASP SSRF overview](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery) |
| Address classification | Correct IPv4/IPv6 private-address checks | [Python `ipaddress` documentation](https://docs.python.org/3/library/ipaddress.html) |
| Database migrations | Additive, reproducible schema changes | [Alembic tutorial](https://alembic.sqlalchemy.org/en/latest/tutorial.html) |
| Sysmon | Meaning of process, network, file, registry, and DNS telemetry | [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| ATT&CK concepts | Map behavior flags to understandable attacker techniques | [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/) |
| Secure file handling | Existing attachment storage and safe paths | [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) |

### Viva/interview questions to prepare

1. Why does dynamic URL analysis run only after static scoring?
2. What is SSRF, and why must redirects be validated too?
3. Why are browser contexts ephemeral and downloads disabled?
4. Why is a score alone insufficient without flags and persisted evidence?
5. Why is offline Sysmon-event scoring the first attachment MVP?
6. Why does the main application never execute an attachment?
7. Why did you choose PostgreSQL/no cache instead of Redis?
8. How do feature flags, timeouts, and error handling keep demos reliable?
9. Why are migrations additive and nullable for new dynamic evidence?
10. How do your unit tests avoid requiring a live browser, VirusTotal, or VM?

## Completion Checklist

- [ ] Phase 0 flags and policy tests complete.
- [ ] Dynamic URL analyzer works with fake browser data and real harmless local pages.
- [ ] `0003` migration, ORM persistence, API breakdown, and UI display complete.
- [ ] Sysmon parser and behavior scorer work against safe fixtures.
- [ ] `0004` migration and attachment dynamic-result UI complete.
- [ ] Optional sandbox is isolated and supervisor-approved, or its scope is explicitly recorded as future work.
- [ ] Full test suite passes and documentation/screenshots support the final presentation.
