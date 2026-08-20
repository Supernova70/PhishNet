# Phishing Guard V2 — Implementation Status & Roadmap

> **Purpose**: Single source of truth for *what is done*, *what is left*, and *exactly how we will build the rest*. This is a college major project, so the design prioritises **robustness** (isolation, timeouts, idempotency, auditability) over fancy features.
> **Last updated**: 2026-07-10
> **Owner**: Project team

---

## Table of Contents

1. [How to Navigate This Codebase (graphify map)](#1-how-to-navigate-this-codebase-graphify-map)
2. [What Is Implemented](#2-what-is-implemented)
3. [What Is Remaining (Gaps)](#3-what-is-remaining-gaps)
4. [How We Will Implement the Remaining Parts](#4-how-we-will-implement-the-remaining-parts)
   - 4.1 [Quick Win — Redis caching for VirusTotal](#41-quick-win--redis-caching-for-virustotal)
   - 4.2 [Quick Win — Enable + harden VT hash lookup for attachments](#42-quick-win--enable--harden-vt-hash-lookup-for-attachments)
   - 4.3 [Async Scan Worker (Celery + Redis)](#43-async-scan-worker-celery--redis)
   - 4.4 [Dynamic URL Analysis (Playwright)](#44-dynamic-url-analysis-playwright)
   - 4.5 [Dynamic Attachment Analysis (Sysmon Sandbox)](#45-dynamic-attachment-analysis-sysmon-sandbox)
   - 4.6 [Auth & Security Hardening](#46-auth--security-hardening)
   - 4.7 [Testing, Observability & Dashboard](#47-testing-observability--dashboard)
5. [Data Model & Migration Plan](#5-data-model--migration-plan)
6. [Semester 2 Timeline](#6-semester-2-timeline)
7. [Robustness Checklist (applies to every new component)](#7-robustness-checklist-applies-to-every-new-component)

---

## 1. How to Navigate This Codebase (graphify map)

The project is mapped with **graphify**. The interactive map lives in:

```
graphify-out/
├── graph.html          ← open this in a browser to navigate the whole codebase visually
├── GRAPH_REPORT.md     ← audit report: communities, god nodes, surprising connections
└── graph.json           ← raw graph (queryable)
```

**Current state (2026-07-10 refresh):** 654 nodes · 1,116 edges · 66 communities. Ghost nodes from the deleted `REMAINING_IMPLEMENTATION_GUIDE.md` were pruned and the graph + HTML were rebuilt so navigation is accurate.

### Top "god nodes" (core abstractions — start reading here)

| Node | Edges | What it is | File |
|------|-------|------------|------|
| `FileAnalysisResult` | 41 | Standardised per-file result dataclass | `app/engines/analyzers/base.py` |
| `AttachmentAnalyzer` | 34 | File-engine orchestrator | `app/engines/attachment_analyzer.py` |
| `UrlAnalyzer` | 22 | URL heuristics + VT | `app/engines/url_analyzer.py` |
| `EmailService` | 19 | IMAP fetch + parse + store | `app/services/email_service.py` |
| `ScanService` | 19 | Pipeline orchestrator | `app/services/scan_service.py` |
| `get_settings()` | 18 | Config singleton | `app/config.py` |
| `Base` | 18 | SQLAlchemy declarative base | `app/models/__init__.py` |

### Navigation shortcuts (the big communities)

- **Engines (the heart):** Scan Detail & URL Analysis UI, URL Analysis Engine, Text Analysis Engine, File Analysis Engines, Office & PDF Analyzers, YARA Scanner
- **Pipeline/DB:** Database Migrations & Scan API, Core Infrastructure, Email API Endpoints
- **Frontend:** Frontend App Entry, Dashboard & Email Pages, Scan Results Page, Data Visualization Charts

> **Keeping the map fresh:** After adding files, run `/graphify --update` here. It only re-extracts new/changed files and merges into the existing graph (cheap). A full rebuild (`/graphify .`) is only needed if a lot of structure changes.

---

## 2. What Is Implemented

Legend: ✅ done & wired · 🟡 code exists but disabled / stubbed · ❌ not started

### 2.1 Core infrastructure

| Component | Status | Notes |
|-----------|--------|-------|
| FastAPI app factory + lifespan | ✅ | `app/main.py` |
| Centralised Pydantic Settings | ✅ | `app/config.py` — all env vars via `get_settings()` |
| SQLAlchemy 2.0 ORM models | ✅ | `app/models/` — Email, Attachment, Scan, Verdict, UrlResult, FetchState |
| Alembic migrations (idempotent) | ✅ | `0001_initial_schema.py`, `0002_add_url_results.py` |
| PostgreSQL via docker-compose | ✅ | `postgres:16-alpine`, host port 5433 |
| Dependency injection (get_db) | ✅ | `app/dependencies.py` |
| REST API (emails, scans, health) | ✅ | `app/api/` with Swagger at `/docs` |
| BackgroundTask-based async scan | ✅ | Returns 202 immediately, runs in BackgroundTask (own DB session) |
| Docker image | ✅ | `Dockerfile` installs `libmagic1` + `file` |

### 2.2 Engine 1 — AI Text Analysis (static)

| Subsystem | Status | Notes |
|-----------|--------|-------|
| sklearn pipeline (TF-IDF + LogisticRegression) | ✅ | `app/engines/text_analyzer.py` |
| Trained model + joblib serialisation | ✅ | `data/phishing_model.joblib`; `train_model.py` |
| `@lru_cache` singleton | ✅ | `get_text_analyzer()` |
| HTML fallback to text | ✅ | Falls back to `body_html` if no plain text |
| Confidence → ai_score (0–100) | ✅ | `confidence` from `predict_proba` |

### 2.3 Engine 2 — URL Analysis (static + VT)

| Subsystem | Status | Notes |
|-----------|--------|-------|
| URL extraction (text regex + BeautifulSoup) | ✅ | `_extract_and_deduplicate()` |
| Normalisation (strip utm/fbclid/gclid/ref/mc_) | ✅ | `_normalize()` |
| Local-IP filtering | ✅ | `_is_local_ip()` |
| 10 static heuristic checks | ✅ | `_score_heuristic()` — HTTP, IP host, TLD, shortener, brand impersonation, subdomains, long URL, entropy, `@`, redirect |
| VirusTotal URL v3 lookup + round-robin keys | ✅ | `_check_virustotal()` (only if keys set) |
| Per-URL DB rows (`url_results`) | ✅ | written by `ScanService` |
| **Dynamic analysis (Playwright, Weeks 1–4 MVP)** | ✅ | Policy gate, SSRF validation, redirect preflight, isolated Chromium observation, DOM/TLS/download/popup evidence, screenshots, scoring, and static fallback implemented; richer UI/persistence fields remain Weeks 5–6 |
| VT result caching | ❌ | Redis removed intentionally |

### 2.4 Engine 3 — Attachment Analysis (static + YARA)

| Subsystem | Status | Notes |
|-----------|--------|-------|
| Orchestrator + file-type routing | ✅ | `app/engines/attachment_analyzer.py` |
| MIME detection (python-magic) + mismatch scoring | ✅ | `_detect_mime()`, +20 on mismatch |
| PE/EXE static analysis (pefile) | ✅ | `analyzers/pe_analyzer.py` |
| PDF static analysis (PyPDF2) | ✅ | `analyzers/pdf_analyzer.py` |
| Office OLE + OOXML analysis (olefile, zipfile) | ✅ | `analyzers/office_analyzer.py` |
| Generic fallback analyzer | ✅ | `analyzers/generic_analyzer.py` |
| YARA scanner (rules cached/compiled) | ✅ | `analyzers/yara_scanner.py` + 5 rule files (800 lines) |
| Worst-file-dominates aggregation | ✅ | `max(per-file scores)` |
| Size limit + path safety | ✅ | `MAX_ATTACHMENT_BYTES`, `os.path.isfile` checks |
| VT file hash lookup code | 🟡 | `_vt_hash_lookup()` fully written; disabled by `ENABLE_VT_HASH_LOOKUP=False` |
| **Dynamic analysis (Sysmon sandbox)** | ❌ | Not started |

### 2.5 Cross-cutting

| Component | Status | Notes |
|-----------|--------|-------|
| Probabilistic final score `1-(1-p_ai)(1-p_url)(1-p_att)` | ✅ | `ScanService._compute_final_score()` |
| Classification thresholds | ✅ | safe<30, suspicious 30–70, dangerous≥70 |
| Full breakdown JSON stored in Verdict | ✅ | ai/url/attachment sub-objects |
| React + Vite + TS + Tailwind frontend | ✅ | `frontend/` — Dashboard, EmailInbox, ScanDetail, ScanResults, UrlAnalysis, ActiveScans, Health |
| ActiveScans live polling | ✅ | `usePollScan` |
| Charts (classification donut, threat timeline) | ✅ | `components/charts/` |
| API key auth middleware | 🟡 | `app/middleware/auth.py` exists, **not mounted** |
| Redis / caching | ❌ | `app/cache.py` is a stub returning None |
| Celery async queue | ❌ | FastAPI BackgroundTasks + HTTP 202 polling are implemented; a durable Celery/Redis queue remains future production work |
| Notifications / webhooks | ❌ | |
| Sysmon dynamic analysis | ❌ | |

---

## 3. What Is Remaining (Gaps)

Ordered by **value/effort ratio** for a college major project.

| # | Gap | Engine | Effort | Why it matters |
|---|-----|--------|--------|----------------|
| G1 | VT response caching (Redis) | URL + Attachment | Low | Frees VT quota (free tier = 4 req/min); fixes biggest production blocker |
| G2 | Flip `ENABLE_VT_HASH_LOOKUP=True` + rotation/hardening | Attachment | Low | Code already written; just disabled for safety. Unlocks file reputation |
| G3 | Async scan worker (Celery + Redis) | Pipeline | Medium | Playwright + Sysmon are slow; BackgroundTask blocks the worker. Needed before G4/G5 |
| G4 | **Dynamic URL analysis (Playwright)** | URL | Medium | Catches JS-rendered phishing forms, redirect chains, expired SSL — static heuristics miss these |
| G5 | **Dynamic attachment analysis (Sysmon sandbox)** | Attachment | High | Signature of this project. Catches zero-day / behaviour-based malware that static + YARA miss |
| G6 | Enable + mount API-key auth | API | Low | Presently every endpoint is open |
| G7 | Tests + coverage + dashboards | All | Medium | Required for a defensible major project |
| G8 | Robustness hardening (timeouts, idempotency, audit) | All | Medium | Makes the system defensible in a viva |

---

## 4. How We Will Implement the Remaining Parts

Each subsection gives: **goal → files to create/edit → contract → robustness notes.** We keep the design simple and individually testable; nothing fancy.

### 4.1 Quick Win — Redis caching for VirusTotal

**Goal:** Avoid re-hitting VT for the same URL/hash within a TTL; respect the 4 req/min free tier.

**Files**
- Edit `app/config.py`: add `REDIS_URL: str = "redis://redis:6379/0"` and `VT_CACHE_TTL_SECONDS: int = 86400`.
- Edit `app/cache.py`: replace the stub with a small `VTCache` wrapper (get/set with TTL, JSON serialise). Gracefully degrade to no-op if Redis is down (never block a scan on cache).
- Edit `app/engines/url_analyzer.py::_check_virustotal`: look up cache by `normalized_url`-based key before HTTP; store on success.
- Edit `app/engines/attachment_analyzer.py::_vt_hash_lookup`: same pattern keyed by `sha256`.
- Edit `docker-compose.yml`: re-add the `redis:7-alpine` service.

**Contract**

```python
class VTCache:
    def __init__(self, redis_url: str | None, ttl: int): ...
    def get(self, kind: str, key: str) -> dict | None: ...   # returns stored stats or None
    def set(self, kind: str, key: str, value: dict) -> None: ...  # best-effort
```

Key format: `vt:{kind}:{sha256|url_hash}`. `kind ∈ {"url","file"}`.

**Robustness notes**
- Cache is a **read-through optimisation only**: on any Redis error, log + continue to live VT. Never raise from the cache layer.
- Store the *full* VT stats dict, not just the derived score, so re-scoring logic stays in code.
- Negative caching: cache 404 ("not analysed") responses with a short TTL (e.g. 1h) so we don't spam VT with resubmits.

---

### 4.2 Quick Win — Enable + harden VT hash lookup for attachments

**Goal:** Flip `ENABLE_VT_HASH_LOOKUP=True` and make the lookup safe.

**Files**
- Edit `app/config.py`: default to `True`; add `VT_HASH_LOOKUP_ENABLED` tumbling and `VT_FILE_TIMEOUT_SECONDS: int = 10`.
- Edit `app/engines/attachment_analyzer.py::_vt_hash_lookup`: add round-robin key rotation (currently uses key[0]); use the configured timeout; treat 429 as soft-degrade (return heuristic-only). Reuse the `VTCache` from 4.1.

**Robustness notes**
- A VT failure must **never lower** a file's score — only the heuristic/YARA result stands. VT is corroborating evidence.
- Cap total concurrent VT calls per scan via a simple semaphore (config `VT_MAX_CONCURRENT=4`) so one email with 20 attachments cannot burn the whole quota at once.

---

### 4.3 Async Scan Worker (Celery + Redis)

**Goal:** Move the heavy scan pipeline off the FastAPI request thread so slow dynamic steps (Playwright/Sysmon) never time out the API.

**Files**
- New `app/worker.py`: Celery app factory (`make_celery()`), config from `REDIS_URL`.
- Edit `app/config.py`: add Celery-ish knobs (`SCAN_TIMEOUT_SECONDS`, `DYNAMIC_URL_ENABLED`, `DYNAMIC_ATTACHMENT_ENABLED`).
- Edit `app/api/scan.py`: instead of `BackgroundTasks.add_task`, enqueue a Celery task `run_scan_task.delay(scan_id)`; return 202 with `scan_id` and a `task_id`.
- Edit `app/services/scan_service.py`: keep `_execute_pipeline` synchronous and engine-callable; the Celery task wraps it (opens its own DB session — same pattern as today).
- New `Dockerfile.worker` (or extra service in compose) running `celery -A app.worker worker --loglevel=info --concurrency=2`.
- Edit `docker-compose.yml`: add `worker` service reusing the app image.

**Contract**

```python
# app/worker.py
@celery.task(name="scan.run", bind=True, max_retries=2, default_retry_delay=10)
def run_scan_task(self, scan_id: int) -> dict:
    """Open DB session, run ScanService.run_scan_by_id, return {'scan_id','classification'}."""
```

**Robustness notes**
- **Idempotency:** Before running, check `scan.status`; if already `running`/`complete`, short-circuit. This makes retries safe.
- **Timeout:** Celery `time_limit`/`soft_time_limit` per task = `SCAN_TIMEOUT_SECONDS`; on SoftTimeLimitExceeded mark scan `error` and commit.
- **Result back-pressure:** Concurrency kept low (2) because Playwright/Sysmon are CPU/IO heavy. Scale workers horizontally, not concurrency.
- Keep the **synchronous BackgroundTask path** behind a config flag (`SCAN_MODE=sync|async`) so the system keeps working even if Redis is down (great for demos / viva).

> This is the prerequisite for G4 and G5. Build it first, then plug dynamic engines in as new pipeline steps gated by config flags.

---

### 4.4 Dynamic URL Analysis (Playwright)

**Goal:** For URLs that static heuristics rate as *suspicious* (not those already clearly malicious from VT), open the page in a headless browser and capture behaviour: redirect chain, final DOM login form, expired/invalid SSL, screenshot. Produce a `dynamic_score` (0–100) and fill the reserved `url_results` columns.

**Triggering policy (important — keeps it cheap and safe):** Only run dynamic analysis on URLs where `final_score ∈ [30, 70)` (ambiguous) **or** shortener-style URLs (which hide the destination). Never auto-visit a URL that VT already flags malicious (no need, and avoids loading malware pages).

**Files**
- New `app/engines/dynamic/dynamic_url_analyzer.py` — pure function `analyze_url_dynamic(url) -> DynamicUrlResult`.
- New `app/integrations/browser.py` — a thin Playwright wrapper with a strict context manager (browser/context/page created + closed per URL; never shared).
- Edit `app/engines/url_analyzer.py`: after static score, if policy triggers, call dynamic analyzer and merge `max(static, dynamic_score_eff)`.
- Edit `scan_service.py`: persist the new columns (`dynamic_score`, `redirect_chain`, `dom_has_login_form`, `ssl_valid`, `playwright_screenshot_path`).
- Edit `Dockerfile`: `pip install playwright` then `playwright install chromium --with-deps`.
- Add deps: `playwright>=1.40` to `pyproject.toml`.

**Contract**

```python
@dataclass
class DynamicUrlResult:
    visited: bool
    dynamic_score: float          # 0-100
    redirect_chain: list[str]    # ordered hops
    final_url: str | None
    dom_has_login_form: bool
    ssl_valid: bool
    screenshot_path: str | None
    error: str | None
```

**Scoring rubric (simple, explainable — good for a report):**

| Signal | Points |
|--------|--------|
| Redirect to a different registrable domain | +30 |
| Final page has a `<form>` with password field | +35 |
| SSL invalid/expired/self-signed | +20 |
| Form `action` posts to a third-party domain | +25 |
| Page tries to download a file (download event) | +25 |

Cap at 100. Store the breakdown in a new `dynamic_flags` JSON column on `url_results` (migration 0003, see §5).

**Robustness notes**
- **Isolation:** Each visit gets a fresh browser context, no cookies/localStorage persisted, `--no-sandbox` only inside container, disk wiped. One page, one origin.
- **Network jail (production grade):** Prefer routing Playwright through a proxy/SOCKS or a restricted network namespace so a malicious page can't reach internal hosts. For the college project, at minimum block private IP ranges via a request handler.
- **Time budget:** Hard navigation timeout 15s, total page budget 25s. If exceeded → `error="timeout"`, `dynamic_score` stays 0, scan proceeds.
- **Disk hygiene:** Screenshots saved under `uploads/screenshots/{scan_id}/{url_hash}.png`; auto-delete older than N days via a small cleanup task.
- **Never click "Download" or accept dialogs** — read-only inspection only. Set `accept_downloads=False`.
- **Fail-closed vs fail-open:** Playwright failure must NOT raise out of the scan; it sets `error` and returns score 0, so the static/VT score still stands.

---

### 4.5 Dynamic Attachment Analysis (Sysmon Sandbox)

> This is the **signature feature** of the major project: behaviour-based detection that static + YARA cannot do.

**Goal:** For **executable attachments** (PE/EXE/DLL, and Office docs with macros) that are *ambiguous after static* (score in 30–70) or have YARA matches without a clear verdict, detonate the file inside an isolated Windows VM that runs **Sysmon** + Windows Event Forwarding, collect the logs, parse them, and compute a `dynamic_score`. Combine with static: `final = static * 0.4 + dynamic * 0.6` when dynamic ran (matches the roadmap's Semester 2 policy).

**High-level architecture**

```
Phishing Guard (Linux container)
       │  submits file (sha256) + job_id
       ▼
Sandbox Controller (FastAPI micro-service on the VM host)
       │  copies file into VM via shared folder / Vagrant upload
       ▼
Windows VM (VirtualBox/Hyper-V, snapshot-based, isolated)
   ├─ Sysmon (config: process creation, network, file, registry)
   ├─ Winlogbeat / wevtutil export → forwards evtx/xml to controller
   └─ Auto-reverts to clean snapshot after each job
       │
       ▼
Behavior Analyzer (Python, in the main app)
   parses Sysmon events → IOC heuristics → dynamic_score
```

**Why a VM and not a Linux sandbox (Cuckoo/CAPE):** Sysmon is Windows-only, and the threat model is Windows malware delivered by email (PE + Office macros). A Windows VM running real Sysmon is the most authentic, defensible choice for a college project. We use **snapshot revert** so each detonation starts clean — no leftover state, reproducible.

**Files (new)**

```
app/engines/dynamic/
├── __init__.py
├── sandbox_controller.py    # talks to the VM host API; submit_job(sha256, path)
├── sysmon_parser.py         # parse Sysmon evtx/xml → normalized events
├── behavior_scorer.py       # events → IOC hits → dynamic_score (0-100)
└── dynamic_attachment_analyzer.py   # orchestrator: submit → wait → parse → score
app/integrations/
└── sandbox_client.py        # httpx client to sandbox controller (retry, timeout)
sandbox/                       # everything that runs on the VM host
├── vm_manager.py             # start VM, revert snapshot, copy file in, collect logs out
├── detonator.ps1             # PS script run inside VM: drop file, execute, wait, stop
├── sysmon-config.xml         # Sysmon rule set (event IDs 1,3,11,12,13,22, etc.)
└── collect_logs.ps1          # exports Sysmon evtx + converts to XML for shipping
```

**Contract**

```python
@dataclass
class DynamicAttachmentResult:
    detonated: bool
    dynamic_score: float           # 0-100
    behavior_flags: list[str]      # human-readable IOC descriptions
    sysmon_events: list[dict]      # normalized event subset (for breakdown JSON)
    processes_created: list[str]
    network_connections: list[str]
    error: str | None
```

**Behavior scoring rubric (transparent & report-friendly):**

| Sysmon Event ID | Behaviour | Points |
|-----------------|-----------|--------|
| 1 (ProcessCreate) | child of Office app spawns `powershell.exe`/`cmd.exe`/`wscript.exe` | +35 |
| 1 | process spawned from temp/user-writable dir | +15 |
| 3 (NetworkConnect) | outbound connection to non-standard / high-risk port or bare IP | +25 |
| 11 (FileCreate) | writes to Startup folder / Run registry equivalent | +30 |
| 12/13 (Registry) | persistance — Run key / Scheduled task / COM hijack | +30 |
| 22 (DNSEvent) | resolves newly-registered / high-entropy domain | +15 |
| any | process crashes / exits immediately after spawning child (packer) | +10 |

Cap at 100. Store flags + normalized events in `attachment_dynamic_results` (migration 0004, §5).

**Triggering policy (keeps it feasible):**
- Only for PE/EXE/DLL and macro-bearing Office docs.
- Only when static score ∈ [30, 70) **or** YARA matched but no clear verdict. Never detonate a file VT already flags malicious (waste of VM time + risk).
- One detonation per sha256 is cached (with lock) so the same malware emailed to 50 people is run once.

**Robustness notes (the most important section for the viva):**
- **Isolation is non-negotiable:** The VM must have no network route to the corporate/college LAN or to the app's DB. Use host-only or NAT with internet blocked except an allowlist (or fully airgapped + manual log retrieval).
- **Snapshot revert after every job** — guarantees clean state and prevents lateral movement from a persistent implant.
- **Wall-clock budget:** detonation timeout 60–120s; if no behaviour in that window, score 0 with `error="timeout"`.
- **Synchronous-safe submit, asynchronous wait:** The worker submits the job, polls the controller (or uses a webhook/callback) for completion; never blocks a worker thread on a blocking socket. Celery handles retries on controller outage.
- **No code execution on the app side** — the app only ships bytes; execution happens only inside the VM via the detonator script.
- **Audit trail:** every detonation records sha256, submit time, VM snapshot id used, collection time, and full event subset. This is your "evidence" for the report.
- **Fail-open for the pipeline, fail-closed for the verdict:** If the sandbox is down, `dynamic_score=0` and we mark the scan `suspicious` (not `safe`) with a `dynamic_error` so an ambiguous file is never auto-marked safe just because dynamic analysis failed.

**Minimal MVP fallback (if VM setup slips):** Start with `sysmon_parser.py` + `behavior_scorer.py` operating on **sample evtx files** you collect manually from a test VM. This lets you build + unit-test the scoring logic while the controller/VM wiring is still in progress — de-risks the timeline.

---

### 4.6 Auth & Security Hardening

**Goal:** Mount the existing API-key middleware and lock down destructive endpoints; cheap, improves defensibility.

**Files**
- Edit `app/main.py`: mount `ApiKeyMiddleware` behind `ENABLE_AUTH` config (default False in dev, True in prod).
- Edit `app/config.py`: add `ENABLE_AUTH: bool = False`, `VALID_API_KEYS` (already have `API_KEYS`).
- Edit `Dockerfile`: run as non-root user; pin base image digest.
- Add `requirements audit`: `pip-audit` step in CI or a script.

**Rules (simple, robust):**
- Public endpoints: `/health`, `/docs`, `/openapi.json`. Everything else requires `X-API-Key`.
- Rate-limit per key using Redis token bucket (reuse Redis from 4.1). 429 on exceed.

---

### 4.7 Testing, Observability & Dashboard

**Goal:** Make the project defensible: tests pass, you can see what's happening, the dashboard shows the new dynamic columns.

**Tests (target ≥70% on `app/`)**
- Mock VT (use `respx` or `httpx.MockTransport`) in `test_url_analyzer.py`, `test_attachment_analyzer.py`.
- Unit-test `behavior_scorer.py` and `dynamic_url_analyzer.py` against **captured sample event fixtures** so they run without a VM/browser.
- Add `tests/test_worker.py` with Celery `eager` mode (`task_always_eager=True`) to test the async path without a broker.
- Add an integration test: fetch → scan (mocked engines) → verdict row present.

**Observability**
- Structured logging already in place (`logging`); add a `scan_id`/`email_id` log filter for traceability.
- Add `GET /scans/{id}` field for `dynamic_*` and surface errors (`vt_error`, `dynamic_error`) in the breakdown.

**Frontend**
- `ScanDetail` / `UrlAnalysis`: show `redirect_chain`, `dom_has_login_form`, `ssl_valid`, screenshot thumbnail.
- New `AttachmentDynamicCard` showing behavior flags + Sysmon process tree (textual is fine).

---

## 5. Data Model & Migration Plan

New migrations only add nullable columns / new tables — safe, no data loss.

### Migration `0003_url_dynamic_columns.py`
Add to `url_results`:
- `dynamic_score Float nullable`
- `dynamic_flags JSON nullable`  ← new (rubric breakdown)
- (existing reserved columns `redirect_chain`, `dom_has_login_form`, `ssl_valid`, `playwright_screenshot_path` already present — just populate them)

> Note: `dynamic_flags` is the only truly new column; the rest were added nullable in `0002` already. Verify with `alembic inspect` before creating; skip if present (idempotent, matching house style).

### Migration `0004_attachment_dynamic_results.py`
New table `attachment_dynamic_results` (1 row per detonated attachment):

| Column | Type | Notes |
|--------|------|-------|
| `id` | SERIAL PK | |
| `scan_id` | INT FK scans.id, indexed | |
| `attachment_id` | INT FK attachments.id, indexed | |
| `sha256` | VARCHAR(64) indexed | dedup key (run once per hash) |
| `detonated` | BOOLEAN | |
| `dynamic_score` | FLOAT | 0–100 |
| `behavior_flags` | JSON | list of strings |
| `sysmon_events` | JSON | normalized subset |
| `processes_created` | JSON | list |
| `network_connections` | JSON | list |
| `error` | VARCHAR(256) | nullable |
| `vm_snapshot_id` | VARCHAR(128) | audit |
| `submitted_at` | TIMESTAMP | |
| `collected_at` | TIMESTAMP | |

Index `(sha256)` for dedup lookups; index `(scan_id)` for breakdown aggregation.

### Migration `0005_redis_cached_vt.py`
No schema change — cache lives in Redis. (Reserved number in case we add a `vt_cache_keys` audit table later.)

---

## 6. Semester 2 Timeline

| Week | Focus | Deliverable |
|------|-------|-------------|
| 1–2 | Redis cache (G1) + enable VT hash (G2) | VT quota relaxed in demo; attachment VT scores appear |
| 3–4 | Async worker Celery (G3) | `POST /scans` enqueues; long scans don't block API; sync fallback still works |
| 5–7 | Dynamic URL — Playwright (G4) | Suspicious URLs get redirect chain + screenshots; new columns populated |
| 8–11 | **Dynamic Attachment — Sysmon sandbox (G5)** | VM detonates ambiguous files; behavior_score computed |
| 12 | Auth + rate limit (G6) | Endpoints locked behind API key |
| 13–14 | Tests + observability + dashboard (G7) | ≥70% coverage; dashboard shows dynamic data |
| 15 | Robustness pass (G8) | Timeouts, idempotency, audit trail verified |
| 16 | Report, architecture diagrams, presentation | Final deliverables |

Dependence order: **G1 → G3 → (G4, G5 in parallel) → G6 → G7 → G8.** G2 can ship anytime after G1.

---

## 7. Robustness Checklist (applies to every new component)

Before merging any new engine/step, it must satisfy:

- [ ] **Never raises out of the scan pipeline** — all errors are caught and recorded in `*_error` fields; the scan completes.
- [ ] **Fail-open for the pipeline, fail-closed for the verdict** — a failed dynamic/VT step sets score 0 but bumps ambiguous verdicts toward `suspicious`, never toward `safe`.
- [ ] **Idempotent** — re-running a scan with the same inputs produces the same result; no duplicate rows (dedup by message_id / sha256 / normalized_url).
- [ ] **Time-bounded** — every external call has a configurable timeout; scan has an overall soft time limit.
- [ ] **Resource-bounded** — concurrency caps, file size limits, disk cleanup; one misbehaving analysis can't OOM the worker.
- [ ] **Isolated** — sandbox/browser/VM have no route to internal services; contexts are ephemeral and reverted.
- [ ] **Config-gated** — every dynamic/heavy feature sits behind a config flag (`DYNAMIC_URL_ENABLED`, `DYNAMIC_ATTACHMENT_ENABLED`, `SCAN_MODE`) so the system stays demoable if an infra piece is down.
- [ ] **Auditable** — every dynamic result records what was run, when, where, on what snapshot, with the raw evidence retained.
- [ ] **Logged with trace IDs** — `scan_id`/`email_id` on every log line.
- [ ] **Tested with mocked/fixed external dependencies** — no test requires live VT, a browser, or a VM.

---

### Appendix — Where to start tomorrow

1. `graphify --update` to refresh the navigation map (see §1).
2. Re-add Redis to `docker-compose.yml` + implement `app/cache.py` (§4.1).
3. Flip `ENABLE_VT_HASH_LOOKUP` and add key rotation (§4.2).
4. Scaffold `app/worker.py` and move the scan off BackgroundTask behind `SCAN_MODE=async` (§4.3).
5. Then begin Playwright (§4.4) and the Sysmon sandbox MVP in parallel (§4.5).
