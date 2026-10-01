# Phishing Guard V2 — Complete Project Guide

This is the primary technical and operational handbook for Phishing Guard V2. Read it to understand the system, run it, change a feature, test it, explain it in an interview, and introduce CI/CD safely.

For the browser engine specifically, also read [`URL_ENGINE_WALKTHROUGH.md`](URL_ENGINE_WALKTHROUGH.md).

## 1. Project summary

Phishing Guard V2 is a full-stack email phishing analysis platform. It imports email from an IMAP mailbox, stores normalized email and attachment data, runs three independent analysis engines, combines their risk, and presents evidence through a REST API and React dashboard.

The three analysis dimensions are:

- **Text engine:** machine-learning probability from the email body.
- **URL engine:** static URL rules, optional VirusTotal reputation, and opt-in Playwright browser behavior.
- **Attachment engine:** file-type-specific static analysis, YARA, MIME mismatch checks, and optional VirusTotal hash reputation.

The project is a defensive-analysis capstone. It should not be marketed as a production malware sandbox or a replacement for an email security gateway.

## 2. Current functionality matrix

| Area | Status | What works today |
|---|---|---|
| IMAP import | Implemented | TLS IMAP login, UID-based incremental fetch, MIME parsing, deduplication |
| Email storage | Implemented | Headers, text/HTML body, attachment metadata and files |
| ML text analysis | Implemented | Joblib scikit-learn pipeline, phishing probability |
| Static URL analysis | Implemented | Extraction, normalization, ten explainable heuristics |
| URL reputation | Implemented/optional | VirusTotal URL API with key rotation and graceful fallback |
| Dynamic URL analysis | Week 4 MVP | Policy-gated Chromium, SSRF controls, redirect/DOM evidence, screenshot |
| Attachment analysis | Implemented | Generic, PE, PDF, Office, YARA, MIME and optional VT hash checks |
| Scan orchestration | Implemented | Pending/running/complete/error lifecycle and persisted verdict |
| Background execution | MVP | FastAPI in-process background task |
| Dashboard | Implemented | Email inbox, scans, details, URL evidence, health and charts |
| API documentation | Implemented | FastAPI Swagger at `/docs` |
| Database migrations | Implemented | Alembic revisions `0001` and `0002` |
| Redis/cache | Not active | `app/cache.py` is a compatibility stub |
| Durable worker queue | Planned | Celery/RQ/Arq plus Redis/RabbitMQ |
| Attachment page | Placeholder | Route exists but page is not implemented |
| Settings page | Placeholder | Route exists but page is not implemented |
| API-key enforcement | Incomplete | Middleware exists but is not registered in `create_app()` |
| CI/CD | Not committed yet | Ready-to-use design is included in this guide |

## 3. Technology stack

### Backend

- Python 3.11+; Docker currently uses Python 3.12.
- FastAPI and Uvicorn for HTTP APIs.
- Pydantic Settings for environment-based configuration.
- SQLAlchemy 2 ORM and Alembic migrations.
- PostgreSQL 16 in Docker Compose.
- HTTPX for VirusTotal and redirect preflight requests.
- IMAPClient and Python email libraries for mailbox ingestion.

### Analysis

- scikit-learn and Joblib for the email-text model.
- BeautifulSoup for HTML URL extraction.
- `tldextract` for public-suffix-aware registered domains.
- Playwright Python and Chromium for dynamic URL observation.
- `python-magic` for detected MIME type.
- `pefile`, PyPDF2, `olefile`, ZIP/XML inspection, and YARA for attachments.

### Frontend

- React 19 and TypeScript.
- Vite 8 build tooling.
- React Router 7.
- Axios for API calls.
- Recharts for charts.
- Tailwind/Vite integration plus application CSS.
- Framer Motion and Lucide icons.

### Infrastructure and quality

- Docker and Docker Compose.
- Pytest, pytest-asyncio, and pytest-cov.
- ESLint and TypeScript compiler.
- GitHub Actions design for CI/CD.

## 4. Architecture

```text
┌────────────────────────── React/Vite frontend ──────────────────────────┐
│ Dashboard | Email inbox | Active scans | Results | URL view | Health   │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │ Axios / JSON / polling
                                 v
┌──────────────────────────── FastAPI application ────────────────────────┐
│ /health | /emails/* | /scans/* | OpenAPI /docs                         │
└───────────────┬────────────────┬────────────────────┬───────────────────┘
                │                │                    │
                v                v                    v
          EmailService      ScanService          Health checks
                │                │
                │       ┌────────┼─────────┐
                │       v        v         v
                │   Text ML   URL engine  Attachment engine
                │               │              │
                │        static/VT/browser   format/YARA/VT
                │
                v
           IMAP mailbox

                     All application state
                              │
                              v
                    PostgreSQL + uploads volume
```

### Architectural principles

- API routes should validate requests and delegate work to services.
- Services own application workflows and database transactions.
- Engines return plain result objects and should remain independently testable.
- ORM models represent persistence; Pydantic schemas represent API contracts.
- Integrations isolate third-party or browser behavior.
- Safety checks are separate from risk scoring.
- Optional dependencies must fail gracefully without erasing other evidence.

## 5. Repository map

```text
app/
  api/                    FastAPI routes
  engines/
    analyzers/            Attachment format analyzers
    dynamic/              Dynamic URL policy, contracts, and scoring
    rules/                YARA rules
    attachment_analyzer.py
    text_analyzer.py
    url_analyzer.py
  integrations/           Playwright browser adapter
  middleware/             API-key middleware (not currently registered)
  models/                 SQLAlchemy models
  schemas/                Pydantic response contracts
  security/               URL/SSRF validation
  services/               Email and scan workflows
  config.py               Environment settings
  dependencies.py         DB engine/session dependency
  main.py                 Application factory

alembic/                  Database migrations
data/                     ML model and training artifacts
docs/                     Project and implementation documentation
frontend/                 React/Vite application
tests/                    Automated backend test suite
architecture/             Excalidraw architecture sources
Dockerfile                Backend/browser runtime image
docker-compose.yml        App and PostgreSQL development stack
pyproject.toml            Python package and dependencies
train_model.py            ML training entry point
```

## 6. Application startup

`app.main.create_app()` builds the FastAPI instance, configures CORS for local frontend origins, and includes the aggregate API router.

The lifespan hook logs startup and shutdown. It does not create tables. Schema changes are owned by Alembic.

The Docker Compose app command runs:

```text
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Host port `8080` maps to container port `8000`.

### CORS

Allowed development origins currently include:

```text
http://localhost:5173
http://127.0.0.1:5173
http://localhost:3000
```

For production, replace this fixed development list with an environment-controlled allowlist.

## 7. Configuration system

`app/config.py` defines one cached `Settings` instance. Values come from environment variables and `.env`.

Use `.env.example` as the template:

```powershell
Copy-Item .env.example .env
```

Never commit `.env`, mailbox passwords, API keys, production database URLs, or cloud credentials.

### Core variables

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | SQLAlchemy PostgreSQL connection string |
| `DEBUG` | SQL logging/debug behavior |
| `API_KEYS` | Intended comma-separated API keys |
| `EMAIL_HOST`, `EMAIL_PORT` | IMAP server |
| `EMAIL_ADDRESS`, `EMAIL_PASSWORD` | Mailbox credentials/app password |
| `MODEL_PATH` | Joblib model location |
| `ATTACHMENT_DIR` | Attachment and default screenshot storage root |
| `VIRUSTOTAL_API_KEYS` | Optional comma-separated VT keys |
| `MAX_ATTACHMENT_BYTES` | Maximum attachment size loaded into memory |
| `ENABLE_VT_HASH_LOOKUP` | Enables attachment hash reputation |
| `DYNAMIC_URL_*` | Browser policy, timeout, budget, and storage settings |

The supplied path values `/app/uploads` and `/app/data/phishing_model.joblib` are Docker-container paths. When running Uvicorn directly from this Windows repository, use workspace-relative values instead:

```env
ATTACHMENT_DIR=uploads
MODEL_PATH=data/phishing_model.joblib
DYNAMIC_URL_SCREENSHOT_DIR=uploads/url_screenshots
```

`MAX_ATTACHMENT_BYTES=52428800` means 50 MiB per file. `DYNAMIC_URL_TOTAL_TIMEOUT_SECONDS` limits one URL, while `DYNAMIC_URL_SCAN_BUDGET_SECONDS` limits all dynamically visited URLs in one email scan. `DYNAMIC_URL_SCREENSHOT_RETENTION_DAYS` expresses the intended retention period, but automatic cleanup is still a roadmap item.

After changing `.env`, restart the backend. `get_settings()` is cached with `lru_cache`.

### API-key limitation

`ApiKeyMiddleware` can validate `X-API-Key`, but `create_app()` does not currently call `app.add_middleware(ApiKeyMiddleware)`. Therefore setting `API_KEYS` alone does not enforce authentication. Register and test the middleware before claiming that the API is protected.

## 8. Database model

### `emails`

Stores Message-ID, sender, recipient, subject, original date string, plain/HTML bodies, flags, and fetch timestamp.

The RFC Message-ID is unique. If an email has no Message-ID, the service creates a deterministic hash-based fallback.

### `attachments`

Stores the original filename, declared content type, byte size, SHA-256, and server-side storage path. Deleting an email cascades to its attachments.

### `fetch_state`

Stores the highest processed IMAP UID per mailbox. This makes email fetching incremental and avoids relying on unstable IMAP sequence numbers.

### `scans`

Represents one analysis attempt and tracks:

```text
pending -> running -> complete
                   \-> error
```

It owns one verdict and many URL-result rows.

### `verdicts`

Stores individual engine scores, final score, classification, and a JSON evidence breakdown.

### `url_results`

Stores one row per unique normalized URL in a scan, including static, reputation, dynamic, and final scores plus core browser evidence.

### Relationships

```text
Email 1 ── * Attachment
Email 1 ── * Scan
Scan  1 ── 1 Verdict
Scan  1 ── * UrlResult
```

## 9. Alembic migration management

Current revisions:

- `0001_initial_schema.py`: email, attachment, scan, verdict, and fetch-state baseline.
- `0002_add_url_results.py`: per-URL results and reserved dynamic columns.

Common commands:

```powershell
alembic current
alembic history
alembic upgrade head
alembic downgrade -1
alembic revision --autogenerate -m "describe change"
```

Workflow for a schema change:

1. Change the SQLAlchemy model.
2. Generate a revision.
3. Inspect the generated upgrade and downgrade carefully.
4. Apply it to a fresh test database.
5. Apply it to a copy of an existing database.
6. Test both upgrade and rollback.
7. Commit model and migration together.

Do not use `Base.metadata.create_all()` as a replacement for migrations.

## 10. Email ingestion

`EmailService.fetch_and_store()` performs the following:

1. Connect to IMAP using TLS and UID mode.
2. Load `FetchState.last_uid` for `INBOX`.
3. Search only for newer UIDs.
4. Fetch up to the requested limit, newest first.
5. Parse MIME parts into text, HTML, and attachments.
6. Deduplicate using the RFC Message-ID.
7. Save attachment bytes beneath `{ATTACHMENT_DIR}/{email_id}/`.
8. Prefix sanitized filenames with eight SHA-256 characters.
9. Store metadata and update the highest UID.
10. Commit the transaction.

### Managing mailbox access

For Gmail, use a Google App Password rather than the normal account password. Keep the test mailbox separate from personal mail and fill it only with controlled samples.

To fetch:

```powershell
Invoke-RestMethod -Method Post 'http://127.0.0.1:8080/emails/fetch?limit=20'
```

Potential improvement: make mailbox name configurable instead of hardcoding `INBOX`.

## 11. Text-analysis engine

`TextAnalyzer` loads a Joblib scikit-learn pipeline once through a cached factory. The expected training design is TF-IDF features plus logistic regression.

Input selection:

```text
body_text, otherwise body_html, otherwise empty string
```

If `predict_proba` exists, class 1 probability becomes a 0–100 score. A score greater than 50 is labeled `Phishing`; otherwise `Legitimate`.

If the model is missing or cannot load, the engine returns score 0 and an explanatory label instead of stopping the full scan.

### Train and manage the model

```powershell
python -m pip install -e ".[ml]"
python train_model.py
```

Store the resulting model at the path configured by `MODEL_PATH`. Record dataset source, split method, metrics, scikit-learn version, and model hash. Loading a model created under a different scikit-learn version can generate compatibility warnings or fail.

## 12. URL-analysis engine

The URL engine:

1. extracts links from text and HTML;
2. normalizes and deduplicates them;
3. applies explainable static rules;
4. optionally queries VirusTotal;
5. optionally sends policy-selected URLs to Playwright;
6. stores evidence per URL;
7. uses the highest URL score as the engine score.

Dynamic analysis is disabled by default. Full algorithms, scoring tables, safety design, examples, and test strategy are in [`URL_ENGINE_WALKTHROUGH.md`](URL_ENGINE_WALKTHROUGH.md).

## 13. Attachment-analysis engine

`AttachmentAnalyzer` reads each stored attachment up to `MAX_ATTACHMENT_BYTES`, detects its MIME using file magic, and routes it by detected type with extension fallback.

### Format routing

| File family | Analyzer | Examples of evidence |
|---|---|---|
| PE executable | `pe_analyzer.py` | suspicious sections/imports, entropy, packer-like traits |
| PDF | `pdf_analyzer.py` | JavaScript, launch actions, embedded files, suspicious objects |
| Legacy Office OLE | `office_analyzer.py` | macros, suspicious streams and keywords |
| OOXML Office | `office_analyzer.py` | macro files, relationships, embedded objects |
| Other | `generic_analyzer.py` | entropy, magic bytes, double extensions, scripts, embedded executables |

Every file is also scanned by YARA when rules compile successfully. A declared/detected MIME mismatch adds risk. Optional VirusTotal file reputation uses SHA-256 and never uploads file contents.

Per-file score is the strongest applicable evidence after boosts. The attachment engine score is the maximum per-file score.

### Manage YARA rules

Rules live in `app/engines/rules/*.yar`.

When adding a rule:

1. Use a unique descriptive rule name.
2. Add severity and description metadata expected by the scanner.
3. Avoid extremely broad byte patterns.
4. Add both positive and negative fixture tests.
5. Run the attachment suite before committing.

```powershell
pytest -q tests/test_attachment_analyzer.py
```

## 14. Scan orchestration and scoring

`ScanService` is the central workflow:

```text
TextAnalyzer -> UrlAnalyzer -> AttachmentAnalyzer -> Verdict
```

The final score uses probabilistic risk accumulation:

```text
p_safe  = (1 - p_ai) * (1 - p_url) * (1 - p_attachment)
p_risk  = 1 - p_safe
score   = p_risk * 100
```

Example:

```text
AI = 40, URL = 70, Attachment = 10
p_safe = 0.60 * 0.30 * 0.90 = 0.162
final = (1 - 0.162) * 100 = 83.8
```

Classification thresholds:

| Score | Classification |
|---:|---|
| `0 <= score < 30` | safe |
| `30 <= score < 70` | suspicious |
| `70 <= score <= 100` | dangerous |

This formula assumes the three signals are sufficiently independent. That is an engineering simplification and should be validated on a labeled dataset.

## 15. Background scan lifecycle

`POST /scans/{email_id}` creates a pending row, schedules `_run_scan_task`, and returns HTTP 202. The task creates its own SQLAlchemy session, transitions the scan to running, executes all engines, and commits a complete or error state.

This avoids blocking the API request during browser/file analysis. It does not provide durable delivery, multi-process coordination, retries, or queue backpressure.

Recommended evolution:

```text
FastAPI -> durable queue -> isolated scan worker -> PostgreSQL
                         -> isolated browser worker
```

## 16. REST API

Interactive documentation:

```text
http://127.0.0.1:8080/docs
```

### Health

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Database, ML model, VirusTotal configuration and latency |

### Emails

| Method | Path | Purpose |
|---|---|---|
| POST | `/emails/fetch?limit=20` | Import new IMAP messages |
| GET | `/emails` | Filtered, paginated email list |
| GET | `/emails/{email_id}` | Full email and attachment detail |
| GET | `/emails/{email_id}/latest-scan` | Latest scan for an email |

Email list filters include sender, attachment presence, date range, scanned status, skip, and limit.

### Scans

| Method | Path | Purpose |
|---|---|---|
| POST | `/scans/{email_id}` | Queue a new scan; returns HTTP 202 |
| GET | `/scans` | Filter/paginate scans |
| GET | `/scans/{scan_id}` | Status, verdict, and evidence |

Scan filters include classification, score range, email ID, skip, and limit.

### Example flow

```powershell
$queued = Invoke-RestMethod -Method Post http://127.0.0.1:8080/scans/1
$scanId = $queued.scan_id
Invoke-RestMethod http://127.0.0.1:8080/scans/$scanId
```

## 17. Frontend functionality

| Route | Page | Functionality |
|---|---|---|
| `/` | Dashboard | KPI summaries, recent activity, classification and timeline charts |
| `/emails` | Email inbox | Import, search/filter, body/attachment view, start scan, poll result |
| `/active-scans` | Active scans | Periodic view of pending/running scans |
| `/scans` | Scan results | Classification/status/score filters |
| `/scans/:id` | Scan detail | Verdict and engine evidence, URL/attachment breakdown |
| `/url-analysis` | URL analysis | Aggregate URLs, risk filters, sorting and evidence expansion |
| `/system-health` | Health | Component status incl. VirusTotal key-pool rotation (`/health` is proxied to backend JSON for LB probes) |
| `/attachments` | Placeholder | Not implemented |
| `/settings` | Placeholder | Not implemented |

The API base URL is currently hardcoded as `http://127.0.0.1:8080`. A production build should use a Vite environment variable such as `VITE_API_BASE_URL`.

The scan polling hook requests status every two seconds for up to 180 seconds.

### Known frontend/backend mismatch

`useSystemHealth.ts` contains an older `redis`-shaped interface, while the backend health response now reports `virustotal`. The main health page uses the API response more directly, but the shared hook should be corrected before relying on it.

## 18. Local development

### Backend

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
python -m playwright install chromium
Copy-Item .env.example .env
alembic upgrade head
uvicorn app.main:app --reload --port 8080
```

For Windows MIME detection:

```powershell
python -m pip install -e ".[windows-dev]"
```

### Frontend

```powershell
Set-Location frontend
npm ci
npm run dev
```

### Docker

```powershell
docker compose up --build
docker compose ps
docker compose logs -f app
docker compose down
```

Use `docker compose down -v` only when you intentionally want to delete database and upload volumes.

## 19. How to manage each major feature

### Turn dynamic URL analysis on/off

```env
DYNAMIC_URL_ENABLED=true
```

Install Chromium, restart/rebuild, verify URL tests, and monitor screenshot storage. Set it back to `false` for an immediate application-level kill switch.

### Configure VirusTotal

```env
VIRUSTOTAL_API_KEYS=key_one,key_two
ENABLE_VT_HASH_LOOKUP=false
```

URL lookup uses the URL endpoint. Attachment lookup uses hashes only and must be enabled separately. Watch quota/rate-limit errors and never log keys.

### Change scan classification

Thresholds live in `ScanService._classify()`. Any change requires unit tests, documentation, and ideally evaluation against labeled data.

### Change final scoring

Update `_compute_final_score()` and `tests/test_scan_service.py`. Treat scoring as a versioned decision rule; changing it changes historical interpretation.

### Change URL rules

Add the flag and weight in `_score_heuristic()`, then add positive, negative, boundary, and score-cap tests. Keep the reason human-readable.

### Change dynamic scoring

Update only the pure function in `dynamic/scoring.py`, adjust unit tests, and document the rationale in the URL walkthrough.

### Add an attachment format

Create an analyzer returning `FileAnalysisResult`, add MIME/extension routing, add generated harmless fixtures, and test malformed input.

### Change database fields

Change ORM + migration + schema/API types + frontend types + tests together.

## 20. What the `tests/` folder is for

The test folder is executable proof that the implementation behaves as intended. It protects against regressions, makes refactoring safer, and documents edge cases better than prose alone.

### Current test responsibilities

| Test file | Responsibility |
|---|---|
| `test_ml_engine.py` | Model loading/prediction smoke behavior |
| `test_url_analyzer.py` | URL heuristics, VT responses, dynamic merge |
| `test_url_safety.py` | SSRF validation and normalization |
| `test_dynamic_url_policy.py` | Browser-selection decision matrix |
| `test_dynamic_url_scoring.py` | Browser evidence weights and domain handling |
| `test_dynamic_url_analyzer.py` | Dynamic orchestration with fake adapter |
| `test_playwright_redirect_safety.py` | Private redirect blocking |
| `test_playwright_browser_integration.py` | Real Chromium, redirect, JS DOM, screenshot |
| `test_attachment_analyzer.py` | Generic, PDF, PE, Office, MIME, aggregate behavior |
| `test_email_service.py` | UID fetch, Message-ID and filename safety |
| `test_scan_service.py` | Engine aggregation and verdict classification |
| `test_scan_background_task.py` | Session ownership, queued response, error lifecycle |

### Test pyramid for this project

```text
                    Few end-to-end tests
                 Browser/API integration tests
              Service and adapter contract tests
             Many fast deterministic unit tests
```

Most tests should not require internet, Gmail, VirusTotal, or live malicious infrastructure. Mock boundaries and use generated harmless fixtures.

### Commands

```powershell
pytest -q
pytest -q tests/test_url_safety.py
pytest -k dynamic -vv
pytest --maxfail=1 -x
pytest --cov=app --cov-report=term-missing --cov-report=html
```

Frontend quality gates currently include:

```powershell
Set-Location frontend
npm ci
npm run lint
npm run build
```

There is no frontend unit-test runner configured yet. A future step can add Vitest and React Testing Library.

Current baseline: `npm run build` succeeds, but `npm run lint` currently reports 16 errors and one warning in pre-existing frontend code. The main categories are explicit `any` types, React effect/state rules, one unused type/error variable, and one empty block. CI should expose this debt, but do not mark the lint job as a required branch check until those findings are fixed. Do not hide them permanently with `continue-on-error`.

## 21. Test environment design

### Local test environment

Use a separate test database and controlled mailbox. Do not run tests against production credentials.

Recommended `.env.test` concepts:

```env
DATABASE_URL=postgresql://phishing_test:phishing_test@localhost:5434/phishing_guard_test
MODEL_PATH=data/phishing_model.joblib
VIRUSTOTAL_API_KEYS=
EMAIL_ADDRESS=
EMAIL_PASSWORD=
DYNAMIC_URL_ENABLED=false
DYNAMIC_URL_SCREENSHOT_DIR=.test-artifacts/url-screenshots
```

External reputation and IMAP should be mocked in normal CI. Dynamic integration tests should use the harmless local server already included in the suite.

### Test data rules

- Generate small deterministic samples in tests.
- Do not commit real inbox messages containing personal information.
- Do not commit malware binaries.
- Do not browse known malicious URLs.
- Store any larger approved fixture by hash and document its provenance.
- Clean test databases and screenshots between isolated runs.

## 22. GitHub Actions CI implementation

Continuous Integration runs automated checks for every pull request and push. For this project, CI should answer four questions:

1. Does the backend install and pass all tests?
2. Does real Chromium integration still work?
3. Does the frontend lint and build?
4. Can the production Docker image build?

Create `.github/workflows/ci.yml` with the following starting point:

The workflow below intentionally runs `npm run lint`. On the current branch that step will fail until the documented frontend lint debt is resolved. A practical rollout is: first merge the workflow with `npm run build`, fix the lint baseline in a focused pull request, then add the lint command and make the job required.

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  backend-tests:
    name: Backend tests
    runs-on: ubuntu-latest
    timeout-minutes: 25

    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_USER: phishing_test
          POSTGRES_PASSWORD: phishing_test
          POSTGRES_DB: phishing_guard_test
        ports:
          - 5432:5432
        options: >-
          --health-cmd "pg_isready -U phishing_test -d phishing_guard_test"
          --health-interval 5s
          --health-timeout 5s
          --health-retries 10

    env:
      DATABASE_URL: postgresql://phishing_test:phishing_test@127.0.0.1:5432/phishing_guard_test
      MODEL_PATH: data/phishing_model.joblib
      VIRUSTOTAL_API_KEYS: ""
      EMAIL_ADDRESS: ""
      EMAIL_PASSWORD: ""
      DYNAMIC_URL_ENABLED: "false"
      DYNAMIC_URL_SCREENSHOT_DIR: ${{ runner.temp }}/url-screenshots

    steps:
      - name: Checkout
        uses: actions/checkout@v6

      - name: Set up Python
        uses: actions/setup-python@v6
        with:
          python-version: "3.12"
          cache: pip
          cache-dependency-path: pyproject.toml

      - name: Install system and Python dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y libmagic1 file
          python -m pip install --upgrade pip
          python -m pip install -e .

      - name: Install Chromium
        run: python -m playwright install --with-deps chromium

      - name: Apply migrations
        run: alembic upgrade head

      - name: Run backend tests with coverage
        run: |
          mkdir -p test-results
          pytest -q \
            --cov=app \
            --cov-report=term-missing \
            --cov-report=xml \
            --junitxml=test-results/pytest.xml

      - name: Upload backend test artifacts
        if: ${{ !cancelled() }}
        uses: actions/upload-artifact@v5
        with:
          name: backend-test-results
          path: |
            coverage.xml
            test-results/
            ${{ runner.temp }}/url-screenshots/
          if-no-files-found: ignore
          retention-days: 14

  frontend-build:
    name: Frontend lint and build
    runs-on: ubuntu-latest
    timeout-minutes: 15
    defaults:
      run:
        working-directory: frontend

    steps:
      - name: Checkout
        uses: actions/checkout@v6

      - name: Set up Node
        uses: actions/setup-node@v6
        with:
          node-version: "22"
          cache: npm
          cache-dependency-path: frontend/package-lock.json

      - run: npm ci
      - run: npm run lint
      - run: npm run build

      - name: Upload frontend build
        uses: actions/upload-artifact@v5
        with:
          name: frontend-dist
          path: frontend/dist
          retention-days: 7

  docker-build:
    name: Docker build
    runs-on: ubuntu-latest
    timeout-minutes: 30

    steps:
      - uses: actions/checkout@v6
      - name: Build image
        run: docker build --tag phishing-guard:${{ github.sha }} .
```

### Why these jobs are separate

- A frontend failure does not hide backend diagnostics.
- Job names become clear required status checks.
- Docker validates packaging independently from the editable Python install.
- Browser screenshots and coverage survive as downloadable artifacts.

### GitHub repository setup

1. Push the workflow on a feature branch.
2. Open a pull request and let every job run.
3. Fix any environment-only failures.
4. Go to **Settings → Branches → Add branch protection rule**.
5. Protect `main`.
6. Require pull requests and the three CI jobs to pass.
7. Disable force pushes and branch deletion.
8. Optionally require one review.

Do not place Gmail or VirusTotal secrets in normal pull-request CI. Forked pull requests intentionally do not receive repository secrets.

## 23. CI test layering and optimization

If installation time becomes high, split the backend into two jobs:

### Fast unit job

```powershell
pytest -q --ignore=tests/test_playwright_browser_integration.py
```

### Browser integration job

```powershell
python -m playwright install --with-deps chromium
pytest -q tests/test_playwright_browser_integration.py tests/test_playwright_redirect_safety.py
```

Run the fast job on every commit and the browser job on every pull request/main push. Do not cache Playwright browsers by default; browser binaries and Linux dependencies change with Playwright versions and the official guidance recommends installing them in CI.

Add a coverage threshold only after measuring the baseline:

```powershell
pytest --cov=app --cov-fail-under=75
```

Increase gradually. A high percentage is not a substitute for meaningful assertions and boundary cases.

## 24. Continuous Delivery and Deployment

CI verifies the code. CD packages or deploys only code that passed CI.

For this project, a safe first CD milestone is to publish the backend image to GitHub Container Registry (GHCR) on version tags. It should not automatically connect to a production mailbox.

Create `.github/workflows/publish-image.yml`:

```yaml
name: Publish container

on:
  push:
    tags: ["v*"]
  workflow_dispatch:

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  publish:
    name: Publish backend image
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write

    steps:
      - uses: actions/checkout@v6

      - name: Log in to GHCR
        uses: docker/login-action@v4
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Generate tags and labels
        id: meta
        uses: docker/metadata-action@v6
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=tag
            type=sha

      - name: Build and push
        uses: docker/build-push-action@v7
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
```

For stronger supply-chain security, pin third-party actions to reviewed commit SHAs rather than floating version tags.

### Actual deployment options

- **Simple demo:** a single VM running Docker Compose behind HTTPS.
- **Managed container:** Render, Railway, Fly.io, Azure Container Apps, AWS ECS, or Google Cloud Run, subject to Playwright/runtime constraints.
- **Production direction:** API container, managed PostgreSQL, durable queue, separate restricted browser workers, object storage, monitoring, and secrets manager.

### Production deployment sequence

```text
Pull request -> CI -> review -> merge -> version tag
-> build immutable image -> push GHCR -> staging migration
-> staging smoke test -> manual production approval
-> production migration -> rolling deployment -> health check
```

Use a GitHub `production` environment with required reviewers, branch/tag restrictions, and environment-scoped secrets. Use deployment concurrency so two production releases cannot run simultaneously.

## 25. Secrets and security in GitHub

Use **Settings → Secrets and variables → Actions** for CI/CD credentials.

Possible deployment-only secrets:

```text
PRODUCTION_DATABASE_URL
DEPLOY_HOST
DEPLOY_USER
DEPLOY_SSH_KEY
```

Mailbox and VirusTotal secrets should be added only if a controlled staging smoke test genuinely needs them. Prefer service accounts and least privilege.

Security rules:

- Set workflow `permissions` to read-only by default.
- Grant `packages: write` only to the publishing job.
- Never run untrusted pull-request code with production secrets.
- Do not print environment variables.
- Protect deployment environments with approval.
- Pin third-party actions to commit SHAs for a hardened workflow.
- Use Dependabot for Python, npm, Docker, and GitHub Actions updates.

## 26. Monitoring and operations

### Health endpoint

`GET /health` checks:

- PostgreSQL connectivity;
- existence of the ML model file;
- number of configured VirusTotal keys;
- response latency.

The overall state becomes `degraded` for database or model failure. VirusTotal is optional and does not degrade health when missing.

### Logs to watch

- email login/fetch/parse failures;
- duplicate or UID-state behavior;
- model loading errors;
- VirusTotal 429 responses;
- browser startup, navigation timeout, unsafe-target, and crash errors;
- scan error transitions;
- YARA compilation failures;
- database connection pool failures.

### Operational metrics to add

- scans queued/running/completed/failed;
- scan duration by engine;
- dynamic-policy decisions by reason;
- browser timeout/crash rate;
- URL and attachment score distributions;
- VirusTotal quota/rate limiting;
- screenshot storage volume;
- queue depth when a durable worker is introduced.

## 27. Troubleshooting

### Backend cannot connect to PostgreSQL

- In Docker, the host in `DATABASE_URL` must be `postgres`.
- From the host, use `localhost:5433` with the current Compose mapping.
- Check `docker compose ps` and database logs.

### Chromium is unavailable

```powershell
python -m playwright install chromium
```

On Linux CI/container:

```bash
python -m playwright install --with-deps chromium
```

### ML model reports not loaded

Check `MODEL_PATH`, file existence, permissions, and scikit-learn version compatibility.

### IMAP login fails

Use an app password, confirm IMAP access, and verify host/port/account. Do not expose the password in logs.

### VirusTotal always skipped

Check that `VIRUSTOTAL_API_KEYS` is present in the process environment and restart the app. A blank key list intentionally enables heuristic-only mode.

### Frontend says backend offline

Check `http://127.0.0.1:8080/health`, CORS origins, and the hardcoded frontend base URL.

### Existing database conflicts with migration

Inspect `alembic current` and `alembic history`. Do not delete the volume reflexively. Back up first, then stamp only when you have verified that the schema matches the revision.

## 28. Known limitations and technical debt

- Browser execution is not protected by a complete network sandbox.
- Background scans are not durable.
- Redis/cache is not implemented.
- API-key middleware is not registered.
- Frontend API origin defaults to the local backend and should become environment-configurable before deployment.
- Screenshot retention cleanup is not implemented.
- Dynamic browser concurrency is not globally limited.
- Some dynamic fields are stored only in verdict JSON.
- VirusTotal URL calls have no cache and simple rate-limit handling.
- HTML text analysis does not explicitly sanitize/strip markup before ML inference when no plain text exists.
- No frontend unit test framework is configured.
- No CI/CD workflows are currently committed.
- Attachment and settings frontend pages are placeholders.
- Scoring thresholds need dataset-based calibration.

## 29. Recommended implementation roadmap

### Immediate

1. Add the CI workflow from this guide.
2. Make the frontend API base URL environment-configurable.
3. Register and test API-key middleware, or remove the unused setting until ready.
4. Add screenshot cleanup and browser concurrency control.

### Weeks 5–6 dynamic URL work

1. Add typed database fields/migration for remaining dynamic evidence.
2. Add authentication and automatic retention cleanup to the screenshot evidence route.
3. Add API contract tests and more browser failure scenarios.
4. Add controlled concurrency and retention service.

### Weeks 7–8 hardening

1. Evaluate on a labeled, ethically collected dataset.
2. Measure precision, recall, false positives, timeouts, and latency.
3. Move browser execution to an isolated worker environment.
4. Add monitoring, demo scripts, architecture diagrams, and final presentation evidence.

## 30. Interview study guide

Be able to explain:

- why service, engine, integration, model, and API layers are separate;
- how IMAP UIDs and Message-ID deduplication work;
- how the ML model turns probability into a risk score;
- how static URL heuristics differ from dynamic evidence;
- what SSRF is and why redirects/DNS answers must be validated;
- how format routing and YARA complement one another;
- why the final score uses probabilistic accumulation;
- why unit tests mock boundaries while the browser integration test uses real Chromium;
- the difference between CI, CD, a background task, and a durable worker queue;
- how GitHub branch protection converts tests into an enforced engineering control;
- which current limitations you would fix before production.

One-minute project explanation:

> “Phishing Guard V2 is a FastAPI and React email-security platform. It incrementally imports messages over IMAP, stores normalized evidence in PostgreSQL, and analyzes text, links, and attachments with independent engines. Text uses a scikit-learn probability model; URLs combine explainable static rules, optional VirusTotal reputation, and policy-gated Playwright observation protected by SSRF validation; attachments use format-aware static analysis, MIME checks, YARA, and optional hash reputation. A scan service persists per-engine evidence and combines risk probabilistically into safe, suspicious, or dangerous. The frontend queues scans and polls their lifecycle. The current capstone MVP is well tested, while durable workers and hardened browser isolation are explicit production roadmap items.”

## 31. Primary external references

- [FastAPI testing](https://fastapi.tiangolo.com/tutorial/testing/)
- [FastAPI background tasks](https://fastapi.tiangolo.com/tutorial/background-tasks/)
- [Playwright Python CI](https://playwright.dev/python/docs/ci)
- [Playwright browser installation](https://playwright.dev/python/docs/browsers)
- [GitHub Actions: building and testing Python](https://docs.github.com/en/actions/tutorials/build-and-test-code/python)
- [GitHub Actions: PostgreSQL service containers](https://docs.github.com/en/actions/tutorials/using-containerized-services/creating-postgresql-service-containers)
- [GitHub Actions workflow artifacts](https://docs.github.com/en/actions/concepts/workflows-and-actions/workflow-artifacts)
- [GitHub protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [GitHub publishing Docker images](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images)
- [GitHub deployment environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
