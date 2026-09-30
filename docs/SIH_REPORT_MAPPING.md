# SIH 26106 — Problem Statement → Feature → Code → Test Mapping

**AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform**

One row per problem-statement component (as recorded in `docs/SIH_IMPLEMENTATION_PLAN.md` §1).
Every row names a working feature, the code that implements it, and the tests that prove it.
All tests run offline (network access is injected/mocked); run with `pytest -q`.

Legend: ✅ implemented and covered by passing tests · stretch items marked explicitly.

---

## 1. Fraudulent Email Detection (NLP / BEC)

| Feature | Code | Tests |
|---|---|---|
| Binary ML phishing classifier (TF-IDF + Logistic Regression, 99.2% F1 on 82,440 emails) | `app/engines/text_analyzer.py`, `train_model.py`, `data/training_report.txt` | `tests/test_ml_engine.py` |
| BEC category rules: payment diversion, fake invoice, credential harvest, executive impersonation, urgency threat (weighted signals → confidence 0–100) | `app/engines/bec_analyzer.py` | `tests/test_bec_analyzer.py` |
| Lookalike-brand detection: homoglyphs, Levenshtein ≤2, hyphen/subdomain tricks, brand-in-subdomain (`paypal.secure-login.tk`) | `app/engines/lookalike.py` | `tests/test_lookalike.py` |
| Body-text YARA rules (urgency/verification phrases) in the text engine | `app/engines/text_analyzer.py` + `app/engines/rules/` | `tests/test_ml_engine.py` |
| Combined AI signal `ai_score = max(ml_score, bec_score, lookalike_score)` with flags in breakdown | `app/services/scan_service.py` (stage 2b) | `tests/test_scan_service.py` |
| 4-class retrain (weak-supervision labels) | *stretch — `bec_labels` export path; not claimed as shipped* | — |

## 2. Header & Protocol Analysis

| Feature | Code | Tests |
|---|---|---|
| Raw RFC822 retention at fetch: gzip + sha256 + full `headers_json` (multi-valued) | `app/services/email_service.py`, `app/models/email_source.py` | `tests/test_email_service.py` |
| Received-chain parsing: bracketed IPs, HELO, `by`, timestamps, parse confidence, internal-hop detection, earliest reliable **external** hop = origin | `app/engines/headers/received_parser.py` | `tests/test_received_parser.py` |
| SPF/DKIM/DMARC parsing from `Authentication-Results` / `Received-SPF` / `DKIM-Signature` + optional active DNS checks (`HEADER_DNS_CHECKS_ENABLED`, default off) | `app/engines/headers/auth_parser.py`, `app/engines/headers/dns_checks.py` | `tests/test_auth_parser.py`, `tests/test_spf_dmarc.py` |
| Anomaly rules with weights + human-readable flags: From↔Return-Path mismatch, display-name spoof, Reply-To hijack, non-monotonic Received, SPF/DKIM/DMARC fail, missing Received, … → `header_score` = min(sum, 100) | `app/engines/headers/anomaly_rules.py`, `app/engines/header_analyzer.py` | `tests/test_header_analyzer.py` |
| 4-signal fusion `p_safe = (1-p_ai)(1-p_url)(1-p_att)(1-p_header)`; absent header evidence → `p_header = 0`; thresholds <30 / 30–69 / ≥70 unchanged | `app/services/scan_service.py` (`_compute_final_score`) | `tests/test_scan_service.py` (incl. legacy 3-signal regression cases) |
| Headers API: raw headers + parsed hops + auth results + raw sha256 | `GET /emails/{id}/headers` — `app/api/intel.py` | `tests/test_api_intel.py` |

## 3. Origin Traceability & GeoLocation

| Feature | Code | Tests |
|---|---|---|
| Origin selection from the Received chain (`OriginTrace`: ip, hop, host, helo, timestamp) | `app/engines/intel/origin.py` | `tests/test_intel_origin.py` |
| GeoIP provider protocol: free `ipwhois.io` (httpx, 3s timeout) + optional MaxMind offline DB (`GEOIP_DB_PATH`, guarded `geoip2` import); in-process TTL cache + `ip_intel` table persistence | `app/engines/intel/geo_provider.py`, `app/models/ip_intel.py` | `tests/test_intel_geo_provider.py` |
| ASN/organisation + curated hosting-provider detection (AWS/Azure/GCP/DigitalOcean/…) | `app/engines/intel/asn_rdap.py` | `tests/test_intel_threats.py` |
| VPN/TOR/proxy/hosting flags (provider threat fields + cached Tor exit list) | `app/engines/intel/vpn_tor.py` | `tests/test_intel_threats.py` |
| DNSBL checks (SpamCop default, Spamhaus ZEN behind optional DQS key; `DNSBL_ENABLED` off in tests) | `app/engines/intel/dnsbl.py` | `tests/test_intel_dnsbl.py` |
| IP intel service: cache-only by default, `refresh=true` for live enrichment, graceful offline | `app/services/ip_intel_service.py` | `tests/test_ip_intel_service.py` |
| APIs: `GET /ips/{ip}` (cache-only unless refresh), `GET /emails/{id}/trace`, `GET /ips/stats` (dashboard country aggregates) | `app/api/intel.py` | `tests/test_api_intel.py` |
| Origin Trace page: hop table + Leaflet map (origin marker, geo/ASN/VPN-TOR badges, refresh-intel flow) | `frontend/src/pages/TracePage.tsx` | `npx eslint .` + `npm run build` (frontend gate; see CI) |

## 4. Identity Correlation & Attribution

| Feature | Code | Tests |
|---|---|---|
| IoC extraction per scan: sender/reply-to domains, origin IP, URL registrable domains, attachment SHA-256, lookalike brand, auth results → `indicators` (per-scan rows, aggregated in API) | `app/engines/correlation/ioc_store.py`, `app/models/indicator.py` | `tests/test_ioc_store.py` |
| Attribution graph: `email/domain/ip/hash/brand/campaign` nodes, relation edges, server-side 500-node cap, plain-JSON output (dict-based, no networkx) | `app/engines/correlation/graph_builder.py` | `tests/test_graph_builder.py` |
| Campaign clustering: union-find over shared high-value IoCs + subject similarity (TF-IDF cosine) → `campaigns` table with confidence/status; `POST /campaigns/recluster` backfill | `app/engines/correlation/campaign_clustering.py`, `app/models/campaign.py` | `tests/test_campaign_clustering.py`, `tests/test_api_intel.py` |
| Attribution verdicts with weighted evidence: `spoofed_domain`, `compromised_account` (requires internal sender), `anonymized_infrastructure`, `direct_actor` → `breakdown["attribution"]` | `app/engines/correlation/attribution.py` | `tests/test_attribution.py` |
| APIs: `GET /graph`, `GET /campaigns`, `GET /campaigns/{id}` | `app/api/intel.py` | `tests/test_api_intel.py` |
| Surfaces: `/graph` force-directed view (color by type, size by risk, click-through), `/campaigns` list + detail with member scans, ScanDetail button links | `frontend/src/pages/GraphPage.tsx`, `frontend/src/pages/CampaignsPage.tsx`, `frontend/src/pages/ScanDetail.tsx` | frontend lint + build gates |

## 5. Alerts, Dashboard, Forensic Reports

| Feature | Code | Tests |
|---|---|---|
| Global SSE endpoint `GET /scans/events` (all terminal/high-risk scans, order-safe vs `/{scan_id}`); per-scan `GET /scans/{scan_id}/events` | `app/api/scan.py`, `app/services/scan_service.py` (`publish_scan_event`) | `tests/test_platform_hardening.py` |
| Alert rules: score ≥70, spoof/auth-fail, BEC category ≥40 → one `alerts` row per scan, reasons list, never fails a scan | `app/services/alert_service.py`, `app/services/scan_service.py` (stage 7b), `app/models/alert.py` | `tests/test_alerts.py` |
| Alert feed API: `GET /alerts` (+ unread count/filter), `POST /alerts/{id}/read`, `POST /alerts/read-all` | `app/api/alerts.py` | `tests/test_alerts.py` |
| Bell dropdown (30s poll, mark-read inline) + `/alerts` page with reason chips and scan links | `frontend/src/components/layout/AlertBell.tsx`, `frontend/src/pages/AlertsPage.tsx` | frontend lint + build gates |
| Forensic report `GET /scans/{id}/report`: case metadata, verdict + sub-scores, header forensics, geo origin, received chain, indicators, campaign, chain-of-custody block; `export=true` seals a new evidence row + audit entry; canonical sha256 + disclaimer footer | `app/api/report.py` | `tests/test_evidence_compliance.py` |
| Report page `/scans/:id/report` with Export & Seal button | `frontend/src/pages/ReportPage.tsx` | frontend lint + build gates |
| Header forensics panel in ScanDetail: SPF/DKIM/DMARC pills, alignment, header flags, Received hops, raw sha256, link to trace | `frontend/src/components/forensics/HeaderForensics.tsx` | frontend lint + build gates |
| Dashboard: spoof/auth-fail count, open campaigns, top origin countries (plus existing KPIs/timeline/donut) | `frontend/src/pages/Dashboard.tsx` (`IntelStrip`), `GET /ips/stats`, `GET /alerts`, `GET /campaigns` | `tests/test_api_intel.py` (stats), `tests/test_alerts.py`, frontend gates |
| CSV export of scans (NULL-breakdown safe) | `app/api/scan.py` | `tests/test_api_core.py` |

## 6. Privacy / Legal / Compliance

| Feature | Code | Tests |
|---|---|---|
| Hash-chained `evidence_chain`: genesis `0*64`, `row_hash = sha256(payload)` after flush, append-only, verify endpoints (`/evidence/{id}/verify`, list) | `app/models/evidence.py`, `app/services/evidence_service.py`, `app/api/evidence.py` | `tests/test_evidence_compliance.py` |
| Evidence hook on every completed scan (actor `scanner`; failure never fails a scan) | `app/services/scan_service.py` (stage 7) | `tests/test_evidence_compliance.py` |
| Append-only `audit_log`: raw header views, raw downloads, report exports, retention purges (`AUDIT_ACTIONS` whitelist) | `app/models/audit_log.py`, `app/services/evidence_service.py` (`audit`) | `tests/test_evidence_compliance.py`, `tests/test_platform_hardening.py` |
| PII masking (`MASK_PII`): recipient local-parts `j***@corp.com`, origin IPs in exports/reports | `app/services/pii.py`, `app/api/report.py` | `tests/test_evidence_compliance.py` |
| Retention purge (`RETENTION_DAYS`): raw files, screenshots, expired ip_intel; verdicts only with explicit `--include-verdicts`; dry-run mode; CLI `scripts/purge_old_evidence.py` | `app/services/retention.py` | `tests/test_platform_hardening.py` |
| Report footer: evidentiary-use disclaimer, generation time, app version, integrity sha256 | `app/api/report.py` | `tests/test_evidence_compliance.py` |
| Raw evidence download `GET /emails/{id}/evidence/raw` (audited) | `app/api/evidence.py` | `tests/test_evidence_compliance.py` |

## Hygiene

| Feature | Code | Tests |
|---|---|---|
| Schema-drift fix + full migration chain 0001→0008 (guarded, re-runnable) | `alembic/versions/` | fresh-DB `alembic upgrade head` verified; guarded-drop checks in `tests/test_evidence_compliance.py` |
| API-key middleware registered when `API_KEYS` configured (`X-API-Key`, `/health` exempt) | `app/main.py` (`ApiKeyMiddleware`) | `tests/test_platform_hardening.py` |
| CI: backend (postgres service + playwright + `pytest --cov=app --cov-fail-under=75`), frontend (`npm ci`, lint, build), docker build | `.github/workflows/ci.yml` | runs on GitHub Actions |
| Demo corpus: 24 crafted `.eml` + importer + `scripts/demo.sh` (fetch→scan→recluster→deep links) | `scripts/generate_corpus.py`, `scripts/import_eml.py`, `scripts/demo.sh` | `tests/test_demo_corpus.py` |
| API-key-gated isolation of network integrations; all network injectable, tests fully offline | throughout (`HEADER_DNS_CHECKS_ENABLED=False`, `DNSBL_ENABLED=False` defaults) | entire suite (2 known env-only failures: Playwright binary, yara wheel on py3.14) |

---

## Verification commands

```bash
# backend (from repo root, with .venv active)
alembic upgrade head                 # fresh DB: 0001 → 0008
pytest -q --cov=app --cov-fail-under=75

# frontend (Node ≥22.12)
cd frontend && npx eslint . && npm run build

# 5-minute demo
./scripts/demo.sh
```

**Known honest gaps** (not claimed anywhere): no OS-level malware sandbox, no durable
job queue (scans are in-process/background), no live 4-class BEC model (rule engine +
binary ML only), Playwright/Chromium and yara are optional locally and excluded from
hard-fail expectations where unavailable.
