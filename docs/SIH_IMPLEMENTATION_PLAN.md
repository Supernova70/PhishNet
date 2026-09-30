# SIH 26106 — Implementation Plan

**AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform**
(SIH problem statement 26106 — this repo was previously branded *Phishing Guard V2 / PhishNet*)

**Capacity:** 5 SDEs × 3 weeks = 15 engineer-weeks
**Status:** Plan approved. Decisions locked: (1) free `ipwhois.io` GeoIP API default with optional MaxMind offline DB; (2) rule/weak-supervision BEC category engine first, 4-class retrain as stretch; (3) rebrand to the SIH title.

---

## 1. Gap Analysis — Problem Statement vs. Current Codebase

| # | PS Component | Current State | Gap |
|---|---|---|---|
| 1 | Fraudulent Email Detection (NLP/BEC) | Binary ML (TF-IDF+LR, 99.2% F1), URL + attachment engines | No BEC/impersonation/urgency classes (YARA urgency rules run on attachments only), no multi-class labels, no display-name spoof / lookalike-domain detection |
| 2 | Header & Protocol Analysis | **Nothing** — raw RFC822 fetched then discarded (`app/services/email_service.py:114-117`); no Received/Return-Path/DKIM/SPF/DMARC anywhere | Full module: header retention, Received-chain parse, auth validation, relay anomaly rules |
| 3 | Origin Traceability & GeoLocation | No sender IP extraction, no GeoIP, no WHOIS, no ASN/VPN/TOR/DNSBL | Full module |
| 4 | Identity Correlation & Attribution | VirusTotal for URLs/files only; no graph, no campaign clustering, no attribution scoring | Full module |
| 5 | Alerts, Dashboard, Forensic Reports | Dashboard + per-scan SSE + CSV export exist; global SSE endpoint broken (`frontend/src/hooks/useScanSse.ts` → `/scans/events` does not exist) | Trace map, geo map, graph view, case management, forensic report, global alert feed |
| 6 | Privacy/Legal/Compliance | Nothing (no audit log, masking, retention, chain-of-custody) | Full module |
| Hygiene | — | Migration `0003` (URL dynamic columns) referenced in docs but absent; no CI; API-key middleware defined but never registered | Fix |

**Reusable assets:** 3-engine detection pipeline + probabilistic fusion, PostgreSQL/Alembic, React dashboard, Docker/AWS deploy, 46 tests, VirusTotal integration, SSRF validator, graceful-fallback patterns.

---

## 2. Target Architecture

```text
                            IMAP inbox
                               │
                    raw RFC822 retained (gzip + sha256 + full headers)
                               │
        ┌──────────────────────┼──────────────────────────┐
        ▼                      ▼                          ▼
  Text/BEC Engine        Header Forensics           URL Engine
  (binary ML +           (Received chain,           (heuristics + VT +
   BEC category           SPF/DKIM/DMARC,            policy-gated Playwright)
   rules + lookalike      anomaly rules →
   domains + body YARA)   header_score)
        │                      │                          │
        │                 ┌────┴─────┐                    │
        │                 ▼          ▼                    ▼
        │          Origin Trace   Domain Intel      Attachment Engine
        │          (origin IP,    (WHOIS/DNS/MX,    (PE/PDF/Office/YARA/VT)
        │           Geo/ASN,      age, lookalike)
        │           VPN/TOR, DNSBL)
        │                 │          │                    │
        └────────┬────────┴──────────┴────────┬───────────┘
                 ▼                            ▼
        Probabilistic fusion        Attribution + IOC store
        p_safe=(1-p_ai)(1-p_url)     (networkx graph,
         (1-p_att)(1-p_header)        campaign clustering,
                 │                    confidence verdicts)
                 ▼                            │
        Verdict + evidence  ◄─────────────────┘
                 │
    ┌────────────┼──────────────┬─────────────────┐
    ▼            ▼              ▼                 ▼
 Alert feed   Trace/geo      Case mgmt        Forensic report
 (SSE)        map (Leaflet)  (campaigns)      (HTML/JSON + hashes)
    │
 Compliance layer: chain-of-custody hashes, audit log, PII masking, retention
```

---

## 3. Workstream Ownership (5 roles)

| Role | Scope | Key files |
|---|---|---|
| **SDE-1** Ingestion & Header Forensics | Raw retention, Received-chain parser, SPF/DKIM/DMARC validation, header anomaly rules | `services/email_service.py`, `engines/header_analyzer.py`, `models/email_source.py` |
| **SDE-2** Origin & IP/Domain Intel | Origin IP, GeoIP, ASN/hosting/VPN/TOR, DNSBL, WHOIS/DNS/MX intel | `engines/intel/*`, `models/ip_intel.py` |
| **SDE-3** Detection & Correlation | BEC categories, lookalike domains, fusion, graph, campaigns, attribution | `engines/bec_analyzer.py`, `engines/correlation/*` |
| **SDE-4** Frontend & Reporting | Trace map, geo map, graph view, cases, forensic report, alerts | `frontend/src/pages/*` |
| **SDE-5** Platform & QA | Migrations, compliance, API surface, CI, demo corpus, e2e tests, docs | `alembic/`, `api/*`, `.github/`, `tests/` |

---

## 4. Week 1 — Evidence Foundation

### Schema (SDE-5)
- `0003_url_dynamic_columns.py` — add the missing `dynamic_flags`/`dynamic_error` columns already read by `scan_service.py:153-170` (schema-drift fix)
- `0004_header_forensics.py` — new tables:
  - `email_sources`: `email_id` FK unique, `raw_gzip_path`, `raw_sha256`, `size_bytes`, `headers_json` (all headers as key → list[str]), `fetched_at`
  - `received_hops`: `email_id` FK, `hop_index`, `protocol`, `from_host`, `from_ip`, `helo`, `by_host`, `via`, `timestamp_raw`, `timestamp_utc`, `ptr_host`, `is_internal`, `parse_confidence`
  - `auth_results`: `email_id` FK unique, `spf_result`, `spf_domain`, `dkim_result`, `dkim_domain`, `dkim_selector`, `dmarc_result`, `dmarc_domain`, `alignment`, `source` (`header`|`dns`), `checked_at`, `detail_json`
- `0005_ip_intel.py` — `ip_intel`: `ip` unique, `country`, `region`, `city`, `lat`, `lon`, `asn`, `asn_org`, `isp`, `is_vpn`, `is_tor`, `is_proxy`, `is_hosting`, `ptr_host`, `dnsbl_json`, `source`, `fetched_at`, `expires_at`

### Ingestion (SDE-1)
- Preserve raw bytes at fetch: gzip to `{ATTACHMENT_DIR}/../raw_email/{email_id}.eml.gz`, sha256, size
- Persist **all** headers via `msg.items()` → `headers_json` (multi-valued: keep list per key for `Received`)
- Backfill command: `scripts/backfill_raw_email.py` — re-fetch stored emails by UID/Message-ID where mailbox still has them
- `_parse_mime` gains `return_path`, `reply_to`, `cc`, `x_mailer`, `received_raw` keys (read-only, stored in headers_json)

### Header forensics engine (SDE-1) — `app/engines/header_analyzer.py` + `app/engines/headers/` package
- `received_parser.py`: hop extraction regexes (bracketed `[IP]`, `from host (helo=...) by`, `with ESMTPS/ESMTP`), timestamp parsing (last `at ...` clause), internal-hop detection (myhostname/mydomain/private ranges), ordered chain with per-hop `parse_confidence`; earliest **reliable external** hop = origin candidate
- `auth_validator.py`:
  - Parse `Authentication-Results`/`Received-SPF`/`DKIM-Signature` headers (pass/fail + domain + selector)
  - Active checks (optional flag `HEADER_DNS_CHECKS_ENABLED`, default off in tests): `dnspython` SPF record fetch + mechanism eval vs origin IP, DMARC record fetch + alignment (relaxed/strict) → `dmarc_result`; `dkim` (dkimpy) cryptographic verify against raw body + DNS key fetch
  - Fail-graceful: any DNS failure → `detail_json["errors"]`, never block scan
- `anomaly_rules.py` (pure functions, fully unit-tested):
  - From↔Return-Path domain mismatch (+25), Display-name brand vs actual domain mismatch (+30), Reply-To ≠ From domain (+25), Message-ID domain ≠ From domain (+10), missing Received (+15), non-monotonic Received timestamps (+20), HELO/EHLO mismatch with connecting host (+15), sender domain has no DMARC (+5), SPF fail (+30), DKIM fail (+20), DMARC fail (+30), suspension/clock-skew notes
  - `header_score` = min(sum, 100); every point stores a human-readable `header_flags` entry

### Fusion contract (SDE-3)
- `scan_service._compute_final_score` → `p_safe = (1-p_ai)(1-p_url)(1-p_att)(1-p_header)` where `p_header = header_score/100`
- Missing header evidence (old emails) → `p_header = 0` (never penalize absent evidence)
- Verdict `breakdown` gains `header_score`, `header_flags`; update `tests/test_scan_service.py`
- Classification thresholds unchanged: <30 safe, 30–69 suspicious, ≥70 dangerous

### Week 1 exit criteria
- Fresh `alembic upgrade head` on empty DB green; all existing 46 tests green
- New tests: received parser (6 crafted chains incl. forged/missing/non-monotonic), auth header parsing (6 fixtures), anomaly rules (12+ boundary cases), fusion math, ingestion raw-retention roundtrip
- Demo: fetch email → `/emails/{id}/headers` shows parsed chain + auth results (API added by SDE-5 in Week 2, but engine output visible in scan breakdown)

---

## 5. Week 2 — Intelligence & Correlation Engines

### Origin trace (SDE-2) — `app/engines/intel/`
- `origin.py` — earliest external hop IP → `OriginTrace` (ip, hop, ptr, first_seen)
- `geo_provider.py` — `IpIntelProvider` protocol; `IpWhoisIoProvider` (free, no key, 1K/day, `httpx` with 3s timeout) primary; `MaxMindGeoLite2Provider` optional (`GEOIP_DB_PATH` config, `geoip2` import guarded); in-process TTL cache + `ip_intel` table persistence
- `asn_rdap.py` — `ipwhois` lib for ASN/org/network; hosting-provider detection via curated ASN/org name list (AWS, Azure, GCP, DigitalOcean, OVH, Hetzner, Vultr, Linode, Choopa, M247…)
- `vpn_tor.py` — provider threat fields (vpn/tor/proxy/hosting) + fetchable Tor exit list (`check.torproject.org/torbulkexitlist`) cached daily; open-proxy indicators best-effort
- `dnsbl.py` — pluggable DNSBL: SpamCop (`bl.spamcop.net`) free default; Spamhaus ZEN behind optional `SPAMHAUS_DQS_KEY` (`<rev-ip>.zen.dq.spamhaus.org`); `DNSBL_ENABLED` config, **off in tests**; results → `dnsbl_json`
- `domain_intel.py` — `dnspython`: MX/NS/TXT/SPF/DMARC presence + counts; RDAP/`python-whois` (optional dep, guarded) registrar/creation/expiry → `domain_age_days`, `registrar`, `is_young` (<30d), `has_mx`, `dmarc_policy`

### Detection upgrades (SDE-3)
- `app/engines/bec_analyzer.py` — pure rule engine over subject/body/headers, each category with weighted regex+keyword signals and confidence:
  - `payment_diversion` (bank-change, wire, urgent transfer, beneficiary)
  - `fake_invoice` (invoice/PO/quote + amount + due urgency)
  - `credential_harvest` (verify/account/suspended/login + link)
  - `executive_impersonation` (CEO/CFO/MD display name + authority cues + reply-to mismatch)
  - `urgency_threat` (24h, legal action, account closure, confidentiality)
  - Weak-supervision labels written to `bec_labels` CSV for the optional 4-class retrain (`train_model.py --multiclass`, stretch goal)
  - Result: `bec_categories: [{category, confidence, evidence}]`, `bec_score` (0–100)
- `app/engines/lookalike.py` — brand list (PayPal, Google, Amazon, Apple, Microsoft, Netflix, Facebook, Chase, Wells Fargo, SBI, HDFC…) vs From/Reply-To/URL registrable domains: homoglyph map (а→a, 0/o, l/1), Levenshtein ≤2, hyphen/subdomain tricks, brand-in-subdomain (`paypal.secure-login.tk`) → `lookalike_score` + matched brand
- Run `app/engines/rules/phishing.yar` against **body text** (currently attachments-only) in text engine
- `text_analyzer.py` gains `bec_score`/`lookalike_score` inputs → combined `ai_score = max(ml_score, bec_score, lookalike_score)` with flags in breakdown (ML stays authoritative when present)

### Attribution & correlation (SDE-3) — `app/engines/correlation/`
- `ioc_store.py` — per scan extract: sender domain, reply-to domain, origin IP, URL registrable domains, URL host IPs, attachment SHA-256, lookalike brand, DKIM/SPF/DMARC results → table `indicators` (`scan_id`, `type`, `value`, `first_seen`, `last_seen`, `sighting_count`)
- `graph_builder.py` — `networkx` multigraph: node types `email | domain | ip | url_host | hash | person | campaign`; edges `sent_from`, `authenticated_by`, `originated_from`, `hosted_on`, `links_to`, `replies_to`, `same_campaign`; API returns `{nodes:[{id,type,label,risk}], edges:[{source,target,relation}]}`; server-side degree cap (500 nodes) for UI safety
- `campaign_clustering.py` — union-find over shared high-value IOCs (origin IP / reply-to domain / lookalike brand / URL registrable domain) + subject similarity (TF-IDF cosine ≥0.72 within same brand) → `campaigns` table (`name`, `first_seen`, `last_seen`, `email_count`, `avg_score`, `status`, `confidence`); backfill endpoint clusters existing scans
- `attribution.py` — confidence-based verdict with evidence list (weights in one pure table, unit-tested):
  - `spoofed_domain` (SPF/DKIM/DMARC fail + display-name mismatch + reply-to mismatch)
  - `compromised_account` (auth passes + internal sender + lookalike/ BEC content + odd reply-to)
  - `anonymized_infrastructure` (origin is VPN/TOR/proxy/hosting or DNSBL-listed)
  - `direct_actor` (auth fails + young domain + hosting origin + no TLS)
  - Each: `confidence = 0–100`, `factors: [{label, weight}]`; cap-by-evidence count; stored in `verdicts.breakdown["attribution"]` + `indicators`

### API surface (SDE-5)
| Method | Path | Purpose |
|---|---|---|
| GET | `/emails/{id}/headers` | Raw headers, parsed hops, auth results |
| GET | `/emails/{id}/trace` | Ordered hops + geo/ASN/VPN per hop + origin verdict |
| GET | `/scans/{id}/attribution` | Attribution verdict + factors + indicators |
| GET | `/scans/{id}/indicators` | IOC list for the scan |
| GET | `/graph?campaign_id=&scan_id=` | Node/edge graph JSON |
| GET/POST | `/campaigns` | List/create; POST `/campaigns/recluster` |
| GET | `/campaigns/{id}` | Campaign detail + emails + indicators |
| GET | `/domains/{domain}/intel` | WHOIS/DNS/lookalike intel |
| PATCH | `/campaigns/{id}` | status (`new`/`investigating`/`closed`), notes |

### Week 2 exit criteria
- Engines tested offline with fake providers (no network in unit tests)
- End-to-end: fetch → scan → headers/trace/attribution/graph endpoints return coherent data on demo corpus
- Existing tests still green; new tests ≥40

---

## 6. Week 3 — Dashboard, Reports, Compliance, Hardening

### Frontend (SDE-4) — 6 surfaces
1. **Origin Trace page** `/emails/:id/trace` — hop table (index, host, IP, PTR, time, internal badge) + Leaflet world map with polyline source→relay→origin, geo/ASN/VPN/TOR badges, origin callout
2. **Header forensics panel** in ScanDetail — raw header viewer, Received chain, SPF/DKIM/DMARC badge row, anomaly flags with weights
3. **Graph view** `/graph` — `react-force-graph-2d`, node color by type, size by risk, click → side panel, filter by campaign
4. **Case management** `/campaigns` — campaign table (score bar, email count, first/last seen, status select), detail drawer, search by domain/IP/subject
5. **Forensic report** `/scans/:id/report` — printable HTML: evidence summary, header chain, geo origin, attribution, indicators, report sha256 + evidence hashes + chain-of-custody block; buttons: `Print/PDF` (browser), `Export JSON`, existing CSV export retained
6. **Global alert feed** — fix `useScanSse.ts` by adding `GET /scans/events` (SSE, all terminal/high-risk scans); bell dropdown + `/alerts` page (score ≥70, spoof fail, BEC category hit); mark-as-read stored in `alerts` table

Dashboard KPI additions: spoofing-detection count, top origin countries, open campaigns, attribution split donut.

### Compliance (SDE-5)
- `models/evidence.py` — `evidence_chain`: `id`, `email_id`, `scan_id`, `sha256(raw)`, `report_sha256`, `created_at`, `actor`, `prev_hash`, `row_hash` (hash-chained; verify endpoint `/evidence/{id}/verify`)
- `models/audit_log.py` — every raw-email view, report export, evidence download → append-only log
- Retention: `RETENTION_DAYS` config + `scripts/purge_old_evidence.py` (raw files + screenshots + soft-delete intel cache; never deletes verdicts without explicit `--include-verdicts`)
- PII masking: `MASK_PII` config toggle — mask recipient local-parts (`j***@corp.com`) and (optionally) IPs in exports/graph labels; applies to API responses + reports
- Report footer disclaimer: evidentiary-use notice, generation time, system version, integrity hash

### Platform fixes & QA (SDE-5 + all)
- Register `ApiKeyMiddleware` when `API_KEYS` set (`main.py`) + tests; **or** document as disabled — decided: register it
- Global SSE endpoint; fix `useSystemHealth.ts` redis/virustotal type mismatch
- **CI** `.github/workflows/ci.yml`: backend job (postgres service, playwright chromium, pytest + coverage xml), frontend job (`npm ci`, lint, build), docker build job
- `test_ml_engine.py`/`test_scan_service.py` upgraded to real assertions
- Coverage target ≥75% on `app/`

### Demo corpus & docs (SDE-5)
- `tests/fixtures/eml/` — ≥20 crafted `.eml`: clean mail, plain spoof, display-name spoof, SPF/DKIM fail, BEC invoice, payment-diversion, lookalike domain, credential harvest, relay-forged (non-monotonic Received), missing Received, TOR-origin label, young domain, URL shortener + brand, exec impersonation, reply-to hijack, DKIM pass/auth-pass BEC (compromised-account case), bulk campaign (5 similar), clean DKIM+DMARC pass, HTML-only with hidden link, double-extension attachment
- `scripts/demo.sh` — import corpus → bulk scan → print URLs for trace/attribution/campaign/report
- Docs: README rebrand + feature matrix update, architecture diagram, `docs/SIH_REPORT_MAPPING.md` (every PS bullet → feature + test file), interview Q&A refresh

### Week 3 exit criteria (Definition of Done)
- [x] Every problem-statement bullet maps to a working feature + passing test — `docs/SIH_REPORT_MAPPING.md` created
- [x] `pytest` green, coverage ≥75% — **348 passed, 78% coverage** (2 known env-only failures: Chromium/yara binaries, excluded locally; CI installs Chromium)
- [x] Fresh-DB migration path verified (`alembic upgrade head` 0001→0008 on empty SQLite/Postgres); existing-DB path guarded (existence-checked DDL in 0003–0008)
- [x] 5-minute demo: `scripts/demo.sh` — import 24-email corpus → bulk scan → recluster → prints trace/graph/campaign/report deep links
- [x] No unimplemented claims in docs (sandbox/CI-queue honesty preserved; `.github/workflows/ci.yml` ships the pipeline, GitHub-side status not verifiable from this repo)

**Implementation status (2026-09-29): all five workstreams delivered.** Deviations from the original plan, documented in code:
1. No `ipwhois` PyPI dependency — ASN/org/hosting detection is provider-field + curated-ASN-list based (`app/engines/intel/asn_rdap.py`).
2. No `networkx` — graph builder emits the plan's JSON contract from plain dicts (`app/engines/correlation/graph_builder.py`).
3. `text_analyzer.py` untouched — BEC/lookalike combine at the pipeline level (`ai_score = max(...)`, stage 2b) instead.
4. Attribution `compromised_account` requires an internal sender (strict evidence rule).
5. Indicator rows are per-scan unique `(scan_id, type, value)`; `/indicators` aggregates with GROUP BY — global dedup would have broken clustering/graph linkage.
6. Map ships as Leaflet + OSM with a graceful "coordinates unavailable" panel (plan's chosen stack); polyline source→relay→origin is reduced to an origin marker because only the origin hop is enriched with geo (per-hop geo is a stretch).
7. Global SSE added as `GET /scans/events`; `useSystemHealth` needed no fix (backend never emitted a `redis` component).

---

## 7. Deliverable Count (justifies 15 engineer-weeks)

- ~12 new backend modules/packages
- 6 migrations (0003–0008) / ~8 new tables
- ~9 new API groups
- 6 new frontend surfaces + 2 dashboard upgrades
- +65 new tests (→ ~110 total)
- CI pipeline, demo corpus (20+ .eml), report generator, docs rebrand

## 8. Technical Stack Additions

| Need | Chosen | Rationale |
|---|---|---|
| Received/auth parsing | stdlib `email` + custom parsers | No maintained lib covers the whole need |
| DNS checks (SPF/DMARC/MX) | `dnspython` | Ubiquitous, pure Python |
| DKIM verify | `dkim` (dkimpy) | Cryptographic verify, maintained |
| GeoIP | `ipwhois.io` API (free, no key) + optional `geoip2` | Decision (1); cache in `ip_intel` |
| ASN/RDAP | `ipwhois` | BSD, supports RDAP+ASN |
| WHOIS (domain) | `python-whois` (optional, guarded) | Best-effort; degrade gracefully |
| DNSBL | SpamCop free; Spamhaus ZEN via optional DQS key | No account required for demo |
| Graph | `networkx` (server) + `react-force-graph-2d` (UI) | Standard, JSON-friendly |
| Map | `leaflet` + OSM tiles (fallback: static SVG if offline) | Simple, familiar |
| Subject similarity | scikit-learn TF-IDF cosine (already a dep) | No new dependency |

## 9. Risk Register

| Risk | Mitigation |
|---|---|
| Free geo API rate limits during demo | DB cache (`ip_intel`) + in-process TTL; seeded demo intel |
| WHOIS/DNS unavailable offline at venue | All intel providers fail-graceful with `unavailable` state; demo corpus pre-warmed into cache |
| Spamhaus free resolver deprecation | SpamCop default; Spamhaus behind optional key; DNSBL off in tests |
| Playwright/Chromium heavy in CI | Existing pattern: split fast unit job vs browser job |
| Scope creep in Week 3 | Compliance and reports are must; graph polish/4-class model explicitly stretch |
| IMAP backfill impossible (mail deleted) | Raw retention applies to new fetches; corpus import path is primary demo route |

## 10. Mapping Table Placeholder

See `docs/SIH_REPORT_MAPPING.md` (created Week 3) — one row per problem-statement bullet → feature → code → test.
