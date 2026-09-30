PHISHING GUARD V2 - SEPTEMBER DEVELOPMENT TIMELINE

Project: SIH 26106 - AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform
Reporting Period: 1 September 2026 to 30 September 2026
Document Type: Monthly development timeline and final sprint report
Prepared For: Project Mentor Review
Status: Complete, deployed to production, all quality gates passed


1. EXECUTIVE SUMMARY

Phishing Guard V2 is an AI-powered email threat detection, geolocation and forensic intelligence platform that ingests real mailboxes, scores every message through four independent detection engines, clusters related attacks into campaigns, and presents the results to an analyst through a full forensics workbench. The system was designed, built, tested and deployed entirely within September 2026 across three development weeks, with a final overnight integration sprint on 30 September that polished the analyst-facing experience and closed the last data-quality gaps.

At the end of the month the platform holds 72 analysed emails and 349 completed scan verdicts in production, forms 25 attack campaigns, geolocates and fingerprints every reachable sending IP, and reports zero false positives and zero false negatives against the labelled evaluation corpus (22 phishing, 50 benign). The automated test suite passes 428 tests at 78.19 percent statement coverage, the frontend compiles with zero TypeScript errors and zero lint errors, and the live deployment at https://phishing-guard.duckdns.org serves the full analyst workbench on Docker containers behind Nginx on an AWS EC2 instance.


2. SYSTEM ARCHITECTURE AT A GLANCE

Backend: Python with FastAPI, SQLAlchemy ORM, Alembic database migrations, PostgreSQL for persistence, scikit-learn for the phishing classifier, and a threaded background scan queue with per-scan timeouts and startup recovery.

Detection engines: four independent score channels - machine learning classification, URL analysis, attachment analysis and email header forensics - fused with the multiplicative safety model p_safe = (1 - p_ai)(1 - p_url)(1 - p_att)(1 - p_header). Final verdict thresholds: score below 30 is SAFE, 30 to 69 is SUSPICIOUS, 70 and above is DANGEROUS. The AI channel score is the maximum of the ML classifier, the business-email-compromise rule engine and the brand lookalike engine.

Forensic layer: Received-chain parser, SPF/DKIM/DMARC authentication parsing, header anomaly scoring, origin hop extraction, IP geolocation and ASN reputation, domain intelligence (DNS posture and RDAP registration age), sending-infrastructure attribution, indicator extraction, union-find campaign clustering, and an evidence chain with SHA-256 hashes for chain of custody.

Frontend: React with TypeScript built on Vite, using a dark SOC-style theme, with dashboard, inbox, scan results, URL analysis, attachments, campaigns, attribution graph, alerts, health and settings pages, plus dedicated forensic views for header analysis, origin trace and a printable sealed report.

Deployment: Docker Compose production stack (Postgres, backend with two Uvicorn workers, Nginx frontend, one-shot frontend build service) on AWS EC2, released through a single startup script that applies database migrations, recovers stuck scans, requeues pending work and brings the stack up. Remote access is provided through DuckDNS with a TLS certificate.


3. DEVELOPMENT TIMELINE


WEEK 1 - FOUNDATION AND CORE DETECTION PIPELINE (1 SEPTEMBER TO 7 SEPTEMBER)

Objectives: stand up the repository, the database schema and the end-to-end scan pipeline so that a fetched email can be scored automatically and returned as a verdict.

1-2 September: project scaffolding. FastAPI application structure with modular routers and services, SQLAlchemy models for emails, email sources, attachments, scans, verdicts, indicators and evidence rows, Alembic initialisation, PostgreSQL containerisation, configuration loaded from environment via Pydantic settings, and the first test harness with SQLite-backed fixtures so that the suite runs offline.

3-4 September: ingestion layer. Gmail IMAP fetch with an application password, MIME decoding of plain-text and HTML bodies, attachment extraction with SHA-256 hashing and size metadata, header normalisation, and a raw-email archive on disk that can be re-parsed later by the backfill tooling.

4-5 September: detection engines. The scikit-learn phishing classifier trained on the labelled corpus, the URL extractor and heuristic scorer (shorteners, punycode, embedded redirects, high-risk TLDs, IP hosts), the attachment scorer (double extensions, executables, macro documents, archive inspection), and the header anomaly engine (return-path mismatch, message-id mismatch, display-name spoofing, SPF/DKIM/DMARC failures).

5-6 September: fusion and queue. The multiplicative fusion formula, verdict classification thresholds, the background scan queue with pending, running, complete and error states, per-scan timeout handling, and the REST endpoints to trigger a scan, poll its status and fetch its verdict.

6-7 September: verification and tooling. Unit tests across every engine, corpus evaluation script with a pass/fail gate, Docker Compose development stack, and the first end-to-end run proving an inbox message could be fetched, scanned and displayed. Week 1 deliverable: a working detection core that could classify an email end to end with reproducible tests.


WEEK 2 - FORENSIC INTELLIGENCE AND CORRELATION LAYER (13 SEPTEMBER TO 19 SEPTEMBER)

Objectives: turn the detection core into an investigation platform by adding header forensics, infrastructure intelligence, correlation and case management.

13-14 September: header forensics deepened. Received-chain parsing with hop-by-hop timestamps, internal versus external classification and origin extraction; authentication-results parsing with SPF, DKIM and DMARC outcomes plus identifier alignment; a weighted anomaly scoring model with raw rule visibility for the analyst.

14-15 September: URL and attachment intelligence. VirusTotal lookups keyed to extracted URLs with graceful offline degradation, per-URL score breakdowns with top contributing flags, dynamic analysis plumbing, and file analysis detail views backed by stored attachment metadata.

15-16 September: infrastructure intelligence. IP geolocation and ASN lookup with a read-through database cache, VPN/TOR/hosting/DNSBL reputation flags, origin-trace construction from the Received chain, and a geospatial route polyline of the sending path.

16-17 September: domain intelligence and attribution (backlog B1 and B2). DNS posture checks (MX, TXT, SPF, DMARC) and RDAP registration age for any sending domain, plus a sending-infrastructure attribution engine that classifies direct actor, compromised account, spoofed domain or unknown, requiring a young domain before a direct-actor verdict can be issued.

17-18 September: indicators, campaigns and graph (backlog B3, B4, B5). A searchable indicator API across all scans; union-find campaign clustering that joins scans sharing origin IP, reply-to domain or registrable URL domain, with a TF-IDF subject-similarity pass for same-brand lures; campaign CRUD with analyst status workflow (new, open, investigating, closed) and case notes up to 4000 characters; and a node-capped attribution graph API with per-scan filtering.

18-19 September: evidence completeness (backlog B6, B7, B8). A raw-email backfill tool that re-parses archived messages into structured headers and hops, body-level YARA scanning of message content, and an attribution statistics endpoint powering the dashboard donut. Week 2 deliverable: every forensic endpoint required by the analyst workbench existed, was tested, and degraded gracefully offline.


WEEK 3 - ANALYST WORKBENCH FRONTEND, QUALITY HARDENING AND PRODUCTION GO-LIVE (20 SEPTEMBER TO 30 SEPTEMBER)

Phase A (20-26 September) - the analyst workbench. The React application was built page by page: dashboard with KPI cards and charts, email inbox with fetch, bulk fetch, per-email preview and scan triggers, scan results with classification and score-range filters, URL analysis table with risk pills and search, attachment analysis grid, campaigns board with status editing and notes, attribution graph with side panel, alerts feed, API health page and settings page. The six frontend backlog items were completed in this phase: FE-C1 header forensics view with engine weight breakdown and raw header viewer; FE-C2 campaign case management controls; FE-C3 printable forensic report with JSON export; FE-C4 graph campaign filter with node side panel; FE-C5 attribution donut driven by the statistics endpoint; FE-C6 origin trace page with geospatial route polyline.

Phase B (27-29 September) - hardening and production. Startup recovery was fixed so that scans abandoned by a crash are reset from running to error and pending scans are requeued instead of stalling forever; the connection pool was resized to survive background scan bursts; scan timeouts were raised to 240 seconds; database migration 0009 was applied in production; the raw-email backfill ran with a 48 of 48 success rate; and a false-positive overhaul removed three systematic over-scoring paths - envelope-authenticated mail no longer triggers return-path and message-id mismatch anomalies, ESP-owned tracking redirects on the sender's own domain no longer trigger long-URL penalties, and display-name spoofing now checks the lookalike brand registry for ownership of the From domain. A machine-learning corroboration cap was added so that a clean, envelope-authenticated email with clean header, URL and attachment channels cannot be pushed into the suspicious band by the ML residual alone; the cap is recorded transparently in the verdict flags as ml_residual_capped. All 72 emails were re-scanned and re-verified: zero false positives (highest safe score 25.0 against a threshold of 30) and zero false negatives (lowest phishing score 33.1). Campaigns were reclustered into 25 groups, the notification bell z-index defect was fixed by removing the header overflow clip and raising the dropdown above page content, and API keys (VirusTotal, Gmail) were configured and validated in production.

Phase C (30 September) - final integration sprint. The overnight session described in full in the next section.


4. FINAL INTEGRATION SPRINT - 30 SEPTEMBER (LAST 8 TO 9 HOURS)

Objective: remove every rough edge an evaluator or mentor would notice during a live walkthrough - dead-end navigation, meaningless campaign names, missing sort controls, broken print output, and the origin trace page that showed mostly empty fields - then re-run every quality gate and redeploy.

4.1  INBOX TO ANALYSIS NAVIGATION (WORK ITEM 1)

Previously, an email that had already been scanned showed only a disabled "Scan Complete" button with no way to reach its results; the full report link existed only immediately after a fresh scan. The scan button component now resolves the latest completed scan for the email through the latest-scan endpoint and renders a primary "View Analysis" action that navigates directly to the full scan report, a "Re-scan" action for re-running the analysis, and the inline verdict summary (score and classification) for the historical result. An analyst can now move from inbox to evidence in one click for every scanned message.

4.2  AUTOMATIC CAMPAIGN NAMES (WORK ITEM 2)

Campaigns were previously named mechanically, producing labels such as "campaign 12" or "origin 1.2.3.4" that convey nothing to an investigator. The clustering engine now derives a human-readable name from two signals: the most frequent tactic vocabulary matched across member subjects (payment lure, credential phishing, delivery notice, document share lure, job offer scam, CEO or wire fraud, security alert lure, official impersonation, account update lure) and the shared infrastructure (impersonated brand, reply-to domain or shared URL domain). Brand plus tactic yields names such as "paypal credential phishing"; tactic plus infrastructure yields names such as "credential phishing via tokenharbor.ai"; when neither signal exists the engine falls back to the previous infrastructure labels. After reclustering, the 25 production campaigns now read, for example: "delivery notice via parcel-redelivery.org", "payment lure via company-mail.co", "CEO/wire fraud campaign", "document share lure via stealth.example". Five new unit tests lock the naming behaviour in place.

4.3  SORTING CONTROLS (WORK ITEM 3)

Three analyst tables gained explicit sort controls with a direction toggle:
• Scan Results - sort by date, score or subject, ascending or descending (default remains score high to low).
• URL Analysis - the existing score, URL and scan-id options were joined by a date option and an ascending or descending toggle.
• Attachments - sort by date, filename, score or size with a direction toggle; the list previously had no ordering control at all.
The controls use the existing dark input styling, so the pages look unchanged apart from the new selector.

4.4  PRINT AND PDF OUTPUT (WORK ITEM 4)

The report page previously printed as a screenshot-like copy of the dark screen - sidebar and toolbar included, content clipped by the scroll containers, and the browser assigned a generic PDF filename. Two changes fixed this. First, the page title is now set to a unique self-explanatory name - PhishNet-report-scan-<id>-<classification>-<email subject> - immediately before the print dialog opens, so the saved PDF is named meaningfully and is unique per report; the title restores itself after printing. Second, a dedicated print stylesheet was added: it hides the sidebar, header, offline banner, toasts and all action buttons; un-clips every scroll container so full content flows across pages; forces a light colour palette over the dark-theme variables; and renders tables with readable hairline borders.

4.5  ORIGIN TRACE COMPLETE OVERHAUL (WORK ITEM 5)

The origin trace page was reported as roughly 80 percent empty fields - no geo, no ASN, no ISP, no map route. Investigation during the sprint uncovered three independent root causes, all fixed:

Root cause A - enrichment results were never persisted. The database session helper closes the session without committing, so every live geolocation lookup performed by the trace endpoint was returned in that one response and then silently discarded. The next page load was always a cache miss. The fix adds an explicit commit after enrichment in both the trace refresh path and the IP intelligence endpoint.

Root cause B - the geolocation provider no longer exists. The configured provider URL (api.ipwhois.io) had been retired and returned DNS resolution failure for every lookup, so no data could ever be fetched regardless of committing. The endpoint was migrated to the successor service ipwho.is, which speaks the identical JSON schema, needs no API key, and was verified working from inside the production container. The country code field, previously never copied into the cache, is now persisted as well.

Root cause C - no automatic fill, and a poisoned cache. The endpoint was strictly cache-only unless the analyst clicked refresh, hop IPs were never looked up at all, and transient provider failures wrote empty placeholder rows that blocked any retry for the full 30-day cache lifetime. The redesigned flow queues missing IPs (origin first, then relays, capped at six per request) into a background enrichment job that runs after the response is sent; the payload reports an "enriching" counter and the page re-polls itself every three seconds, up to four times, so geo and ASN details appear on screen a few seconds after first view with no user action. A manual refresh now enriches up to ten IPs synchronously. Empty rows are no longer written on transient failures, while definitive answers (reserved and private address ranges) are cached as permanent misses so they are never retried. Concurrent enrichment of the same IP from parallel requests is handled gracefully - a duplicate insert is recognised as "another worker already wrote it" instead of failing the batch. The Received-chain table also gained a protocol column and a hover tooltip exposing the raw header line.

4.6  TESTS, GATES AND DEPLOYMENT

New and updated tests this sprint: five campaign-naming tests, five origin-trace tests (background queueing, refresh semantics, persistence-commit verification, disabled-auto-enrichment behaviour), two IP-intelligence tests (country-code persistence and no-negative-cache-on-failure), and two geolocation-provider tests (definitive versus transient error handling).

Gates executed before deployment: backend suite 428 passed at 78.19 percent coverage against a required floor of 75 percent; evaluation corpus PASS with 22 true positives, 50 true negatives, 0 false positives, 0 false negatives; TypeScript build clean; ESLint zero errors (one pre-existing informational warning); production bundle built successfully.

Deployment: backend and frontend containers rebuilt and restarted through the production compose stack; database healthy; campaigns reclustered with the new naming engine; the geolocation cache was pre-warmed across all 72 emails; and every endpoint was re-verified live (trace enrichment, latest-scan, campaign list and case-update, attribution statistics, health). Zero tracebacks and zero errors were logged after the final deployment.


5. QUALITY ASSURANCE SUMMARY

Automated tests: 428 passing, covering engines, services, API routes, clustering, intel endpoints and evidence integrity.

Coverage: 78.19 percent of application statements, gate set at 75 percent.

Detection quality: zero false positives and zero false negatives on the labelled corpus; safe emails peak at 25.0 against a decision threshold of 30, confirmed phishing bottoms out at 33.1.

Frontend quality: zero TypeScript compilation errors, zero lint errors, production build clean.

Degradation: every external intelligence source (geolocation, VirusTotal, DNS, RDAP, TOR list) is optional by configuration; offline runs serve cached or absent data and never fail a scan.


6. OPERATIONS AND INFRASTRUCTURE

Production stack: AWS EC2 (65.2.178.253) behind DuckDNS (phishing-guard.duckdns.org) with TLS, Nginx serving the built frontend and proxying the API, PostgreSQL with a tuned connection pool (10 persistent plus 25 overflow connections, 60 second acquisition timeout), and two Uvicorn workers. The startup script applies Alembic migrations, recovers interrupted scans and requeues pending work, so a container restart is always safe. Configured integrations: VirusTotal API key, Gmail IMAP application password, DuckDNS update token, keyless geolocation, RDAP and TOR intelligence sources. Recommended future upgrades: additional rotating VirusTotal keys, a MaxMind offline database, DNS blocklist checks with an explicit allow-list, and dynamic URL rendering with a headless browser.


7. KEY METRICS AT THE END OF THE SPRINT

Emails analysed in production: 72 (48 real mailbox messages plus 24 curated corpus samples)
Completed scan verdicts: 349
Campaigns clustered: 25 (337 of 349 scans assigned)
IP intelligence records: 47 (23 fully geolocated, 24 reserved-range misses correctly cached)
Tests passing: 428
Statement coverage: 78.19 percent
False positives / false negatives on corpus: 0 / 0
TypeScript errors / lint errors: 0 / 0
Post-deployment errors in production logs: 0


8. PROBLEMS ENCOUNTERED AND HOW THEY WERE RESOLVED

Stuck scan queue after crashes - root cause was a shutdown call that blocked forever on abandoned worker threads; fixed by using a non-blocking shutdown plus startup recovery that resets and requeues interrupted scans.

Systematic false positives on legitimate ESP mail - resolved by exempting envelope-authenticated messages from mismatch anomalies, gating long-URL penalties on sender-authenticated redirects, and tightening display-name spoofing against the brand registry.

Machine-learning residual pushing clean mail into the suspicious band - resolved with a documented corroboration cap that only engages when every other channel is clean, recorded transparently in the verdict.

Database pool exhaustion under scan bursts - resolved by resizing the pool and raising scan timeouts, with pool parameters kept in code rather than the connection URL because the driver rejects them as URL options.

Origin trace showing empty intelligence - resolved through the three-part root cause analysis described in section 4.5 (missing commits, retired geolocation provider, absence of automatic enrichment plus cache poisoning).

Notification bell hidden behind page content - resolved by removing the header's overflow clip, giving the header an explicit stacking level, and raising the alert dropdown above page content.

Printed reports unusable - resolved with unique print filenames and a print stylesheet that hides application chrome and un-clips scrolling content.


9. FUTURE SCOPE

Rotating multiple VirusTotal keys for higher query quota; MaxMind GeoLite2 for offline geolocation with country codes; enabling DNS blocklist and header DNS validation checks behind explicit configuration; dynamic URL rendering with a headless browser for phishing-kit screenshots; mail-server level aggregation across multiple mailboxes; and an auto-refreshing live feed on the dashboard during active incidents.


10. CONCLUSION

Within one month, Phishing Guard V2 moved from an empty repository to a production-deployed forensic platform with a four-engine detection core, an end-to-end intelligence and correlation layer, a complete analyst workbench, and a verified zero-false-positive, zero-false-negative evaluation result. The final overnight sprint on 30 September closed the last usability and data-quality gaps - navigation from inbox to analysis, meaningful campaign names, sort controls, professional print output, and a fully populated origin trace - and every quality gate was re-run and passed before redeployment. The system is stable, documented, tested and ready for mentor evaluation and live demonstration.

End of report.
