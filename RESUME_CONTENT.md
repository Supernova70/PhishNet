# Resume Content — PhishNet (Add Project Form)

Copy-paste values for each field in your application form.

---

## Field Values

**Project Title***
AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform (SIH 26106 — system name "PhishNet")

**Project Type***
Personal / Academic Security Project
(If the list has "Internship", select that — the repo references an internship project)

**Company Name**
Independent Project (or your college/company name if submitted through one)

**Project Link**
https://github.com/<your-username>/<repo-name>

**Skills**
Python, FastAPI, Machine Learning, Scikit-learn, YARA, VirusTotal API, Playwright, PostgreSQL, Docker, AWS EC2, REST API, React, TypeScript, Leaflet, Cybersecurity, Email Forensics, Phishing Analysis, SPF/DKIM/DMARC, GeoIP/ASN, SSRF, Malware Analysis, VAPT, Chain of Custody, pytest

**Start Date**
<Month Year — e.g., January 2025>

**Completion Date***
<Month Year — e.g., September 2025>

**Duration**
<e.g., 8 months>

---

## Project Description*

Built an AI-powered email threat detection, geolocation and forensic intelligence platform (SIH 26106) that classifies malicious emails with a four-signal probabilistic pipeline: an ML phishing classifier trained on 82,000+ emails (99.2% F1), URL IOC analysis with VirusTotal reputation lookups, YARA-powered malware scanning of weaponized attachments (PE, PDF, Office), and RFC822 header forensics — Received-chain parsing, SPF/DKIM/DMARC validation and weighted anomaly rules (display-name spoof, Reply-To hijack, relay forgery). Extended detection with rule-based BEC categories (payment diversion, fake invoice, credential harvest, executive impersonation) and homoglyph/lookalike-brand matching. Added origin traceability (GeoIP/ASN, hosting/VPN/TOR flags, DNSBL) and an attribution layer that extracts IoCs per scan, builds a force-directed attack graph, clusters campaigns via union-find over shared infrastructure, and issues evidence-weighted attribution verdicts. Hardened compliance with a hash-chained chain-of-custody log, append-only audit trail, PII masking, retention purging and integrity-sealed forensic reports (sha256 + disclaimer). Delivered a React dashboard with header-forensics panels, an origin-trace Leaflet map, graph and campaign views, an alert feed, and real-time SSE progress; validated with 348 automated pytest tests (78% coverage) behind a GitHub Actions CI pipeline, deployed on AWS EC2 behind Nginx.

**Shorter alternative (if the form has a character limit):**

Built an AI-powered email threat detection and forensic intelligence platform (SIH 26106): ML classifier (82K emails, 99.2% F1) + URL/attachment engines + header forensics (SPF/DKIM/DMARC, Received chain) fused into safe/suspicious/dangerous verdicts. Added BEC/lookalike rules, origin GeoIP/ASN traceability, IoC graph + campaign clustering with evidence-weighted attribution, and a hash-chained chain-of-custody with integrity-sealed forensic reports. Shipped REST API + React forensics dashboard (trace map, graph, alert feed) with 348 automated tests, CI, and AWS EC2 deployment.

---

## Notes

- Replace `<your-username>/<repo-name>` and the dates with your real values before submitting
- Cite only real metrics (82,440 emails, 99.2% F1, 348 passing tests, 78% coverage) — verifiable from `data/training_report.txt` and `pytest --cov=app`
- Two tests need optional binaries (Chromium, yara) and are excluded from the passing count on machines without them; CI installs Chromium
- Do not claim live CI/CD deployment status, a malware sandbox, or a durable job queue — GitHub Actions workflow exists, but sandbox/queue are not implemented
