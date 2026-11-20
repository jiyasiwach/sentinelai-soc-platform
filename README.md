# SentinelAI - AI-Powered SOC Investigation Platform

SentinelAI is a web platform that helps a Security Operations Center (SOC) analyst turn raw SIEM alerts
into investigated incidents. It ingests alerts from Wazuh, Splunk, Elastic or plain JSON, normalises them,
extracts indicators of compromise (IOCs), enriches them from a local threat-intelligence feed, maps them to
MITRE ATT&CK, links them to vulnerability-assessment (VA) results for the target asset, correlates related
alerts, and gives every alert an explainable 0-100 risk score. An AI engine (an offline expert system by
default, or Claude / any OpenAI-compatible model) writes a verdict, an attack narrative and recommended
response actions, and answers questions about a case in a chat. Response actions are simulated and audited:
the platform never scans, exploits or changes a real system. It was built as a final-year PTVA
(Penetration Testing & Vulnerability Assessment) course project.

## Features

- **Multi-SIEM ingest** - Wazuh, Splunk, Elastic and generic JSON / JSON Lines, by API, paste or file
  upload, with automatic format detection and per-item error reporting.
- **Enrichment pipeline** - IOC extraction (IPv4, domain, URL, email, MD5, SHA-1, SHA-256, CVE), local
  threat-intel lookup, keyword-based ATT&CK mapping (35 techniques across all 12 enterprise tactics).
- **Explainable risk score** - every point added to the 0-100 score is stored with a plain-English reason.
- **VA-aware triage** - alerts on an asset with exploitable or critical vulnerabilities score higher, and
  vulnerabilities on an asset with open alerts are prioritised higher.
- **Correlation and auto-grouping** - alerts sharing a host, user, source IP or external IOC within a time
  window are linked; one click groups them into cases.
- **AI investigation** - verdict, confidence, kill-chain narrative, key findings, recommended actions,
  IOCs to block, open questions and matching playbooks, for a single alert or a whole case.
- **AI case chat** - ask about IOCs, the timeline, ATT&CK, affected assets' vulnerabilities, or next steps.
- **Case management** - status workflow, notes, simulated response actions with an action log, colour-coded
  alert timeline and a downloadable Markdown incident report.
- **Vulnerability assessment module** - import Nmap XML (XXE-safe) and Nessus/OpenVAS/pentest findings
  as JSON; CVSS v3.1 rating bands; priority score that weighs asset criticality and exploitability.
  Alerts and findings stay in sync both ways: VA changes re-score the asset's open alerts, and opening or
  closing alerts re-prioritises the asset's findings.
- **ATT&CK coverage matrix and response playbooks** (8 playbooks).
- **Role-based access** (admin / analyst / viewer), JWT auth, PBKDF2 password hashing, a full audit log.
- **Three AI providers**: `offline` (default, deterministic, no key), `anthropic`, `openai`
  (OpenAI, Azure OpenAI, Groq, Ollama, LM Studio). Any provider error falls back to `offline`.

## Quick start

### Docker (recommended)

```bash
docker compose up --build
```

Open http://localhost:8000. This starts the app (UI and API on one port) and PostgreSQL 16, and seeds the
demo data on the first start. The API documentation (Swagger UI) is at http://localhost:8000/api/docs.

To set options, copy `.env.example` to `.env` and edit it; `docker compose` reads it automatically.

### Local development

Requires Python 3.12 and Node.js 20.

```bash
make install     # creates .venv, installs backend/requirements-dev.txt, runs npm install in frontend/
make backend     # API with auto-reload on http://localhost:8000 (SQLite file backend/sentinel.db)
make frontend    # in a second terminal: Vite dev server on http://localhost:5173, proxies /api to :8000
```

Open http://localhost:5173. Other targets: `make test` (pytest), `make build` (builds the UI into
`frontend/dist`, which FastAPI then serves on :8000), `make run` (build, then serve UI + API on :8000),
`make docker`.

Without `make`:

```bash
cd backend && pip install -r requirements-dev.txt && uvicorn app.main:app --reload
cd frontend && npm install && npm run dev
```

## Demo logins

| Username | Password | Role | Can do |
|---|---|---|---|
| `admin` | `Admin@12345` | admin | everything, plus users, audit log and deleting cases |
| `analyst` | `Analyst@12345` | analyst | ingest, investigate, edit alerts/cases/assets, run actions, chat |
| `viewer` | `Viewer@12345` | viewer | read-only (write controls are hidden) |

The passwords can be overridden with `ADMIN_PASSWORD`, `ANALYST_PASSWORD` and `VIEWER_PASSWORD`. These are
only read when the database is seeded for the first time (when it has no users).

## Using a real LLM

The default `AI_PROVIDER=offline` needs no key. To use a language model, set the variables in `.env`
(or in your host's environment settings) and restart. Keys are read from the environment only.

```bash
# Claude (Anthropic Messages API)
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-opus-5-5        # default
# ANTHROPIC_FALLBACKS=false            # server-side refusal fallbacks are on by default

# OpenAI
AI_PROVIDER=openai
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini               # default

# Ollama (local, no key) - any OpenAI-compatible /chat/completions endpoint works the same way
AI_PROVIDER=openai
OPENAI_BASE_URL=http://localhost:11434/v1
OPENAI_MODEL=llama3.1
```

If the provider fails (bad key, network error, refusal, invalid JSON), SentinelAI uses the offline analyst
for that request and records an `engine_note` explaining why. `AI_TIMEOUT_SECONDS` (default 90) bounds each
call. When the app runs inside Docker, `localhost` is the container itself; point `OPENAI_BASE_URL` at the
host instead (for example `http://host.docker.internal:11434/v1` on Docker Desktop).

## 5-minute demo walkthrough

The seed data contains 20 alerts in four attack chains plus noise, 5 assets with 9 vulnerabilities, and
2 cases. All indicators are documentation-safe (RFC 5737 IPs, `.example` domains, well-known test hashes).
Timestamps are relative to the moment the database was seeded.

1. **Dashboard** - sign in as `analyst`. Note the six KPI tiles (open alerts, critical open, open cases,
   MTTR from the closed EICAR case, open vulnerabilities, true positives), the 7-day alert chart, the severity and verdict breakdowns, the top-risk
   alerts (the exfiltration alert on `fs-01` scores 100), top techniques, tactics, malicious IOCs and sources.
2. **Case #1 - phishing to exfiltration.** Open *Cases* and then case #1. Six alerts on `finance-ws-07` and
   `fs-01` tell the story: macro phishing -> encoded PowerShell -> Mimikatz on LSASS -> Cobalt Strike
   beaconing to `203.0.113.45` -> RDP to `fs-01` -> large upload to the C2 server. The AI analysis gives
   *true positive, confidence 92* and a narrative across 8 ATT&CK tactics. `isolate_host finance-ws-07` is
   already in the action log and ticked as done in the recommendations. In the chat, click the suggestion
   chips ("Which IOCs should we block?", "What should I do next?") and try *Run* on a recommended action
   (for example `block_ip 203.0.113.45`); it is simulated and appears in the action log and audit log.
   Click *Download report* for the Markdown incident report.
3. **Alerts - Log4Shell on web-01.** Open *Alerts* and find "Log4Shell JNDI exploit attempt in User-Agent"
   (status `new`, verdict `pending`, risk 90). The *why this risk score* panel shows: 55 base (critical) +
   15 malicious IOC `192.0.2.66` + 10 critical asset + 8 exploitable vulnerability on the asset + 2 for one
   correlated alert. The target-asset VA panel shows `web-01` with CVE-2021-44228 (Log4Shell, CVSS 10.0,
   public exploit, priority 100). Click *Investigate*: the offline analyst returns *true positive* and
   recommends blocking `192.0.2.66`, and asks whether CVE-2021-44228 on `web-01` was exploited. The
   correlated SQL-injection alert from the same source is listed.
4. **Cases - Auto-group.** Back on *Cases*, click *Auto-group alerts*. SentinelAI groups the correlated alerts
   that are not yet in a case: the SSH brute-force chain on `web-01` (3 alerts), the ransomware chain on
   `hr-ws-03` (3 alerts) and the two web-exploit alerts on `web-01`. Running it again creates nothing new.
5. **Vulnerabilities - import and prioritise.** Open *Vulnerabilities* -> *Import* and upload
   `sample-data/nmap_scan.xml`. The result reports 3 hosts (2 new assets, 1 updated) and 6 findings for
   risky exposed services (FTP, Telnet, Redis, Elasticsearch, RDP, VNC). On the assets list, change
   `cache-01` from `medium` to `critical`: its Redis finding moves from priority 68.6 to 96.0
   (9.8 x 7 x 1.4). Set it to `low` and it drops to 48.0.
6. **Admin - audit log.** Sign in as `admin` and open *Admin*. The audit log shows every login, failed
   login, ingest, AI investigation, chat question, response action, import and asset change, with actor and
   time. You can also create users here.

## Project structure

```
soc-investigator/
├── backend/
│   ├── app/
│   │   ├── main.py            FastAPI app, security headers, serves the built UI
│   │   ├── config.py          settings from environment variables
│   │   ├── database.py        SQLAlchemy engine/session
│   │   ├── models.py          ORM models
│   │   ├── schemas.py         Pydantic request models and response serialisers
│   │   ├── security.py        PBKDF2 hashing, JWT, role checks, audit helper
│   │   ├── seed.py            demo data
│   │   ├── api/               auth.py, alerts.py, cases.py, vulns.py, dashboard.py
│   │   ├── services/          normalizer, enrichment, mitre, vuln, correlation, scoring,
│   │   │                      playbooks, pipeline, ai_engine, report
│   │   └── data/              mitre_techniques.json, playbooks.json, threat_intel.json,
│   │                          sample_alerts.json, sample_vulns.json
│   ├── tests/                 conftest.py, test_api.py, test_services.py
│   ├── requirements.txt / requirements-dev.txt / pytest.ini
├── frontend/                  React 18 + Vite 5 + React Router 6 (no UI framework)
│   └── src/                   main.jsx, App.jsx, api.js, components/, pages/
├── sample-data/               Wazuh/Splunk/Elastic/JSONL alerts, nmap_scan.xml, va_findings.json
├── docs/                      ARCHITECTURE, API, DEPLOYMENT, TESTING, PROJECT_REPORT
├── Dockerfile                 multi-stage: Node 20 builds UI, Python 3.12-slim serves UI + API
├── docker-compose.yml         app + postgres:16-alpine
├── render.yaml                Render blueprint
├── Makefile, .env.example, .github/workflows/ci.yml, LICENSE (MIT)
```

## Security notes

- **Nothing touches real systems.** Response actions (`isolate_host`, `block_ip`, ...) are recorded with
  status `simulated` and audited. The VA module only imports the *results* of tests you are authorised to
  run; it never scans.
- **Production guard.** With `APP_ENV=production` the app refuses to start unless `JWT_SECRET` is at least
  32 characters and not a known weak value. It logs a warning when demo seeding is on and `ADMIN_PASSWORD`
  is still the default.
- **Prompt-injection defence.** Log data sent to an LLM is fenced in `<alert_data>` / `<case_data>` tags
  with `<` and `>` escaped, the model must return strict JSON, and the output is validated against
  whitelists. The AI only recommends; it cannot execute anything.
- **Input hardening.** XXE-safe Nmap parsing, upload size limits (20 MB alerts, 10 MB XML), request item
  caps, strict request schemas (unknown fields rejected), security headers on every response.
- **Accounts.** PBKDF2-SHA256 with 310,000 iterations; JWT (HS256) valid for 480 minutes by default; every
  login, failed login, lockout and write action is in the audit log.
- **Login throttling.** 5 failed logins for one username, or 20 from one client IP, within 15 minutes lock
  further attempts (even with the right password) and return `429` with `Retry-After`. Tune with
  `LOGIN_MAX_FAILURES`, `LOGIN_IP_MAX_FAILURES` and `LOGIN_LOCKOUT_MINUTES`.
- Change the demo passwords before the first start of any shared deployment, or set
  `SEED_DEMO_DATA=false` and create the first admin with the one-off command in
  [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) (with seeding off, no users exist).

## Documentation

- [Architecture](docs/ARCHITECTURE.md) - pipeline, data model, AI and VA design, security controls
- [API reference](docs/API.md) - every endpoint, role and example response
- [Deployment](docs/DEPLOYMENT.md) - checklist, Render, Railway, VPS + Caddy, Vercel split, Fly.io, operations
- [Testing](docs/TESTING.md) - automated tests, manual QA checklist, security checks
- [Project report](docs/PROJECT_REPORT.md) - academic PTVA project report

## License

MIT - see [LICENSE](LICENSE).
