# Architecture

SentinelAI is a single FastAPI application that exposes a JSON API under `/api` and, when the React UI has
been built, serves that UI from the same port. State lives in one relational database (SQLite in
development, PostgreSQL in production). Reference data (ATT&CK techniques, playbooks, threat intel) ships
as JSON files in `backend/app/data/`. There are no background workers: every step runs inside the request
that triggers it.

```
Browser (React SPA) ──HTTPS──▶ FastAPI (backend/app/main.py)
                                 ├── /api/auth, /api/alerts, /api/cases, /api/va, /api/dashboard ...
                                 ├── services/ (pipeline, scoring, AI engine, VA, correlation, ...)
                                 ├── SQLAlchemy 2 ──▶ SQLite / PostgreSQL
                                 ├── httpx ──▶ Anthropic or OpenAI-compatible API (optional)
                                 └── static files: built UI (STATIC_DIR or ../frontend/dist)
```

## 1. Alert pipeline

```mermaid
flowchart LR
    A["Ingest<br/>POST /api/alerts/ingest<br/>POST /api/alerts/upload"] --> B["Normalise<br/>normalizer.py<br/>Wazuh / Splunk / Elastic / generic"]
    B --> C["IOC extraction<br/>enrichment.extract_iocs"]
    C --> D["TI enrichment<br/>enrichment.enrich_iocs<br/>data/threat_intel.json"]
    D --> E["ATT&CK mapping<br/>mitre.map_techniques<br/>data/mitre_techniques.json"]
    E --> F["VA context<br/>vuln.asset_va_context"]
    F --> G["Correlation<br/>correlation.find_related"]
    G --> H["Risk score 0-100<br/>scoring.compute_risk"]
    H --> P["Playbook ranking<br/>playbooks.rank_playbooks"]
    P --> I{"AI triage?<br/>investigate flag or<br/>Investigate button"}
    I -- yes --> J["AI engine<br/>ai_engine.investigate<br/>offline / anthropic / openai"]
    I -- no --> K
    J --> K["Case<br/>manual, or auto_group (union-find)"]
    K --> L["Case AI analysis + chat"]
    L --> M["Simulated response actions<br/>(audited)"]
    L --> N["Markdown incident report"]
```

`pipeline.process_alert` stores the normalised alert and runs `analyze_alert`, which performs steps C-H and
the playbook ranking and writes the results into the alert row (`iocs`, `mitre`, `risk_score`, and
`enrichment` = `ti_summary`, `asset`, `risk_reasons`, `related`, `playbooks`). The ingest endpoint then runs
`analyze_alert` a second time for every alert in the batch so that correlations between alerts of the same
batch are symmetric, and runs `investigate_alert` if the request asked for AI triage.

`investigate_alert` re-runs `analyze_alert` first (so enrichment, VA posture and correlation are fresh),
builds a context with `build_alert_context`, calls the AI engine, stores the report in `alert.ai_report`,
copies the verdict to `alert.verdict` and moves a `new` alert to `triaged`.

## 2. Data model

```mermaid
erDiagram
    USERS {
        int id PK
        string username UK
        string full_name
        string role "admin | analyst | viewer"
        string password_hash "pbkdf2_sha256$iter$salt$hash"
        bool is_active
        datetime created_at
    }
    ALERTS {
        int id PK
        string external_id
        string source
        string title
        text description
        string severity "low | medium | high | critical"
        string status "new | triaged | investigating | closed"
        string category
        string host
        string username
        string src_ip
        string dst_ip
        json raw
        json iocs
        json enrichment
        json mitre
        int risk_score
        string verdict "pending | true_positive | false_positive | benign | needs_review"
        json ai_report
        datetime event_time
        datetime created_at
        datetime updated_at
    }
    CASES {
        int id PK
        string title
        text summary
        string severity
        string status "open | investigating | contained | resolved | closed"
        string assignee
        json ai_report
        string created_by
        datetime created_at
        datetime updated_at
        datetime closed_at
    }
    CASE_ALERTS {
        int case_id PK,FK
        int alert_id PK,FK
    }
    CASE_NOTES {
        int id PK
        int case_id FK
        string author
        text content
        datetime created_at
    }
    RESPONSE_ACTIONS {
        int id PK
        int case_id FK
        string action
        string target
        string performed_by
        string status "simulated"
        text details
        datetime created_at
    }
    CHAT_MESSAGES {
        int id PK
        int case_id FK
        string role "user | assistant"
        text content
        string author
        string engine
        datetime created_at
    }
    ASSETS {
        int id PK
        string hostname
        string ip
        string os
        string criticality "low | medium | high | critical"
        string owner
        json open_ports
        datetime last_scanned
        datetime created_at
    }
    VULNERABILITIES {
        int id PK
        int asset_id FK
        string title
        string cve
        float cvss
        string severity
        int port
        string service
        text description
        text remediation
        bool exploit_available
        string status "open | in_progress | fixed | accepted_risk | false_positive"
        string source "nmap | nessus | openvas | manual | pentest"
        float priority_score
        datetime first_seen
        datetime updated_at
    }
    AUDIT_LOGS {
        int id PK
        string actor
        string action
        string entity
        string entity_id
        text details
        datetime created_at
    }
    CASES ||--o{ CASE_ALERTS : contains
    ALERTS ||--o{ CASE_ALERTS : "belongs to"
    CASES ||--o{ CASE_NOTES : has
    CASES ||--o{ RESPONSE_ACTIONS : has
    CASES ||--o{ CHAT_MESSAGES : has
    ASSETS ||--o{ VULNERABILITIES : has
```

Notes:

- Alerts and cases are many-to-many through `case_alerts`. Deleting a case cascades to its notes, actions,
  chat messages and link rows, not to the alerts.
- **Alerts are not linked to assets by a foreign key.** The link is resolved at analysis time by matching
  the alert's `host` against `assets.hostname` (case-insensitive) or `assets.ip`, then `dst_ip`, then an
  internal `src_ip` (`vuln.asset_va_context`).
- `audit_logs.actor` is a username string, not a foreign key, so failed logins with unknown usernames can be
  recorded.
- Timestamps are stored as naive UTC and serialised with a trailing `Z`.
- Tables are created with `Base.metadata.create_all` at startup. There is no migration tool.

## 3. Components

| Module | Responsibility |
|---|---|
| `main.py` | App factory, lifespan (validate settings, create tables, seed if empty), CORS (non-production only), security-header middleware, generic 500 handler, `/api/health`, SPA serving: the static directory is looked up on each request (so a UI built after start-up is picked up), files are served only if they resolve inside it, fingerprinted `assets/*` get a one-year immutable cache header, other paths get `index.html`, unknown `/api/*` paths (or any path when no UI is built) get a JSON 404. |
| `config.py` | All settings from environment variables; production refusal for weak `JWT_SECRET`; `postgres://` URL normalisation to `postgresql+psycopg://`. |
| `security.py` | PBKDF2-SHA256 (310,000 iterations, 16-byte salt) password hashing, constant-time compare, JWT HS256 issue/verify, `require_roles`, `audit()` helper. |
| `services/normalizer.py` | Format detection and per-source field mapping; severity mapping (words, 0-10, Wazuh 0-15, 0-100); time parsing (ISO 8601, `+0000`, epoch s/ms). |
| `services/enrichment.py` | IOC regexes with false-positive filters (file extensions, internal suffixes, version strings, field names), internal IP ranges, local TI lookup with URL-host, email-domain and parent-domain fallbacks. |
| `services/mitre.py` | Loads 35 techniques; keyword patterns with word boundaries (keywords of 5 characters or fewer need boundaries on both sides); results sorted in kill-chain order; `attack.mitre.org` URLs. |
| `services/vuln.py` | Nmap XML parsing, findings upsert, CVSS bands, priority score, asset matching, VA context for alerts. |
| `services/correlation.py` | Pairwise correlation reasons, `find_related` within a time window, `auto_group` with union-find. |
| `services/scoring.py` | Explainable risk score. |
| `services/playbooks.py` | Ranks the 8 playbooks against techniques, tactics and keywords (top 3). |
| `services/pipeline.py` | Orchestrates the steps above; builds alert and case contexts for the AI. |
| `services/ai_engine.py` | Provider abstraction, prompt fencing, JSON parsing and validation, offline expert system, chat. |
| `services/report.py` | Markdown incident report for a case. |
| `seed.py` | Demo users, assets, findings, 20 alerts, 2 cases. |

### Correlation

Two alerts are correlated if at least one of these holds (`correlation_reasons`):

- same host (case-insensitive);
- same user, ignoring `""`, `-`, `n/a`, `system`, `local service`, `network service`, `unknown`;
- same source IP;
- a shared external IOC (internal IPs and CVE identifiers are excluded).

`find_related` looks at alerts whose `event_time` is within `CORRELATION_WINDOW_MINUTES` (default 60) either
side of the alert, and returns up to 50 matches with their reasons.

`auto_group` takes all alerts that are not `closed` and not already in a case, sorted by time, unions every
correlated pair within the window, and creates one case per cluster of two or more alerts. The case title
is the highest-risk alert's title plus `(+N related)`, its severity is the highest member severity, it is
assigned to the analyst who ran the grouping, and member alerts in `new` move to `triaged`.

### Playbook ranking

For each playbook: +3 per trigger technique matched exactly, +2 if only the parent technique matches,
+1 per trigger tactic present, +2 per trigger keyword found in the alert text. Playbooks scoring 0 are
dropped; the top 3 are returned.

## 4. AI design

### Providers

| `AI_PROVIDER` | Transport | Key variables |
|---|---|---|
| `offline` (default) | none: deterministic rules in `ai_engine.offline_investigate` / `offline_chat` | - |
| `anthropic` | `POST {ANTHROPIC_BASE_URL}/v1/messages`, header `anthropic-version: 2023-06-01` | `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` (default `claude-opus-5-5`), `ANTHROPIC_BASE_URL`, `ANTHROPIC_FALLBACKS` |
| `openai` | `POST {OPENAI_BASE_URL}/chat/completions`, temperature 0.2 | `OPENAI_API_KEY` (optional, sent as Bearer if set), `OPENAI_BASE_URL` (default `https://api.openai.com/v1`), `OPENAI_MODEL` (default `gpt-4o-mini`) |

For Anthropic models whose id starts with `claude-opus-5`, `claude-fable-5` or `claude-sonnet-5-5`, and
unless `ANTHROPIC_FALLBACKS=false`, the request adds the beta header
`anthropic-beta: server-side-fallback-2026-07-01` and `"fallbacks": "default"` so that a refusal triggered by
security-related content can be served by a fallback model. A response with `stop_reason: "refusal"` is
treated as an error. Investigations use `max_tokens` 4000, chat 2000; every call has a timeout of
`AI_TIMEOUT_SECONDS` (default 90).

### Context

The AI never sees the database directly. `build_alert_context` / `build_case_context` assemble a dictionary
with: the anchor alert (with a 3,000-character raw-event excerpt), all alert briefs (description cut to
1,500 characters), enriched IOCs, ATT&CK techniques in kill-chain order, the risk score and its reasons,
related alerts, the VA posture of the target asset(s), ranked playbooks, hosts, users and, for cases,
notes, actions taken and the previous AI report.

### Prompt fencing

`fence(tag, data)` serialises the context as JSON and replaces every `<` with `<` and every `>` with
`>`, then wraps it in `<alert_data>...</alert_data>` or `<case_data>...</case_data>`. Because the payload
can no longer contain an angle bracket, text in a log line such as `</alert_data> Ignore previous
instructions` cannot close the fence or open a new tag; it stays visible to the model as inert data. The
system prompt states that everything inside these tags is untrusted evidence and that instructions found
there must never be followed. The chat prompt sends the case data the same way, then at most the last 10
chat messages (each cut to 4,000 characters) and the question (cut to 2,000 characters).

### Strict JSON and validation

The investigation prompt asks for exactly one JSON object with: `summary`, `verdict`, `confidence`,
`severity`, `attack_narrative`, `key_findings`, `mitre`, `recommended_actions`, `iocs_to_block`,
`open_questions`, `playbooks`. `parse_json_text` strips Markdown code fences and takes the outermost
`{...}`. `validate_report` then:

| Field | Rule |
|---|---|
| `summary` | required, cut to 2,000 chars; missing summary makes the report invalid |
| `verdict` | must be `true_positive`, `false_positive`, `benign` or `needs_review`, else `needs_review` |
| `confidence` | integer, clamped to 0-100, default 50 |
| `severity` | must be `low`/`medium`/`high`/`critical`, else the anchor alert's severity |
| `recommended_actions` | `action` must be one of the 8 action types, `target` non-empty (cut to 300), `priority` must be `immediate`/`high`/`normal` else `normal`; at most 12 |
| `mitre` | `id` must match `^T\d{4}(\.\d{3})?$`; at most 15 |
| lists | `key_findings` 10, `iocs_to_block` 20, `open_questions` 8, `playbooks` 5 |

### The AI never executes

The model output is stored as a report and shown to the analyst. Recommended actions have a *Run* button
in the UI; clicking it calls `POST /api/cases/{id}/actions` as the analyst, which only records a
`simulated` action and an audit entry. Nothing in the backend calls an EDR, firewall or directory.

### Fallback

Any exception in the LLM path (missing key, HTTP error, timeout, refusal, empty reply, invalid JSON, failed
validation) is caught. The offline analyst produces the report instead, and the report carries
`engine: "offline"` plus `engine_note`, for example
`"openai unavailable (LLMError: ...); used offline analyst."`. Chat behaves the same way and returns
`engine_note` in the response. Seeding always uses the offline analyst and never calls a provider.

### Offline expert system

Verdict rules, checked in order (`offline_verdict`):

| # | Condition | Verdict | Confidence |
|---|---|---|---|
| 1 | at least one malicious IOC and at least one mapped technique | `true_positive` | 92 |
| 2 | risk >= 75, or risk >= 65 with a late tactic | `true_positive` | 82 |
| 3 | a sanctioned-activity cue (`approved`, `change ticket`, `chg-`, `awareness`, `eicar`, `authorized test`, `authorised test`) and risk < 60 | `benign` | 85 |
| 4 | there is at least one external IOC that has a reputation or is an ip/domain/url, all such IOCs are `benign`, and none is suspicious | `benign` | 72 |
| 5 | no techniques, no malicious or suspicious IOC, risk < 30 | `false_positive` | 70 |
| 6 | otherwise | `needs_review` | 55 |

Report severity is `low` for benign/false positive verdicts, otherwise the higher of the anchor severity
and a band of the risk score (>= 80 critical, >= 60 high, >= 35 medium, else low).

Recommended actions (none for benign/false positive): `block_ip` for external malicious (immediate) or
suspicious (high) IPs; `block_domain` likewise for domains; `quarantine_file` for malicious hashes;
`isolate_host` (immediate) and `collect_forensics` (high) for up to 3 hosts when an Execution, Credential
Access, Impact or late tactic is present; `reset_password` (high) when a credential technique
(T1078, T1110, T1003, T1552, T1556) or Credential Access is present; `disable_user` (high) for T1098 or
T1136. Actions are sorted immediate, high, normal and capped at 12.

Offline chat routes the question by keywords to: IOCs, timeline, ATT&CK, vulnerabilities, next steps
(marking actions already run as `(done)`), users, hosts, or a summary.

## 5. Vulnerability-assessment design

The VA module analyses the output of authorised tests. It never scans.

### Nmap XML import (`parse_nmap`)

1. Reject input over 10 MB.
2. Reject any `<!ENTITY` declaration (blocks XXE and "billion laughs" entity expansion).
3. Remove a simple `<!DOCTYPE ...>` without an internal subset (Nmap writes `<!DOCTYPE nmaprun>`); reject
   any `DOCTYPE` that remains.
4. Parse with `xml.etree.ElementTree`; the root element must be `<nmaprun>` (output of `nmap -oX`).
5. Keep hosts whose status is `up`; take the first IPv4/IPv6 address, the first hostname, the first
   `osmatch`, and only ports in state `open` (with service name, product and version).

Each host is matched to an existing asset by hostname or IP, or created with criticality `medium`. The
asset's `open_ports` are replaced, `os` is updated if Nmap guessed one, and `last_scanned` is set.

### Risky services

An open port in this list creates or updates a finding with `source = "nmap"`:

| Port | Finding | CVSS |
|---|---|---|
| 21 | FTP service exposed (cleartext credentials) | 7.5 |
| 23 | Telnet service exposed (cleartext remote shell) | 9.1 |
| 445 | SMB exposed | 8.1 |
| 3389 | RDP exposed | 8.1 |
| 5900 | VNC exposed | 8.8 |
| 6379 | Redis exposed (often unauthenticated) | 9.8 |
| 9200 | Elasticsearch HTTP API exposed | 9.1 |
| 27017 | MongoDB exposed | 9.1 |

### Findings import

`POST /api/va/vulnerabilities` accepts Nessus/OpenVAS/pentest/manual findings already converted to the
SentinelAI shape (`host`, `title`, `cve`, `cvss`, `port`, `service`, `description`, `remediation`,
`exploit_available`, `source`, `ip`). A finding is **upserted by asset + title + port**: re-importing the
same finding updates it instead of duplicating it, and keeps its status unless the import supplies one.

### CVSS bands and priority

Severity follows the CVSS v3.1 qualitative rating: >= 9.0 critical, >= 7.0 high, >= 4.0 medium, otherwise
low (a score of 0.0 is shown as `low`, where the specification says "None").

```
priority = min(100, CVSS x 7 x W + 12 [public exploit] + 10 [asset has open alerts])
W = 0.7 (low), 1.0 (medium), 1.2 (high), 1.4 (critical asset criticality)
```

rounded to one decimal place. "Open alerts" means alerts not `closed` whose host matches the asset's
hostname or IP, or whose `dst_ip` is the asset's IP. Priorities are recalculated for an asset when findings
or an Nmap scan are imported for it and when its criticality changes.

### Two-way alert <-> VA link

- **VA -> alert:** during analysis, `asset_va_context` returns the target asset, its open vulnerability
  count, maximum CVSS, number with a public exploit and top 5 by priority. The risk score adds the asset
  criticality points and +8 for an exploitable vulnerability (or +5 if the maximum CVSS is >= 9). The AI
  context includes this posture, so the analyst sees, for example, that a Log4Shell alert hit a host with
  an open CVE-2021-44228 finding.
- **Alert -> VA:** the `+10` term in the priority formula raises every finding on an asset that has open
  alerts, so an asset under active attack rises in the remediation queue.

Both values are calculated at the moment of analysis or reprioritisation; they are not recalculated in the
background (see the limitations in the project report).

## 5b. Keeping alerts and VA data in sync

The alert-to-VA link runs both ways, so `services/sync.py` recalculates the other side whenever one changes:

| Change | Recalculated |
|---|---|
| Findings import, Nmap import, asset criticality change, finding status change | the asset's finding priorities, then the risk score, enrichment and VA snapshot of every open alert on that asset |
| Alert ingest, alert status change, case resolved/closed (closes its alerts) | the "+10 asset has open alerts" priority term of the affected assets' findings, then those assets' open alerts so their stored VA snapshot matches |

An alert maps to an asset by the same rule as its VA context: host name, then destination IP, then an
internal source IP. API responses for VA imports include `alerts_rescored`. Re-scoring does not re-run the
AI verdict; the analyst runs a new investigation when they want a fresh one.

## 6. Security controls

| Control | Where |
|---|---|
| Authentication: OAuth2 password form -> JWT HS256 bearer token (`sub`, `role`, `iat`, `exp`), default lifetime 480 minutes | `security.py`, `api/auth.py` |
| User re-loaded and `is_active` checked on every request | `security.get_current_user` |
| RBAC: `any_user`, `analyst_or_admin`, `admin_only` dependencies on each route | `api/*.py` |
| PBKDF2-SHA256, 310,000 iterations, random salt, `hmac.compare_digest` | `security.py` |
| Production refuses to start with a default, short (< 32) or common `JWT_SECRET`; warns about default demo passwords | `config.Settings.validate` |
| Audit log of logins, failed logins, lockouts and every write and AI call | `security.audit` |
| Login throttling: 5 failures per username / 20 per client IP in a 15-minute sliding window -> `429` + `Retry-After`, checked before the password | `ratelimit.py`, `api/auth.py` |
| Strict request schemas (`extra="forbid"`, length limits, enums) | `schemas.py` |
| Upload limits: 20 MB alert files, 1,000 alerts per request, 10 MB Nmap XML, 5,000 findings per request | `config.py` |
| XXE / entity-expansion rejection for XML | `vuln.parse_nmap` |
| Prompt fencing, strict JSON, output whitelists and caps | `ai_engine.py` |
| Simulated response actions only | `api/cases.run_action` |
| Headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`, `Cache-Control: no-store` on `/api/*` | `main.security_headers` |
| Generic 500 response (stack traces only in server logs) | `main.unhandled` |
| CORS only outside production (for the Vite dev server) | `main.py` |
| Static files: resolved path must stay inside the static directory | `main.spa` |
| Container runs as non-root user (uid 10001) | `Dockerfile` |

## 7. Extension points

- **VirusTotal / external TI enrichment.** Add a lookup in `enrichment.enrich_ioc` after the local feed
  miss (with caching and rate limiting, and the API key from an environment variable). The rest of the
  pipeline only reads `reputation`, `score` and `tags`.
- **Real EDR / firewall actions.** `api/cases.run_action` is the single place where actions are recorded.
  A connector (CrowdStrike, Defender for Endpoint, a firewall API) would be called there, behind an explicit
  approval step, with the result written to `ResponseAction.status`.
- **Sigma rule import.** Sigma rules carry ATT&CK tags; a loader could add their detection keywords and
  technique ids to the technique catalogue used by `mitre.map_techniques`.
- **SOAR webhooks.** Emit a signed webhook from `investigate_case` or `run_action` so that a SOAR platform
  (for example Shuffle or TheHive/Cortex) can pick up cases and run its own playbooks.
- **New alert sources.** Add a parser function to `normalizer.PARSERS` and a rule to `detect_format`.
- **New AI provider.** Add a branch to `ai_engine._llm_complete`; validation and fallback are shared.
