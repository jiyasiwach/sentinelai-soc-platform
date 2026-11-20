"""API tests: auth/RBAC, ingest -> investigate, filters, correlation, uploads, case life cycle, VA, admin."""

import json

import pytest


def test_health_and_security_headers(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"


@pytest.mark.parametrize(
    "path", ["/api/alerts", "/api/cases", "/api/dashboard", "/api/va/assets", "/api/auth/me", "/api/mitre"]
)
def test_requires_auth(client, path):
    assert client.get(path).status_code == 401
    assert client.get(path, headers={"Authorization": "Bearer not-a-token"}).status_code == 401


def test_login_failure_is_audited(client, admin):
    assert client.post("/api/auth/login", data={"username": "analyst", "password": "wrong-password"}).status_code == 401
    audit = client.get("/api/auth/audit", headers=admin).json()
    assert any(a["action"] == "login_failed" and a["actor"] == "analyst" for a in audit)


def test_me(client, analyst):
    me = client.get("/api/auth/me", headers=analyst).json()
    assert me["username"] == "analyst" and me["role"] == "analyst" and "password_hash" not in me


def test_viewer_is_read_only(client, viewer):
    assert client.get("/api/alerts", headers=viewer).status_code == 200
    forbidden = [
        ("post", "/api/alerts/ingest", {"alerts": [{"title": "x"}]}),
        ("patch", "/api/alerts/1", {"status": "closed"}),
        ("post", "/api/alerts/1/investigate", None),
        ("post", "/api/cases", {"title": "nope", "alert_ids": []}),
        ("post", "/api/cases/1/notes", {"content": "hi"}),
        ("post", "/api/cases/1/actions", {"action": "block_ip", "target": "203.0.113.9"}),
        ("post", "/api/cases/1/chat", {"message": "hi"}),
        ("patch", "/api/va/assets/1", {"criticality": "low"}),
        ("post", "/api/cases/auto-group", None),
    ]
    for method, path, body in forbidden:
        r = (
            getattr(client, method)(path, headers=viewer, json=body)
            if body is not None
            else getattr(client, method)(path, headers=viewer)
        )
        assert r.status_code == 403, (method, path, r.status_code)


def test_seeded_demo_data(client, analyst):
    alerts = client.get("/api/alerts?limit=500", headers=analyst).json()
    assert alerts["total"] >= 20
    cases = client.get("/api/cases", headers=analyst).json()
    by_title = {c["title"]: c for c in cases}
    case1 = next(c for t, c in by_title.items() if t.startswith("Phishing to credential theft"))
    assert case1["status"] == "contained" and case1["alert_count"] == 6 and case1["verdict"] == "true_positive"
    detail = client.get(f"/api/cases/{case1['id']}", headers=analyst).json()
    assert len(detail["notes"]) == 1 and detail["actions"][0]["action"] == "isolate_host"
    dash = client.get("/api/dashboard", headers=analyst).json()
    assert dash["kpis"]["mttr_hours"] is not None and dash["kpis"]["open_vulns"] >= 9
    assert len(dash["alerts_7d"]) == 7 and len(dash["tactics"]) == 12
    assert any(i["value"] == "203.0.113.45" for i in dash["top_iocs"])


def test_ingest_then_investigate(client, analyst):
    payload = {
        "format": "generic",
        "alerts": [
            {
                "title": "Cobalt Strike beacon detected",
                "severity": "high",
                "host": "web-01",
                "user": "deploy",
                "src_ip": "10.10.10.5",
                "dst_ip": "203.0.113.45",
                "description": "HTTPS beacon to cdn-sync.example every 60 seconds (command and control)",
            }
        ],
    }
    r = client.post("/api/alerts/ingest", headers=analyst, json=payload)
    assert r.status_code == 201, r.text
    alert = r.json()["alerts"][0]
    assert alert["verdict"] == "pending" and alert["risk_score"] > 60
    detail = client.get(f"/api/alerts/{alert['id']}", headers=analyst).json()
    assert detail["enrichment"]["asset"]["asset"]["hostname"] == "web-01"
    assert any(r["reason"].startswith("Late kill-chain") for r in detail["enrichment"]["risk_reasons"])
    assert sum(r["points"] for r in detail["enrichment"]["risk_reasons"]) == detail["risk_score"]
    inv = client.post(f"/api/alerts/{alert['id']}/investigate", headers=analyst).json()
    assert inv["verdict"] == "true_positive" and inv["ai_report"]["engine"] == "offline"
    assert any(
        a["action"] == "block_ip" and a["target"] == "203.0.113.45" for a in inv["ai_report"]["recommended_actions"]
    )
    assert inv["status"] == "triaged"


def test_ingest_wazuh_auto_detect_and_errors(client, analyst):
    raw = {
        "rule": {
            "level": 12,
            "description": "Multiple authentication failures - brute force",
            "groups": ["authentication_failures"],
        },
        "agent": {"name": "dc-01"},
        "data": {"srcip": "198.51.100.77", "dstuser": "administrator"},
    }
    r = client.post("/api/alerts/ingest", headers=analyst, json={"alerts": [raw, "not-an-object"]})
    body = r.json()
    assert r.status_code == 201 and body["ingested"] == 1 and len(body["errors"]) == 1
    assert body["alerts"][0]["source"] == "wazuh" and body["alerts"][0]["severity"] == "critical"


def test_ingest_limit(client, analyst):
    r = client.post("/api/alerts/ingest", headers=analyst, json={"alerts": [{"title": "x"}] * 1001})
    assert r.status_code == 413


def test_alert_filters_and_sort(client, analyst):
    crit = client.get("/api/alerts?severity=critical", headers=analyst).json()
    assert crit["total"] > 0 and all(a["severity"] == "critical" for a in crit["items"])
    q = client.get("/api/alerts?q=mimikatz", headers=analyst).json()
    assert q["total"] >= 1 and any("Mimikatz" in a["title"] for a in q["items"])
    host = client.get("/api/alerts?host=hr-ws-03", headers=analyst).json()
    assert host["total"] == 3
    risk = [a["risk_score"] for a in client.get("/api/alerts?sort=risk&limit=50", headers=analyst).json()["items"]]
    assert risk == sorted(risk, reverse=True)
    page = client.get("/api/alerts?limit=5&offset=5", headers=analyst).json()
    assert len(page["items"]) == 5
    tp = client.get("/api/alerts?verdict=true_positive", headers=analyst).json()
    assert all(a["verdict"] == "true_positive" for a in tp["items"])


def test_correlation(client, analyst):
    items = client.get("/api/alerts?q=Mimikatz", headers=analyst).json()["items"]
    mimikatz = next(a for a in items if a["title"].startswith("Credential dumping"))
    related = client.get(f"/api/alerts/{mimikatz['id']}/related", headers=analyst).json()
    assert related and all(r["reasons"] for r in related)
    assert any("same host finance-ws-07" in " ".join(r["reasons"]) for r in related)


def test_jsonl_upload(client, analyst):
    lines = "\n".join(
        json.dumps(
            {
                "title": f"Failed logon burst {i}",
                "severity": "medium",
                "host": "jsonl-host",
                "user": "svc_test",
                "description": "multiple failed logon events",
            }
        )
        for i in range(3)
    )
    r = client.post(
        "/api/alerts/upload",
        headers=analyst,
        files={"file": ("alerts.jsonl", lines, "application/x-ndjson")},
        data={"format": "generic", "investigate": "true"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["ingested"] == 3 and all(a["verdict"] != "pending" for a in body["alerts"])
    bad = client.post(
        "/api/alerts/upload", headers=analyst, files={"file": ("x.json", "{not json", "application/json")}
    )
    assert bad.status_code == 422


def test_case_life_cycle(client, analyst, admin):
    ids = [a["id"] for a in client.get("/api/alerts?host=web-01&sort=time", headers=analyst).json()["items"][:2]]
    r = client.post("/api/cases", headers=analyst, json={"title": "Web-01 investigation", "alert_ids": ids})
    assert r.status_code == 201
    case = r.json()
    assert case["status"] == "open" and len(case["alerts"]) == 2

    case = client.post(f"/api/cases/{case['id']}/investigate", headers=analyst).json()
    assert case["status"] == "investigating" and case["ai_report"]["verdict"] in (
        "true_positive",
        "needs_review",
        "benign",
        "false_positive",
    )

    case = client.post(f"/api/cases/{case['id']}/notes", headers=analyst, json={"content": "Checked WAF logs."}).json()
    assert case["notes"][-1]["content"] == "Checked WAF logs."

    chat = client.post(
        f"/api/cases/{case['id']}/chat", headers=analyst, json={"message": "Which IOCs should we block?"}
    ).json()
    assert chat["engine"] == "offline" and chat["answer"] and len(chat["chat"]) == 2

    bad = client.post(
        f"/api/cases/{case['id']}/actions", headers=analyst, json={"action": "format_disk", "target": "web-01"}
    )
    assert bad.status_code == 422
    case = client.post(
        f"/api/cases/{case['id']}/actions", headers=analyst, json={"action": "block_ip", "target": "192.0.2.66"}
    ).json()
    assert case["status"] == "contained" and case["actions"][-1]["status"] == "simulated"

    rep = client.get(f"/api/cases/{case['id']}/report", headers=analyst)
    assert (
        rep.status_code == 200
        and rep.text.startswith("# Incident Report")
        and "attachment" in rep.headers["content-disposition"]
    )

    case = client.patch(f"/api/cases/{case['id']}", headers=analyst, json={"status": "resolved"}).json()
    assert case["closed_at"] and all(a["status"] == "closed" for a in case["alerts"])

    assert client.delete(f"/api/cases/{case['id']}", headers=analyst).status_code == 403
    assert client.delete(f"/api/cases/{case['id']}", headers=admin).status_code == 204
    assert client.get(f"/api/cases/{case['id']}", headers=analyst).status_code == 404


def test_auto_group(client, analyst):
    r = client.post("/api/cases/auto-group", headers=analyst)
    assert r.status_code == 201
    created = r.json()
    assert created["created"] >= 2  # ssh brute-force chain and ransomware chain at minimum
    titles = " | ".join(c["title"] for c in created["cases"])
    assert "Ransomware" in titles or "Shadow" in titles
    again = client.post("/api/cases/auto-group", headers=analyst).json()
    assert again["created"] == 0  # alerts already grouped are not re-grouped


def test_va_import_and_priority(client, analyst):
    findings = {
        "findings": [
            {
                "host": "pentest-box-01",
                "ip": "10.10.77.7",
                "title": "Default Tomcat manager credentials",
                "cvss": 9.8,
                "port": 8080,
                "service": "http",
                "exploit_available": True,
                "source": "pentest",
                "remediation": "Change credentials",
            },
            {"host": "pentest-box-01", "title": "TLS 1.0 enabled", "cvss": 4.3, "port": 443, "source": "nessus"},
        ]
    }
    r = client.post("/api/va/vulnerabilities", headers=analyst, json=findings)
    assert r.status_code == 201 and r.json() == {
        "findings_created": 2,
        "findings_updated": 0,
        "assets_created": 1,
        "alerts_rescored": 0,
    }
    r2 = client.post("/api/va/vulnerabilities", headers=analyst, json=findings)
    assert r2.json()["findings_updated"] == 2  # upsert by host + title + port
    vulns = [v for v in client.get("/api/va/vulnerabilities", headers=analyst).json() if v["asset"] == "pentest-box-01"]
    tomcat = next(v for v in vulns if v["title"].startswith("Default Tomcat"))
    assert tomcat["severity"] == "critical" and tomcat["priority_score"] == round(9.8 * 7 * 1.0 + 12, 1)

    asset = next(a for a in client.get("/api/va/assets", headers=analyst).json() if a["hostname"] == "pentest-box-01")
    client.patch(f"/api/va/assets/{asset['id']}", headers=analyst, json={"criticality": "low"})
    tomcat2 = next(v for v in client.get("/api/va/vulnerabilities", headers=analyst).json() if v["id"] == tomcat["id"])
    assert tomcat2["priority_score"] == round(9.8 * 7 * 0.7 + 12, 1)

    v = client.patch(f"/api/va/vulnerabilities/{tomcat['id']}", headers=analyst, json={"status": "fixed"}).json()
    assert v["status"] == "fixed"


def test_nmap_import_and_xxe_rejection(client, analyst):
    xml = b"""<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host><status state="up"/>
    <address addr="10.10.88.8" addrtype="ipv4"/><hostnames><hostname name="cache-01"/></hostnames>
    <ports><port protocol="tcp" portid="6379"><state state="open"/><service name="redis"/></port></ports></host></nmaprun>"""
    r = client.post("/api/va/import/nmap", headers=analyst, files={"file": ("scan.xml", xml, "application/xml")})
    assert r.status_code == 201 and r.json()["findings_created"] == 1
    assert any(
        v["title"].startswith("Redis exposed") for v in client.get("/api/va/vulnerabilities", headers=analyst).json()
    )
    evil = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun>&x;</nmaprun>'
    r = client.post("/api/va/import/nmap", headers=analyst, files={"file": ("evil.xml", evil, "application/xml")})
    assert r.status_code == 422 and "entit" in r.json()["detail"].lower()


def test_va_raises_alert_risk(client, analyst):
    alert = {
        "title": "Suspicious process on lab host",
        "severity": "medium",
        "host": "lab-77",
        "description": "unusual binary started",
    }
    before = client.post("/api/alerts/ingest", headers=analyst, json={"alerts": [alert]}).json()["alerts"][0][
        "risk_score"
    ]
    client.post(
        "/api/va/vulnerabilities",
        headers=analyst,
        json={
            "findings": [
                {
                    "host": "lab-77",
                    "title": "Critical RCE in agent",
                    "cvss": 9.9,
                    "exploit_available": True,
                    "source": "nessus",
                }
            ]
        },
    )
    asset = next(a for a in client.get("/api/va/assets", headers=analyst).json() if a["hostname"] == "lab-77")
    client.patch(f"/api/va/assets/{asset['id']}", headers=analyst, json={"criticality": "critical"})
    after_alert = client.post("/api/alerts/ingest", headers=analyst, json={"alerts": [alert]}).json()["alerts"][0]
    assert after_alert["risk_score"] >= before + 10 + 8  # criticality +10, exploitable vuln +8
    detail = client.get(f"/api/alerts/{after_alert['id']}", headers=analyst).json()
    assert detail["enrichment"]["asset"]["exploitable_count"] == 1


def test_admin_only_endpoints(client, admin, analyst):
    assert client.get("/api/auth/users", headers=analyst).status_code == 403
    assert client.get("/api/auth/audit", headers=analyst).status_code == 403
    users = client.get("/api/auth/users", headers=admin).json()
    assert {u["username"] for u in users} >= {"admin", "analyst", "viewer"}
    r = client.post(
        "/api/auth/users",
        headers=admin,
        json={"username": "tier1", "full_name": "Tier 1", "role": "viewer", "password": "Str0ng-Passw0rd!"},
    )
    assert r.status_code == 201 and r.json()["role"] == "viewer"
    assert (
        client.post(
            "/api/auth/users",
            headers=admin,
            json={"username": "tier1", "role": "viewer", "password": "Str0ng-Passw0rd!"},
        ).status_code
        == 409
    )
    assert (
        client.post(
            "/api/auth/users", headers=admin, json={"username": "weak", "role": "viewer", "password": "short"}
        ).status_code
        == 422
    )
    assert client.post("/api/auth/login", data={"username": "tier1", "password": "Str0ng-Passw0rd!"}).status_code == 200
    audit = client.get("/api/auth/audit", headers=admin).json()
    assert any(a["action"] == "user_created" for a in audit)


def test_catalogues(client, viewer):
    mitre = client.get("/api/mitre", headers=viewer).json()
    assert len(mitre["tactics"]) == 12 and len(mitre["techniques"]) >= 30
    assert {t["tactic"] for t in mitre["techniques"]} == set(mitre["tactics"])
    pbs = client.get("/api/playbooks", headers=viewer).json()
    assert len(pbs) >= 6 and all(p["steps"] for p in pbs)


def test_unknown_alert_404(client, analyst):
    assert client.get("/api/alerts/999999", headers=analyst).status_code == 404


SAMPLES = __import__("pathlib").Path(__file__).resolve().parents[2] / "sample-data"


@pytest.mark.parametrize(
    "name,source",
    [
        ("wazuh_alerts.json", "wazuh"),
        ("splunk_alerts.json", "splunk"),
        ("elastic_alerts.json", "elastic"),
        ("generic_alerts.jsonl", None),
    ],
)
def test_sample_alert_files_ingest(client, analyst, name, source):
    path = SAMPLES / name
    r = client.post(
        "/api/alerts/upload",
        headers=analyst,
        files={"file": (name, path.read_bytes(), "application/json")},
        data={"format": "auto", "investigate": "true"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["ingested"] >= 2 and not body["errors"]
    if source:
        assert all(a["source"] == source for a in body["alerts"])
    assert all(a["title"] and a["host"] for a in body["alerts"])


def test_sample_va_files_import(client, analyst):
    r = client.post(
        "/api/va/import/nmap",
        headers=analyst,
        files={"file": ("nmap_scan.xml", (SAMPLES / "nmap_scan.xml").read_bytes(), "application/xml")},
    )
    assert r.status_code == 201, r.text
    assert r.json()["hosts"] == 3
    assert (
        r.json()["findings_created"] + r.json()["findings_updated"] == 6
    )  # FTP, Telnet, Redis, Elasticsearch, RDP, VNC
    r = client.post(
        "/api/va/vulnerabilities", headers=analyst, json=json.loads((SAMPLES / "va_findings.json").read_text())
    )
    assert r.status_code == 201, r.text
    assert r.json()["findings_created"] + r.json()["findings_updated"] == 5


def test_spa_fallback_and_traversal(client):
    from app.main import _static_dir

    if _static_dir() is None:
        pytest.skip("frontend not built")
    r = client.get("/alerts/3")
    assert r.status_code == 200 and '<div id="root">' in r.text
    assert client.get("/api/does-not-exist").status_code == 404
    assert "root:" not in client.get("/..%2F..%2F..%2F..%2Fetc%2Fpasswd").text


# ------------------------------------------------------------------ alert <-> VA stay in sync
def _alert(client, headers, alert_id):
    return client.get(f"/api/alerts/{alert_id}", headers=headers).json()


def test_va_change_rescores_existing_alerts(client, analyst):
    alert = client.post(
        "/api/alerts/ingest",
        headers=analyst,
        json={
            "alerts": [
                {
                    "title": "Odd service crash",
                    "severity": "medium",
                    "host": "sync-01",
                    "description": "service restarted unexpectedly",
                }
            ]
        },
    ).json()["alerts"][0]
    before = _alert(client, analyst, alert["id"])
    assert before["enrichment"]["asset"] is None

    r = client.post(
        "/api/va/vulnerabilities",
        headers=analyst,
        json={
            "findings": [
                {
                    "host": "sync-01",
                    "title": "Unauthenticated RCE in agent",
                    "cvss": 9.8,
                    "exploit_available": True,
                    "source": "pentest",
                }
            ]
        },
    )
    assert r.status_code == 201 and r.json()["alerts_rescored"] == 1
    after = _alert(client, analyst, alert["id"])
    assert after["enrichment"]["asset"]["exploitable_count"] == 1
    assert after["risk_score"] == before["risk_score"] + 3 + 8  # medium asset +3, exploitable vuln +8

    asset = next(a for a in client.get("/api/va/assets", headers=analyst).json() if a["hostname"] == "sync-01")
    client.patch(f"/api/va/assets/{asset['id']}", headers=analyst, json={"criticality": "critical"})
    assert _alert(client, analyst, alert["id"])["risk_score"] == before["risk_score"] + 10 + 8

    vuln = next(v for v in client.get(f"/api/va/vulnerabilities?asset_id={asset['id']}", headers=analyst).json())
    client.patch(f"/api/va/vulnerabilities/{vuln['id']}", headers=analyst, json={"status": "fixed"})
    fixed = _alert(client, analyst, alert["id"])
    assert fixed["enrichment"]["asset"]["exploitable_count"] == 0
    assert fixed["risk_score"] == before["risk_score"] + 10  # criticality stays, exploit bonus gone
    assert any("Target asset sync-01 is critical" in r["reason"] for r in fixed["enrichment"]["risk_reasons"])


def test_alert_status_changes_vuln_priority(client, analyst):
    client.post(
        "/api/va/vulnerabilities",
        headers=analyst,
        json={"findings": [{"host": "sync-02", "title": "Outdated OpenSSL", "cvss": 5.0, "source": "nessus"}]},
    )
    vuln = next(v for v in client.get("/api/va/vulnerabilities", headers=analyst).json() if v["asset"] == "sync-02")
    assert vuln["priority_score"] == 35.0  # 5.0 x 7 x 1.0, no open alerts

    alert = client.post(
        "/api/alerts/ingest",
        headers=analyst,
        json={"alerts": [{"title": "Suspicious login", "severity": "low", "host": "sync-02"}]},
    ).json()["alerts"][0]
    v_open = next(v for v in client.get("/api/va/vulnerabilities", headers=analyst).json() if v["id"] == vuln["id"])
    assert v_open["priority_score"] == 45.0 and "+10 asset has open alerts" in v_open["priority_explained"]
    snap = _alert(client, analyst, alert["id"])["enrichment"]["asset"]["top_vulns"][0]
    assert snap["priority_score"] == 45.0  # the alert's stored snapshot matches the VA page

    case = client.post(
        "/api/cases", headers=analyst, json={"title": "sync-02 check", "alert_ids": [alert["id"]]}
    ).json()
    client.patch(f"/api/cases/{case['id']}", headers=analyst, json={"status": "resolved"})
    v_closed = next(v for v in client.get("/api/va/vulnerabilities", headers=analyst).json() if v["id"] == vuln["id"])
    assert v_closed["priority_score"] == 35.0  # resolving the case closed the alert -> +10 removed

    client.patch(f"/api/alerts/{alert['id']}", headers=analyst, json={"status": "investigating"})
    reopened = next(v for v in client.get("/api/va/vulnerabilities", headers=analyst).json() if v["id"] == vuln["id"])
    assert reopened["priority_score"] == 45.0


def test_seeded_alert_va_snapshots_match_va_page(client, analyst):
    vulns = {v["id"]: v["priority_score"] for v in client.get("/api/va/vulnerabilities", headers=analyst).json()}
    items = client.get("/api/alerts?host=web-01&status=new,triaged,investigating&limit=50", headers=analyst).json()[
        "items"
    ]
    assert items
    for a in items:
        for v in _alert(client, analyst, a["id"])["enrichment"]["asset"]["top_vulns"]:
            assert v["priority_score"] == vulns[v["id"]]


# ------------------------------------------------------------------ login throttling
@pytest.fixture
def fresh_throttle():
    from app.ratelimit import login_throttle

    login_throttle.reset()
    yield login_throttle
    login_throttle.reset()


def test_login_lockout_per_username(client, admin, fresh_throttle):
    client.post(
        "/api/auth/users", headers=admin, json={"username": "lockme", "role": "viewer", "password": "Correct-Horse-9"}
    )
    for _ in range(5):
        assert client.post("/api/auth/login", data={"username": "lockme", "password": "wrong-guess"}).status_code == 401
    r = client.post("/api/auth/login", data={"username": "lockme", "password": "Correct-Horse-9"})
    assert r.status_code == 429  # locked: even the right password is refused
    assert 0 < int(r.headers["Retry-After"]) <= 15 * 60 and "Too many failed login attempts" in r.json()["detail"]
    # other accounts from the same client are unaffected (IP limit is higher)
    assert client.post("/api/auth/login", data={"username": "viewer", "password": "Viewer@12345"}).status_code == 200
    audit = client.get("/api/auth/audit", headers=admin).json()
    assert any(a["action"] == "login_locked" and a["actor"] == "lockme" for a in audit)


def test_successful_login_clears_failures(client, fresh_throttle):
    for _ in range(4):
        client.post("/api/auth/login", data={"username": "viewer", "password": "nope"})
    assert client.post("/api/auth/login", data={"username": "viewer", "password": "Viewer@12345"}).status_code == 200
    for _ in range(4):
        assert client.post("/api/auth/login", data={"username": "viewer", "password": "nope"}).status_code == 401
