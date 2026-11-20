"""Demo data: users, assets + vulnerabilities, 20 alerts in four attack chains plus noise, and two cases.

All indicators are documentation-safe: RFC 5737 IPs, .example domains and well-known test hashes.
Seeding never calls an external AI provider (it uses the offline analyst).
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from sqlalchemy.orm import Session

from .config import settings
from .models import Alert, Asset, AuditLog, Case, CaseNote, ResponseAction, User, utcnow
from .security import hash_password
from .services import ai_engine
from .services.normalizer import normalize
from .services.pipeline import analyze_alert, build_alert_context, build_case_context, process_alert
from .services.vuln import import_findings, reprioritize_asset

DATA = Path(__file__).resolve().parent / "data"
NOT_PRE_TRIAGED = {"web-exploit"}  # leave these for the analyst to investigate live in the demo


def seed_if_empty(db: Session) -> bool:
    if db.query(User).first():
        return False
    seed(db)
    return True


def seed(db: Session) -> None:
    db.add_all(
        [
            User(
                username="admin",
                full_name="SOC Administrator",
                role="admin",
                password_hash=hash_password(settings.admin_password),
            ),
            User(
                username="analyst",
                full_name="Tier-2 SOC Analyst",
                role="analyst",
                password_hash=hash_password(settings.analyst_password),
            ),
            User(
                username="viewer",
                full_name="SOC Manager (read-only)",
                role="viewer",
                password_hash=hash_password(settings.viewer_password),
            ),
        ]
    )

    va = json.loads((DATA / "sample_vulns.json").read_text(encoding="utf-8"))
    for a in va["assets"]:
        db.add(Asset(**a, last_scanned=utcnow() - timedelta(days=2)))
    db.flush()
    import_findings(db, va["findings"])

    now = utcnow()
    raw_alerts = json.loads((DATA / "sample_alerts.json").read_text(encoding="utf-8"))
    alerts: list[tuple[str, Alert]] = []
    for item in raw_alerts:
        raw = {k: v for k, v in item.items() if k not in ("chain", "offset_minutes")}
        raw["timestamp"] = (now - timedelta(minutes=item["offset_minutes"])).isoformat() + "Z"
        alert = process_alert(db, normalize(raw, "generic"))
        alert.created_at = alert.event_time
        alerts.append((item["chain"], alert))
    db.flush()

    for asset in db.query(Asset).all():  # assets now have open alerts -> "+10" priority term
        reprioritize_asset(db, asset)
    db.flush()
    for _, alert in alerts:  # second pass: symmetric correlation + VA snapshot with final priorities
        analyze_alert(db, alert)
    for chain, alert in alerts:
        if chain in NOT_PRE_TRIAGED or alert.title.startswith(("Sign-in from Tor", "User added to Domain Admins")):
            continue
        alert.ai_report = ai_engine.offline_investigate(build_alert_context(db, alert))
        alert.verdict = alert.ai_report["verdict"]
        alert.status = "triaged"

    # Case 1: the phishing -> exfiltration chain, investigated, one note, host isolated.
    chain1 = [a for c, a in alerts if c == "phishing-to-exfil"]
    case1 = Case(
        title="Phishing to credential theft, C2 and exfiltration (finance-ws-07 -> fs-01)",
        summary="Macro phishing led to PowerShell, Mimikatz, Cobalt Strike beaconing, RDP to fs-01 and a 2.3 GB upload.",
        severity="critical",
        status="investigating",
        assignee="analyst",
        created_by="analyst",
        created_at=chain1[0].event_time + timedelta(minutes=20),
    )
    case1.alerts = chain1
    for a in chain1:
        a.status = "investigating"
    db.add(case1)
    db.flush()
    case1.ai_report = ai_engine.offline_investigate(build_case_context(db, case1))
    case1.notes.append(
        CaseNote(
            author="analyst",
            content="User confirms she opened the 'invoice' attachment. Finance manager informed. Waiting for EDR memory image.",
            created_at=chain1[0].event_time + timedelta(minutes=50),
        )
    )
    case1.actions.append(
        ResponseAction(
            action="isolate_host",
            target="finance-ws-07",
            performed_by="analyst",
            status="simulated",
            details="Host network-isolated via EDR (simulated)",
            created_at=chain1[0].event_time + timedelta(minutes=55),
        )
    )
    case1.status = "contained"

    # Case 2: EICAR awareness test - closed false positive (gives the dashboard an MTTR).
    eicar = next(a for c, a in alerts if c == "eicar")
    case2 = Case(
        title="EICAR test file on it-ws-01 (awareness exercise)",
        summary="Antivirus detection of the EICAR test string during the IT awareness test.",
        severity="low",
        status="closed",
        assignee="analyst",
        created_by="analyst",
        created_at=eicar.event_time + timedelta(minutes=10),
    )
    case2.alerts = [eicar]
    db.add(case2)
    db.flush()
    case2.ai_report = ai_engine.offline_investigate(build_case_context(db, case2))
    case2.notes.append(
        CaseNote(
            author="analyst",
            content="Confirmed with the IT training team: scheduled awareness test. Closing as false positive / benign.",
            created_at=eicar.event_time + timedelta(hours=2),
        )
    )
    case2.closed_at = eicar.event_time + timedelta(hours=2, minutes=30)
    eicar.status = "closed"
    eicar.verdict = "false_positive"

    db.add(
        AuditLog(actor="system", action="demo_data_seeded", entity="system", details=f"{len(alerts)} alerts, 2 cases")
    )
    db.commit()
