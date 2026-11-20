from collections import Counter
from datetime import timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import Alert, Case, User, Vulnerability, utcnow
from ..schemas import alert_summary
from ..security import get_current_user
from ..services.mitre import TACTICS, attack_url, technique_catalog
from ..services.playbooks import load_playbooks

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/dashboard")
def dashboard(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    alerts = db.query(Alert).all()
    now = utcnow()
    open_alerts = [a for a in alerts if a.status != "closed"]

    done_cases = db.query(Case).filter(Case.closed_at.isnot(None)).all()
    mttr = None
    if done_cases:
        mttr = round(sum((c.closed_at - c.created_at).total_seconds() for c in done_cases) / len(done_cases) / 3600, 1)

    days = []
    for i in range(6, -1, -1):
        day = (now - timedelta(days=i)).date()
        day_alerts = [a for a in alerts if a.event_time and a.event_time.date() == day]
        days.append(
            {
                "date": day.isoformat(),
                "count": len(day_alerts),
                "high": sum(1 for a in day_alerts if a.severity in ("high", "critical")),
            }
        )

    techniques: Counter = Counter()
    names: dict[str, dict] = {}
    tactics: Counter = Counter()
    iocs: Counter = Counter()
    ioc_meta: dict[str, dict] = {}
    for a in alerts:
        seen_tactics = set()
        for t in a.mitre or []:
            techniques[t["id"]] += 1
            names[t["id"]] = t
            seen_tactics.add(t["tactic"])
        for t in seen_tactics:
            tactics[t] += 1
        for i in a.iocs or []:
            if i.get("reputation") == "malicious":
                iocs[i["value"]] += 1
                ioc_meta[i["value"]] = i

    open_vulns = (
        db.query(func.count(Vulnerability.id)).filter(Vulnerability.status.in_(("open", "in_progress"))).scalar()
    )
    return {
        "kpis": {
            "total_alerts": len(alerts),
            "open_alerts": len(open_alerts),
            "critical_open": sum(1 for a in open_alerts if a.severity == "critical"),
            "open_cases": db.query(func.count(Case.id)).filter(Case.status.notin_(("resolved", "closed"))).scalar(),
            "mttr_hours": mttr,
            "open_vulns": open_vulns,
            "exploitable_vulns": db.query(func.count(Vulnerability.id))
            .filter(Vulnerability.status.in_(("open", "in_progress")), Vulnerability.exploit_available.is_(True))
            .scalar(),
            "true_positives": sum(1 for a in alerts if a.verdict == "true_positive"),
        },
        "alerts_7d": days,
        "by_severity": {
            s: sum(1 for a in open_alerts if a.severity == s) for s in ("critical", "high", "medium", "low")
        },
        "by_verdict": dict(Counter(a.verdict for a in alerts)),
        "top_risk": [alert_summary(a) for a in sorted(open_alerts, key=lambda a: -a.risk_score)[:8]],
        "top_techniques": [
            {"id": tid, "name": names[tid]["name"], "tactic": names[tid]["tactic"], "count": n, "url": attack_url(tid)}
            for tid, n in techniques.most_common(8)
        ],
        "tactics": [{"tactic": t, "count": tactics.get(t, 0)} for t in TACTICS],
        "top_iocs": [
            {
                "value": v,
                "type": ioc_meta[v]["type"],
                "count": n,
                "score": ioc_meta[v].get("score", 0),
                "tags": ioc_meta[v].get("tags", []),
            }
            for v, n in iocs.most_common(8)
        ],
        "sources": [{"source": s, "count": n} for s, n in Counter(a.source for a in alerts).most_common()],
        "ai_provider": settings.ai_provider,
    }


@router.get("/mitre")
def mitre(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    counts: Counter = Counter()
    for (m,) in db.query(Alert.mitre).all():
        for t in m or []:
            counts[t["id"]] += 1
    catalog = technique_catalog()
    for t in catalog:
        t["alert_count"] = counts.get(t["id"], 0)
        t["url"] = attack_url(t["id"])
    return {"tactics": TACTICS, "techniques": catalog}


@router.get("/playbooks")
def playbooks(_: User = Depends(get_current_user)):
    return load_playbooks()
