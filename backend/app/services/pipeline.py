"""Alert pipeline: normalise -> extract IOCs -> enrich -> ATT&CK -> VA context -> correlate -> score (-> AI)."""

from __future__ import annotations

import json

from sqlalchemy.orm import Session

from ..models import Alert, Case
from . import ai_engine
from .correlation import find_related
from .enrichment import _string_values, enrich_iocs, extract_iocs, summarize_ti
from .mitre import map_techniques
from .playbooks import rank_playbooks
from .scoring import compute_risk
from .vuln import asset_va_context

ALERT_FIELDS = (
    "external_id",
    "source",
    "title",
    "description",
    "severity",
    "category",
    "host",
    "username",
    "src_ip",
    "dst_ip",
    "event_time",
    "raw",
)


def _raw_text(raw) -> str:
    values: list[str] = []
    _string_values(raw, values)
    return " ".join(values)[:20000]


def analysis_text(alert: Alert) -> str:
    return " ".join([alert.title or "", alert.description or "", alert.category or "", _raw_text(alert.raw)])


def analyze_alert(db: Session, alert: Alert) -> Alert:
    iocs = enrich_iocs(extract_iocs(alert.title, alert.description, alert.src_ip, alert.dst_ip, alert.raw))
    text = analysis_text(alert)
    techniques = map_techniques(text)
    va = asset_va_context(db, alert.host, alert.dst_ip, alert.src_ip)
    related = find_related(db, alert)
    score, reasons = compute_risk(alert.severity, iocs, techniques, va, len(related))
    playbooks = rank_playbooks(techniques, text)
    alert.iocs = iocs
    alert.mitre = techniques
    alert.risk_score = score
    alert.enrichment = {
        "ti_summary": summarize_ti(iocs),
        "asset": va,
        "risk_reasons": reasons,
        "related": [{"id": r.id, "title": r.title, "reasons": why} for r, why in related[:10]],
        "playbooks": [{"id": p["id"], "name": p["name"], "score": p["score"]} for p in playbooks],
    }
    return alert


def process_alert(db: Session, normalized: dict, run_ai: bool = False) -> Alert:
    alert = Alert(**{k: normalized[k] for k in ALERT_FIELDS if k in normalized})
    alert.severity = alert.severity or "medium"
    alert.title = (alert.title or "Untitled alert")[:512]
    db.add(alert)
    db.flush()
    analyze_alert(db, alert)
    if run_ai:
        investigate_alert(db, alert)
    return alert


def alert_brief(a: Alert, with_raw: bool = False) -> dict:
    d = {
        "id": a.id,
        "title": a.title,
        "description": (a.description or "")[:1500],
        "severity": a.severity,
        "status": a.status,
        "verdict": a.verdict,
        "source": a.source,
        "category": a.category,
        "host": a.host,
        "username": a.username,
        "src_ip": a.src_ip,
        "dst_ip": a.dst_ip,
        "risk_score": a.risk_score,
        "event_time": a.event_time.isoformat() if a.event_time else "",
        "mitre": [{"id": t["id"], "name": t["name"], "tactic": t["tactic"]} for t in (a.mitre or [])],
    }
    if with_raw:
        d["raw_excerpt"] = json.dumps(a.raw, default=str)[:3000]
    return d


def build_alert_context(db: Session, alert: Alert) -> dict:
    related = find_related(db, alert)
    text = analysis_text(alert)
    return {
        "kind": "alert",
        "anchor": alert_brief(alert, with_raw=True),
        "alerts": [alert_brief(alert)],
        "iocs": alert.iocs or [],
        "mitre": alert.mitre or [],
        "risk_score": alert.risk_score,
        "risk_reasons": (alert.enrichment or {}).get("risk_reasons", []),
        "related": [{"id": r.id, "title": r.title, "severity": r.severity, "reasons": why} for r, why in related[:10]],
        "va": (alert.enrichment or {}).get("asset"),
        "playbooks": rank_playbooks(alert.mitre or [], text),
        "hosts": [alert.host] if alert.host else [],
        "users": [alert.username] if alert.username else [],
    }


def build_case_context(db: Session, case: Case) -> dict:
    alerts = sorted(case.alerts, key=lambda a: a.event_time)
    if not alerts:
        return {
            "kind": "case",
            "anchor": {"title": case.title, "severity": case.severity},
            "alerts": [],
            "iocs": [],
            "mitre": [],
            "risk_score": 0,
            "risk_reasons": [],
            "related": [],
            "va": None,
            "playbooks": [],
            "hosts": [],
            "users": [],
            "notes": [],
            "actions": [],
        }
    anchor = max(alerts, key=lambda a: a.risk_score)
    iocs: dict[tuple, dict] = {}
    techniques: dict[str, dict] = {}
    for a in alerts:
        for i in a.iocs or []:
            iocs.setdefault((i["type"], i["value"].lower()), i)
        for t in a.mitre or []:
            techniques.setdefault(t["id"], t)
    from .mitre import TACTIC_ORDER

    mitre = sorted(techniques.values(), key=lambda t: (TACTIC_ORDER.get(t["tactic"], 99), t["id"]))
    hosts = list(dict.fromkeys(a.host for a in alerts if a.host))
    users = list(dict.fromkeys(a.username for a in alerts if a.username))
    va_assets = [ctx for h in hosts if (ctx := asset_va_context(db, host=h))]
    text = " ".join(analysis_text(a) for a in alerts)
    return {
        "kind": "case",
        "case": {
            "id": case.id,
            "title": case.title,
            "status": case.status,
            "severity": case.severity,
            "summary": case.summary,
        },
        "anchor": alert_brief(anchor, with_raw=True),
        "alerts": [alert_brief(a) for a in alerts],
        "iocs": list(iocs.values()),
        "mitre": mitre,
        "risk_score": anchor.risk_score,
        "risk_reasons": (anchor.enrichment or {}).get("risk_reasons", []),
        "related": [],
        "va": (anchor.enrichment or {}).get("asset") or (va_assets[0] if va_assets else None),
        "va_assets": va_assets,
        "playbooks": rank_playbooks(mitre, text),
        "hosts": hosts,
        "users": users,
        "notes": [{"author": n.author, "content": n.content, "at": n.created_at.isoformat()} for n in case.notes],
        "actions": [
            {"action": x.action, "target": x.target, "by": x.performed_by, "at": x.created_at.isoformat()}
            for x in case.actions
        ],
        "ai_report": case.ai_report,
    }


def investigate_alert(db: Session, alert: Alert) -> dict:
    analyze_alert(db, alert)  # refresh enrichment, VA posture and correlation first
    report = ai_engine.investigate(build_alert_context(db, alert))
    alert.ai_report = report
    alert.verdict = report["verdict"]
    if alert.status == "new":
        alert.status = "triaged"
    return report


def investigate_case(db: Session, case: Case) -> dict:
    report = ai_engine.investigate(build_case_context(db, case))
    case.ai_report = report
    if case.status == "open":
        case.status = "investigating"
    return report
