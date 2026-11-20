from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Alert, Case, CaseNote, ChatMessage, ResponseAction, User, utcnow
from ..schemas import ActionCreate, AddAlerts, CaseCreate, CaseUpdate, ChatRequest, NoteCreate, case_out, case_summary
from ..security import admin_only, analyst_or_admin, audit, get_current_user
from ..services import ai_engine
from ..services.correlation import auto_group
from ..services.normalizer import SEVERITY_RANK
from ..services.pipeline import build_case_context, investigate_case
from ..services.report import case_markdown
from ..services.sync import sync_alerts

router = APIRouter(prefix="/api/cases", tags=["cases"])

CONTAINMENT_ACTIONS = {"isolate_host", "block_ip", "block_domain", "disable_user", "quarantine_file", "kill_process"}
ACTION_RESULT = {
    "isolate_host": "Host network-isolated via EDR (simulated)",
    "block_ip": "IP added to perimeter firewall deny list (simulated)",
    "block_domain": "Domain sinkholed on DNS / blocked on proxy (simulated)",
    "disable_user": "Account disabled in directory (simulated)",
    "reset_password": "Password reset forced and sessions revoked (simulated)",
    "quarantine_file": "File hash quarantined fleet-wide via EDR (simulated)",
    "kill_process": "Process terminated on endpoint (simulated)",
    "collect_forensics": "Memory and triage disk collection queued (simulated)",
}


def _get(db: Session, case_id: int) -> Case:
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


def _alerts(db: Session, ids: list[int]) -> list[Alert]:
    alerts = db.query(Alert).filter(Alert.id.in_(ids)).all()
    missing = set(ids) - {a.id for a in alerts}
    if missing:
        raise HTTPException(status_code=404, detail=f"Alerts not found: {sorted(missing)[:10]}")
    return alerts


@router.get("")
def list_cases(
    status: str | None = None,
    limit: int = Query(200, ge=1, le=500),
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(Case)
    if status:
        query = query.filter(Case.status.in_(status.split(",")))
    return [case_summary(c) for c in query.order_by(Case.id.desc()).limit(limit).all()]


@router.post("", status_code=201)
def create_case(body: CaseCreate, user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)):
    alerts = _alerts(db, body.alert_ids) if body.alert_ids else []
    severity = body.severity or (
        max((a.severity for a in alerts), key=lambda s: SEVERITY_RANK.get(s, 0)) if alerts else "medium"
    )
    case = Case(
        title=body.title,
        summary=body.summary,
        severity=severity,
        assignee=body.assignee or user.username,
        created_by=user.username,
        status="open",
    )
    case.alerts = alerts
    for a in alerts:
        if a.status in ("new", "triaged"):
            a.status = "investigating"
    db.add(case)
    db.flush()
    audit(db, user.username, "case_created", "case", case.id, {"alerts": body.alert_ids})
    db.commit()
    return case_out(case)


@router.post("/auto-group", status_code=201)
def auto_group_cases(user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)):
    cases = auto_group(db, user.username)
    for c in cases:
        audit(db, user.username, "case_auto_grouped", "case", c.id, {"alerts": [a.id for a in c.alerts]})
    db.commit()
    return {"created": len(cases), "cases": [case_summary(c) for c in cases]}


@router.get("/{case_id}")
def get_case(case_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return case_out(_get(db, case_id))


@router.patch("/{case_id}")
def update_case(case_id: int, body: CaseUpdate, user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)):
    case = _get(db, case_id)
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(case, k, v)
    if changes.get("status") in ("resolved", "closed"):
        case.closed_at = case.closed_at or utcnow()
        for a in case.alerts:  # resolving a case closes its alerts
            a.status = "closed"
        sync_alerts(db, case.alerts)  # their assets may lose the "+10 open alerts" priority term
    elif "status" in changes:
        case.closed_at = None
    audit(db, user.username, "case_updated", "case", case.id, changes)
    db.commit()
    return case_out(case)


@router.delete("/{case_id}", status_code=204)
def delete_case(case_id: int, user: User = Depends(admin_only), db: Session = Depends(get_db)):
    case = _get(db, case_id)
    audit(db, user.username, "case_deleted", "case", case.id, {"title": case.title})
    db.delete(case)
    db.commit()


@router.post("/{case_id}/alerts")
def add_alerts(case_id: int, body: AddAlerts, user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)):
    case = _get(db, case_id)
    existing = {a.id for a in case.alerts}
    for a in _alerts(db, body.alert_ids):
        if a.id not in existing:
            case.alerts.append(a)
    audit(db, user.username, "case_alerts_added", "case", case.id, {"alerts": body.alert_ids})
    db.commit()
    return case_out(case)


@router.post("/{case_id}/notes", status_code=201)
def add_note(case_id: int, body: NoteCreate, user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)):
    case = _get(db, case_id)
    case.notes.append(CaseNote(author=user.username, content=body.content))
    audit(db, user.username, "case_note_added", "case", case.id)
    db.commit()
    return case_out(case)


@router.post("/{case_id}/actions", status_code=201)
def run_action(case_id: int, body: ActionCreate, user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)):
    """Response actions are SIMULATED: nothing touches a real system. Every action is audited."""
    case = _get(db, case_id)
    details = ACTION_RESULT[body.action] + (f". {body.details}" if body.details else "")
    case.actions.append(
        ResponseAction(
            action=body.action, target=body.target, performed_by=user.username, status="simulated", details=details
        )
    )
    if body.action in CONTAINMENT_ACTIONS and case.status in ("open", "investigating"):
        case.status = "contained"
    audit(
        db,
        user.username,
        "response_action",
        "case",
        case.id,
        {"action": body.action, "target": body.target, "simulated": True},
    )
    db.commit()
    return case_out(case)


@router.post("/{case_id}/investigate")
def investigate(case_id: int, user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)):
    case = _get(db, case_id)
    if not case.alerts:
        raise HTTPException(status_code=400, detail="Add alerts to the case before investigating")
    report = investigate_case(db, case)
    audit(
        db,
        user.username,
        "ai_investigation",
        "case",
        case.id,
        {"engine": report.get("engine"), "verdict": report["verdict"]},
    )
    db.commit()
    return case_out(case)


@router.post("/{case_id}/chat")
def chat(case_id: int, body: ChatRequest, user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)):
    case = _get(db, case_id)
    history = [{"role": m.role, "content": m.content} for m in case.chat]
    result = ai_engine.chat(build_case_context(db, case), history, body.message)
    case.chat.append(ChatMessage(role="user", content=body.message, author=user.username))
    case.chat.append(
        ChatMessage(role="assistant", content=result["answer"], author="SentinelAI", engine=result["engine"])
    )
    audit(db, user.username, "ai_chat", "case", case.id, {"engine": result["engine"], "question": body.message[:200]})
    db.commit()
    return {
        "answer": result["answer"],
        "engine": result["engine"],
        "engine_note": result.get("engine_note"),
        "chat": case_out(case)["chat"],
    }


@router.get("/{case_id}/report", response_class=PlainTextResponse)
def report(case_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    case = _get(db, case_id)
    audit(db, user.username, "report_downloaded", "case", case.id)
    db.commit()
    return PlainTextResponse(
        case_markdown(db, case),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="case-{case.id}-incident-report.md"'},
    )
