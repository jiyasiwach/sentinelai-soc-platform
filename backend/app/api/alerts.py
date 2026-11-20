import json

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy import case, or_
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import Alert, User
from ..schemas import AlertUpdate, IngestRequest, alert_out, alert_summary
from ..security import analyst_or_admin, audit, get_current_user
from ..services.correlation import find_related
from ..services.normalizer import normalize
from ..services.pipeline import analyze_alert, investigate_alert, process_alert
from ..services.sync import sync_alerts

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

SORTS = {
    "risk": (Alert.risk_score.desc(), Alert.event_time.desc()),
    "time": (Alert.event_time.desc(),),
    "oldest": (Alert.event_time.asc(),),
    "severity": (
        case({"critical": 0, "high": 1, "medium": 2, "low": 3}, value=Alert.severity, else_=9),
        Alert.risk_score.desc(),
    ),
}


def _get(db: Session, alert_id: int) -> Alert:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.get("")
def list_alerts(
    severity: str | None = None,
    status: str | None = None,
    verdict: str | None = None,
    host: str | None = None,
    source: str | None = None,
    q: str | None = Query(None, max_length=200),
    sort: str = "risk",
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity.in_(severity.split(",")))
    if status:
        query = query.filter(Alert.status.in_(status.split(",")))
    if verdict:
        query = query.filter(Alert.verdict.in_(verdict.split(",")))
    if source:
        query = query.filter(Alert.source == source)
    if host:
        query = query.filter(Alert.host.ilike(f"%{host}%"))
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                Alert.title.ilike(like),
                Alert.description.ilike(like),
                Alert.host.ilike(like),
                Alert.username.ilike(like),
                Alert.src_ip.ilike(like),
                Alert.dst_ip.ilike(like),
            )
        )
    total = query.count()
    items = query.order_by(*SORTS.get(sort, SORTS["risk"])).offset(offset).limit(limit).all()
    return {"total": total, "items": [alert_summary(a) for a in items]}


def _ingest(db: Session, user: User, raw_alerts: list, fmt: str, run_ai: bool, origin: str) -> dict:
    if len(raw_alerts) > settings.max_alerts_per_request:
        raise HTTPException(status_code=413, detail=f"At most {settings.max_alerts_per_request} alerts per request")
    created, errors = [], []
    for idx, raw in enumerate(raw_alerts):
        try:
            normalized = normalize(raw, fmt)
        except ValueError as exc:
            errors.append({"index": idx, "error": str(exc)})
            continue
        created.append(process_alert(db, normalized))
    db.flush()
    # New open alerts give their assets "+10 open alerts": re-prioritise those findings and re-score the
    # assets' open alerts (this also gives correlations inside the batch a symmetric second pass).
    rescored = sync_alerts(db, created)
    for alert in created:
        if alert.id not in rescored:
            analyze_alert(db, alert)
        if run_ai:
            investigate_alert(db, alert)
    audit(
        db,
        user.username,
        "alerts_ingested",
        "alert",
        "",
        {"count": len(created), "errors": len(errors), "origin": origin, "ai": run_ai},
    )
    db.commit()
    return {"ingested": len(created), "errors": errors[:50], "alerts": [alert_summary(a) for a in created[:200]]}


@router.post("/ingest", status_code=201)
def ingest(body: IngestRequest, user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)):
    return _ingest(db, user, body.alerts, body.format, body.investigate, "api")


@router.post("/upload", status_code=201)
async def upload(
    file: UploadFile = File(...),
    format: str = Form("auto"),
    investigate: bool = Form(False),
    user: User = Depends(analyst_or_admin),
    db: Session = Depends(get_db),
):
    if format not in ("auto", "generic", "wazuh", "splunk", "elastic"):
        raise HTTPException(status_code=422, detail="Unknown format")
    content = await file.read(settings.max_alert_upload_bytes + 1)
    if len(content) > settings.max_alert_upload_bytes:
        raise HTTPException(status_code=413, detail="File exceeds 20 MB limit")
    text = content.decode("utf-8", errors="replace").strip()
    name = (file.filename or "").lower()
    try:
        if name.endswith(".jsonl") or name.endswith(".ndjson") or (not text.startswith("[") and "\n{" in text):
            data = [json.loads(line) for line in text.splitlines() if line.strip()]
        else:
            data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON: {exc.msg} (line {exc.lineno})") from exc
    if isinstance(data, dict):
        data = data.get("alerts") or data.get("results") or data.get("hits", {}).get("hits") or [data]
        data = [d.get("_source", d) if isinstance(d, dict) else d for d in data]
    if not isinstance(data, list):
        raise HTTPException(status_code=422, detail="Expected a JSON array, an object or JSON Lines")
    return _ingest(db, user, data, format, investigate, f"upload:{file.filename}")


@router.get("/{alert_id}")
def get_alert(alert_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return alert_out(_get(db, alert_id))


@router.patch("/{alert_id}")
def update_alert(
    alert_id: int, body: AlertUpdate, user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)
):
    alert = _get(db, alert_id)
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(alert, k, v)
    if "severity" in changes:
        analyze_alert(db, alert)
    if "status" in changes:  # opening/closing an alert changes its asset's "+10 open alerts" term
        sync_alerts(db, [alert])
    audit(db, user.username, "alert_updated", "alert", alert.id, changes)
    db.commit()
    return alert_out(alert)


@router.post("/{alert_id}/investigate")
def investigate(alert_id: int, user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)):
    alert = _get(db, alert_id)
    report = investigate_alert(db, alert)
    audit(
        db,
        user.username,
        "ai_investigation",
        "alert",
        alert.id,
        {"engine": report.get("engine"), "verdict": report["verdict"]},
    )
    db.commit()
    return alert_out(alert)


@router.get("/{alert_id}/related")
def related(alert_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    alert = _get(db, alert_id)
    return [{**alert_summary(r), "reasons": why} for r, why in find_related(db, alert)]
