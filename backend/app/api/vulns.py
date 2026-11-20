from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import Asset, User, Vulnerability
from ..schemas import AssetUpdate, FindingsImport, VulnUpdate, asset_out, vuln_out
from ..security import analyst_or_admin, audit, get_current_user
from ..services.sync import sync_assets
from ..services.vuln import ImportErrorBadInput, import_findings, import_nmap, parse_nmap

router = APIRouter(prefix="/api/va", tags=["vulnerability-assessment"])


@router.get("/assets")
def list_assets(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted((asset_out(a) for a in assets), key=lambda a: (rank.get(a["criticality"], 9), -a["max_cvss"]))


@router.patch("/assets/{asset_id}")
def update_asset(
    asset_id: int, body: AssetUpdate, user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)
):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(asset, k, v)
    # Criticality feeds both finding priority and alert risk: re-prioritise findings, re-score open alerts.
    rescored = sync_assets(db, [asset])
    audit(db, user.username, "asset_updated", "asset", asset.id, {**changes, "alerts_rescored": len(rescored)})
    db.commit()
    return asset_out(asset)


@router.get("/vulnerabilities")
def list_vulns(
    severity: str | None = None,
    status: str | None = None,
    asset_id: int | None = None,
    limit: int = Query(500, ge=1, le=2000),
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(Vulnerability)
    if severity:
        query = query.filter(Vulnerability.severity.in_(severity.split(",")))
    if status:
        query = query.filter(Vulnerability.status.in_(status.split(",")))
    if asset_id:
        query = query.filter(Vulnerability.asset_id == asset_id)
    rows = query.order_by(Vulnerability.priority_score.desc(), Vulnerability.cvss.desc()).limit(limit).all()
    return [vuln_out(v) for v in rows]


@router.post("/vulnerabilities", status_code=201)
def import_findings_json(body: FindingsImport, user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)):
    """Import Nessus/OpenVAS/manual pentest findings (already normalised to the SentinelAI finding shape)."""
    try:
        summary = import_findings(db, [f.model_dump() for f in body.findings])
    except ImportErrorBadInput as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    summary["alerts_rescored"] = len(sync_assets(db, summary.pop("_assets")))
    audit(db, user.username, "va_findings_imported", "vulnerability", "", summary)
    db.commit()
    return summary


@router.patch("/vulnerabilities/{vuln_id}")
def update_vuln(vuln_id: int, body: VulnUpdate, user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)):
    v = db.get(Vulnerability, vuln_id)
    if not v:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    old = v.status
    v.status = body.status
    rescored = sync_assets(db, [v.asset])  # a fixed finding lowers the asset's exposure in alert risk
    audit(
        db,
        user.username,
        "vuln_status_changed",
        "vulnerability",
        v.id,
        {"from": old, "to": body.status, "alerts_rescored": len(rescored)},
    )
    db.commit()
    return vuln_out(v)


@router.post("/import/nmap", status_code=201)
async def import_nmap_xml(
    file: UploadFile = File(...), user: User = Depends(analyst_or_admin), db: Session = Depends(get_db)
):
    content = await file.read(settings.max_xml_bytes + 1)
    try:
        hosts = parse_nmap(content)
        summary = import_nmap(db, hosts)
        summary["alerts_rescored"] = len(sync_assets(db, summary.pop("_assets")))
    except ImportErrorBadInput as exc:
        db.rollback()
        audit(db, user.username, "nmap_import_rejected", "asset", "", str(exc))
        db.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    audit(db, user.username, "nmap_imported", "asset", "", {**summary, "file": file.filename})
    db.commit()
    return summary
