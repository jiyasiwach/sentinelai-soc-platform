"""Keep alert risk scores and vulnerability priorities in step with each other.

The link runs both ways:
- an alert's risk score uses its target asset's VA posture (criticality, exploitable / CVSS >= 9 findings);
- a finding's priority gets +10 while its asset has open alerts.

So whenever one side changes, the other side is recalculated:
- VA change (findings import, Nmap import, asset criticality, finding status) -> re-prioritise the asset's
  findings and re-score that asset's open alerts;
- alert change (ingest, status change, case resolved/closed) -> re-prioritise the affected assets' findings,
  then re-score their open alerts so the VA snapshot stored on each alert matches the VA page.

Re-scoring refreshes enrichment, correlation and the risk score. It does not re-run the AI verdict; the
analyst re-runs an investigation when they want a fresh verdict.
"""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..models import Alert, Asset
from .enrichment import is_internal_ip
from .vuln import find_asset, reprioritize_asset


def asset_for_alert(db: Session, alert: Alert) -> Asset | None:
    """Same matching rule as the alert's VA context: host, then destination IP, then internal source IP."""
    asset = find_asset(db, host=alert.host) if alert.host else None
    if not asset and alert.dst_ip:
        asset = find_asset(db, ip=alert.dst_ip)
    if not asset and alert.src_ip and is_internal_ip(alert.src_ip):
        asset = find_asset(db, ip=alert.src_ip)
    return asset


def open_alerts_for_asset(db: Session, asset: Asset) -> list[Alert]:
    conds = []
    if asset.hostname:
        conds.append(Alert.host.ilike(asset.hostname))
    if asset.ip:
        conds.extend([Alert.host == asset.ip, Alert.dst_ip == asset.ip, Alert.src_ip == asset.ip])
    if not conds:
        return []
    candidates = db.query(Alert).filter(Alert.status != "closed").filter(or_(*conds)).all()
    # Keep only alerts whose VA context really resolves to this asset (e.g. src_ip matches only if internal).
    return [a for a in candidates if (found := asset_for_alert(db, a)) is not None and found.id == asset.id]


def sync_assets(db: Session, assets: Iterable[Asset]) -> set[int]:
    """Re-prioritise the assets' findings, then re-score their open alerts. Returns re-scored alert ids."""
    from .pipeline import analyze_alert  # local import: pipeline imports this module's dependencies

    unique = {a.id: a for a in assets if a is not None}
    if not unique:
        return set()
    db.flush()  # make pending alert/VA changes visible to the queries below (autoflush is off)
    for asset in unique.values():
        db.refresh(asset)
        reprioritize_asset(db, asset)
    db.flush()
    rescored: set[int] = set()
    for asset in unique.values():
        for alert in open_alerts_for_asset(db, asset):
            if alert.id not in rescored:
                analyze_alert(db, alert)
                rescored.add(alert.id)
    db.flush()
    return rescored


def sync_alerts(db: Session, alerts: Iterable[Alert]) -> set[int]:
    """After alerts changed: sync every asset they point at."""
    db.flush()
    return sync_assets(db, [asset_for_alert(db, a) for a in alerts])
