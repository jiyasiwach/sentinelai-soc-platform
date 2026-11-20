"""Alert correlation (shared host/user/IP/IOC within a time window) and union-find auto-grouping into cases."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from ..config import settings
from ..models import Alert, Case
from .normalizer import SEVERITY_RANK

IGNORED_USERS = {"", "-", "n/a", "system", "local service", "network service", "unknown"}


def _external_iocs(alert: Alert) -> set[str]:
    values = set()
    for i in alert.iocs or []:
        if i.get("type") == "ip":
            from .enrichment import is_internal_ip

            if is_internal_ip(i["value"]):
                continue
        if i.get("type") == "cve":
            continue
        values.add(i["value"].lower())
    return values


def correlation_reasons(a: Alert, b: Alert) -> list[str]:
    reasons = []
    if a.host and b.host and a.host.lower() == b.host.lower():
        reasons.append(f"same host {a.host}")
    if (
        a.username
        and b.username
        and a.username.lower() == b.username.lower()
        and a.username.lower() not in IGNORED_USERS
    ):
        reasons.append(f"same user {a.username}")
    if a.src_ip and b.src_ip and a.src_ip == b.src_ip:
        reasons.append(f"same source IP {a.src_ip}")
    shared = sorted(_external_iocs(a) & _external_iocs(b))
    if shared:
        reasons.append("shared IOC " + ", ".join(shared[:3]))
    return reasons


def find_related(
    db: Session, alert: Alert, window_minutes: int | None = None, limit: int = 50
) -> list[tuple[Alert, list[str]]]:
    window = timedelta(minutes=window_minutes or settings.correlation_window_minutes)
    candidates = (
        db.query(Alert)
        .filter(Alert.id != alert.id)
        .filter(Alert.event_time >= alert.event_time - window, Alert.event_time <= alert.event_time + window)
        .order_by(Alert.event_time)
        .limit(2000)
        .all()
    )
    related = []
    for other in candidates:
        reasons = correlation_reasons(alert, other)
        if reasons:
            related.append((other, reasons))
    return related[:limit]


def auto_group(db: Session, actor: str) -> list[Case]:
    """Union-find over open alerts not yet in a case; one new case per cluster of 2+ alerts."""
    alerts = (
        db.query(Alert).filter(Alert.status != "closed").filter(~Alert.cases.any()).order_by(Alert.event_time).all()
    )
    if not alerts:
        return []
    parent = {a.id: a.id for a in alerts}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[ry] = rx

    window = timedelta(minutes=settings.correlation_window_minutes)
    for i, a in enumerate(alerts):
        for b in alerts[i + 1 :]:
            if b.event_time - a.event_time > window:
                break
            if correlation_reasons(a, b):
                union(a.id, b.id)

    clusters: dict[int, list[Alert]] = {}
    for a in alerts:
        clusters.setdefault(find(a.id), []).append(a)

    created = []
    for members in clusters.values():
        if len(members) < 2:
            continue
        anchor = max(members, key=lambda m: (m.risk_score, SEVERITY_RANK.get(m.severity, 0)))
        severity = max((m.severity for m in members), key=lambda s: SEVERITY_RANK.get(s, 0))
        hosts = sorted({m.host for m in members if m.host})
        case = Case(
            title=f"{anchor.title} (+{len(members) - 1} related)",
            summary=f"Auto-grouped {len(members)} correlated alerts"
            + (f" on {', '.join(hosts[:4])}" if hosts else "")
            + ".",
            severity=severity,
            status="open",
            assignee=actor,
            created_by=actor,
        )
        case.alerts = members
        for m in members:
            if m.status == "new":
                m.status = "triaged"
        db.add(case)
        created.append(case)
    db.flush()
    return created
