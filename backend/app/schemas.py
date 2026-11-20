"""Pydantic v2 request models and response serializers."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .models import Alert, Asset, AuditLog, Case, User, Vulnerability

Role = Literal["admin", "analyst", "viewer"]
Severity = Literal["low", "medium", "high", "critical"]
AlertStatus = Literal["new", "triaged", "investigating", "closed"]
Verdict = Literal["pending", "true_positive", "false_positive", "benign", "needs_review"]
CaseStatus = Literal["open", "investigating", "contained", "resolved", "closed"]
Criticality = Literal["low", "medium", "high", "critical"]
VulnStatus = Literal["open", "in_progress", "fixed", "accepted_risk", "false_positive"]
ActionType = Literal[
    "isolate_host",
    "block_ip",
    "block_domain",
    "disable_user",
    "reset_password",
    "quarantine_file",
    "kill_process",
    "collect_forensics",
]
AlertFormat = Literal["auto", "generic", "wazuh", "splunk", "elastic"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ---------------------------------------------------------------- requests
class UserCreate(StrictModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    full_name: str = Field(default="", max_length=128)
    role: Role = "analyst"
    password: str = Field(min_length=10, max_length=128)


class IngestRequest(StrictModel):
    alerts: list[Any] = Field(min_length=1)  # validated per item so one bad entry is reported, not fatal
    format: AlertFormat = "auto"
    investigate: bool = False


class AlertUpdate(StrictModel):
    status: AlertStatus | None = None
    verdict: Verdict | None = None
    severity: Severity | None = None


class CaseCreate(StrictModel):
    title: str = Field(min_length=3, max_length=512)
    summary: str = Field(default="", max_length=8000)
    severity: Severity | None = None
    assignee: str = Field(default="", max_length=64)
    alert_ids: list[int] = Field(default_factory=list, max_length=1000)


class CaseUpdate(StrictModel):
    title: str | None = Field(default=None, min_length=3, max_length=512)
    summary: str | None = Field(default=None, max_length=8000)
    severity: Severity | None = None
    status: CaseStatus | None = None
    assignee: str | None = Field(default=None, max_length=64)


class AddAlerts(StrictModel):
    alert_ids: list[int] = Field(min_length=1, max_length=1000)


class NoteCreate(StrictModel):
    content: str = Field(min_length=1, max_length=8000)


class ActionCreate(StrictModel):
    action: ActionType
    target: str = Field(min_length=1, max_length=512)
    details: str = Field(default="", max_length=2000)


class ChatRequest(StrictModel):
    message: str = Field(min_length=1, max_length=2000)


class AssetUpdate(StrictModel):
    criticality: Criticality | None = None
    owner: str | None = Field(default=None, max_length=128)
    os: str | None = Field(default=None, max_length=255)


class VulnUpdate(StrictModel):
    status: VulnStatus


class Finding(BaseModel):
    model_config = ConfigDict(extra="ignore")
    host: str = Field(min_length=1, max_length=255)
    title: str = Field(min_length=1, max_length=512)
    cve: str = Field(default="", max_length=32)
    cvss: float = Field(default=0.0, ge=0, le=10)
    port: int | None = Field(default=None, ge=0, le=65535)
    service: str = Field(default="", max_length=64)
    description: str = Field(default="", max_length=8000)
    remediation: str = Field(default="", max_length=8000)
    exploit_available: bool = False
    source: Literal["nmap", "nessus", "openvas", "manual", "pentest"] = "manual"
    ip: str = Field(default="", max_length=64)


class FindingsImport(BaseModel):
    findings: list[Finding] = Field(min_length=1, max_length=5000)


# ---------------------------------------------------------------- serializers
def iso(dt) -> str | None:
    return dt.isoformat() + "Z" if dt else None


def user_out(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "full_name": u.full_name,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": iso(u.created_at),
    }


def alert_summary(a: Alert) -> dict:
    return {
        "id": a.id,
        "external_id": a.external_id,
        "source": a.source,
        "title": a.title,
        "severity": a.severity,
        "status": a.status,
        "verdict": a.verdict,
        "category": a.category,
        "host": a.host,
        "username": a.username,
        "src_ip": a.src_ip,
        "dst_ip": a.dst_ip,
        "risk_score": a.risk_score,
        "event_time": iso(a.event_time),
        "created_at": iso(a.created_at),
        "case_ids": [c.id for c in a.cases],
        "tactics": list(dict.fromkeys(t["tactic"] for t in (a.mitre or []))),
        "malicious_iocs": sum(1 for i in (a.iocs or []) if i.get("reputation") == "malicious"),
    }


def alert_out(a: Alert) -> dict:
    d = alert_summary(a)
    d.update(
        {
            "description": a.description,
            "raw": a.raw,
            "iocs": a.iocs or [],
            "enrichment": a.enrichment or {},
            "mitre": a.mitre or [],
            "ai_report": a.ai_report,
            "updated_at": iso(a.updated_at),
        }
    )
    return d


def case_summary(c: Case) -> dict:
    return {
        "id": c.id,
        "title": c.title,
        "severity": c.severity,
        "status": c.status,
        "assignee": c.assignee,
        "created_by": c.created_by,
        "created_at": iso(c.created_at),
        "updated_at": iso(c.updated_at),
        "closed_at": iso(c.closed_at),
        "alert_count": len(c.alerts),
        "max_risk": max((a.risk_score for a in c.alerts), default=0),
        "verdict": (c.ai_report or {}).get("verdict"),
    }


def case_out(c: Case) -> dict:
    d = case_summary(c)
    d.update(
        {
            "summary": c.summary,
            "ai_report": c.ai_report,
            "alerts": [alert_summary(a) for a in sorted(c.alerts, key=lambda a: a.event_time)],
            "notes": [
                {"id": n.id, "author": n.author, "content": n.content, "created_at": iso(n.created_at)} for n in c.notes
            ],
            "actions": [
                {
                    "id": x.id,
                    "action": x.action,
                    "target": x.target,
                    "performed_by": x.performed_by,
                    "status": x.status,
                    "details": x.details,
                    "created_at": iso(x.created_at),
                }
                for x in c.actions
            ],
            "chat": [
                {
                    "id": m.id,
                    "role": m.role,
                    "content": m.content,
                    "author": m.author,
                    "engine": m.engine,
                    "created_at": iso(m.created_at),
                }
                for m in c.chat
            ],
        }
    )
    return d


def asset_out(a: Asset) -> dict:
    open_v = [v for v in a.vulnerabilities if v.status in ("open", "in_progress")]
    return {
        "id": a.id,
        "hostname": a.hostname,
        "ip": a.ip,
        "os": a.os,
        "criticality": a.criticality,
        "owner": a.owner,
        "open_ports": a.open_ports or [],
        "last_scanned": iso(a.last_scanned),
        "open_vulns": len(open_v),
        "max_cvss": max((v.cvss for v in open_v), default=0.0),
        "exploitable": sum(1 for v in open_v if v.exploit_available),
    }


def vuln_out(v: Vulnerability) -> dict:
    from .services.vuln import priority_breakdown

    return {
        "id": v.id,
        "asset_id": v.asset_id,
        "asset": (v.asset.hostname or v.asset.ip) if v.asset else "",
        "asset_criticality": v.asset.criticality if v.asset else "",
        "title": v.title,
        "cve": v.cve,
        "cvss": v.cvss,
        "severity": v.severity,
        "port": v.port,
        "service": v.service,
        "description": v.description,
        "remediation": v.remediation,
        "exploit_available": v.exploit_available,
        "status": v.status,
        "source": v.source,
        "priority_score": v.priority_score,
        "priority_explained": priority_breakdown(v),
        "first_seen": iso(v.first_seen),
        "updated_at": iso(v.updated_at),
    }


def audit_out(x: AuditLog) -> dict:
    return {
        "id": x.id,
        "actor": x.actor,
        "action": x.action,
        "entity": x.entity,
        "entity_id": x.entity_id,
        "details": x.details,
        "created_at": iso(x.created_at),
    }
