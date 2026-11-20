"""Vulnerability-assessment module: Nmap XML import (XXE-safe), findings import, CVSS rating, prioritisation.

This platform never scans or exploits anything. It only analyses the *results* of authorised tests.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..config import settings
from ..models import Alert, Asset, Vulnerability, utcnow

CRITICALITY_WEIGHT = {"low": 0.7, "medium": 1.0, "high": 1.2, "critical": 1.4}
CRITICALITIES = tuple(CRITICALITY_WEIGHT)
VULN_STATUSES = ("open", "in_progress", "fixed", "accepted_risk", "false_positive")
VULN_SOURCES = ("nmap", "nessus", "openvas", "manual", "pentest")
OPEN_STATUSES = ("open", "in_progress")

# Risky services that should not be exposed. (port: (title, cvss, service, remediation))
RISKY_SERVICES: dict[int, tuple[str, float, str, str]] = {
    21: (
        "FTP service exposed (cleartext credentials)",
        7.5,
        "ftp",
        "Disable FTP or replace with SFTP/FTPS; restrict by firewall.",
    ),
    23: (
        "Telnet service exposed (cleartext remote shell)",
        9.1,
        "telnet",
        "Disable Telnet and use SSH with key-based authentication.",
    ),
    445: ("SMB exposed", 8.1, "microsoft-ds", "Block SMB (445) at the perimeter; disable SMBv1; patch MS17-010."),
    3389: ("RDP exposed", 8.1, "ms-wbt-server", "Restrict RDP to VPN/jump host, enforce NLA and MFA."),
    5900: ("VNC exposed", 8.8, "vnc", "Restrict VNC to VPN, require strong authentication, or remove."),
    6379: (
        "Redis exposed (often unauthenticated)",
        9.8,
        "redis",
        "Bind Redis to localhost, enable AUTH/ACLs and protected mode.",
    ),
    9200: (
        "Elasticsearch HTTP API exposed",
        9.1,
        "elasticsearch",
        "Enable Elastic security (TLS + auth) and firewall port 9200.",
    ),
    27017: ("MongoDB exposed", 9.1, "mongodb", "Enable MongoDB authentication and bind to private interfaces only."),
}


class ImportErrorBadInput(ValueError):
    pass


def cvss_severity(cvss: float) -> str:
    cvss = float(cvss or 0)
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def priority_score(cvss: float, criticality: str, exploit_available: bool, has_open_alerts: bool) -> float:
    """Priority = min(100, CVSS x 7 x criticality_weight + 12 (public exploit) + 10 (asset has open alerts))."""
    score = float(cvss or 0) * 7 * CRITICALITY_WEIGHT.get(criticality, 1.0)
    if exploit_available:
        score += 12
    if has_open_alerts:
        score += 10
    return round(min(100.0, score), 1)


def priority_breakdown(v: Vulnerability) -> str:
    crit = v.asset.criticality if v.asset else "medium"
    parts = [f"CVSS {v.cvss} x 7 x {CRITICALITY_WEIGHT.get(crit, 1.0)} ({crit} asset)"]
    if v.exploit_available:
        parts.append("+12 public exploit")
    without_alerts = priority_score(v.cvss, crit, v.exploit_available, False)
    with_alerts = priority_score(v.cvss, crit, v.exploit_available, True)
    if v.priority_score >= with_alerts > without_alerts and with_alerts - without_alerts >= 0.1:
        parts.append("+10 asset has open alerts")
    raw = (
        float(v.cvss or 0) * 7 * CRITICALITY_WEIGHT.get(crit, 1.0)
        + (12 if v.exploit_available else 0)
        + (10 if "+10" in " ".join(parts) else 0)
    )
    if raw > 100:
        parts.append("(capped at 100)")
    return " ".join(parts) + f" = {v.priority_score}"


# ---------------------------------------------------------------- Nmap
def parse_nmap(content: bytes) -> list[dict]:
    if len(content) > settings.max_xml_bytes:
        raise ImportErrorBadInput("Nmap XML exceeds 10 MB limit")
    text = content.decode("utf-8", errors="replace")
    if re.search(r"<!ENTITY", text, re.I):
        raise ImportErrorBadInput("XML entities are not allowed (XXE protection)")
    text = re.sub(r"<!DOCTYPE[^>\[]*>", "", text, flags=re.I)  # nmap emits <!DOCTYPE nmaprun>
    if re.search(r"<!DOCTYPE", text, re.I):
        raise ImportErrorBadInput("DOCTYPE declarations with internal subsets are not allowed")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ImportErrorBadInput(f"Invalid XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ImportErrorBadInput("Root element must be <nmaprun> (run nmap with -oX)")

    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") not in (None, "up"):
            continue
        ip = ""
        for addr in h.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                break
        hn = h.find("hostnames/hostname")
        osmatch = h.find("os/osmatch")
        ports = []
        for p in h.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            ports.append(
                {
                    "port": int(p.get("portid", "0")),
                    "protocol": p.get("protocol", "tcp"),
                    "service": svc.get("name", "") if svc is not None else "",
                    "product": " ".join(filter(None, [svc.get("product", ""), svc.get("version", "")]))
                    if svc is not None
                    else "",
                }
            )
        hosts.append(
            {
                "ip": ip,
                "hostname": hn.get("name", "") if hn is not None else "",
                "os": osmatch.get("name", "") if osmatch is not None else "",
                "ports": ports,
            }
        )
    return hosts


def find_asset(db: Session, host: str = "", ip: str = "") -> Asset | None:
    conds = []
    if host:
        conds.append(Asset.hostname.ilike(host))
        conds.append(Asset.ip == host)
    if ip:
        conds.append(Asset.ip == ip)
    if not conds:
        return None
    return db.query(Asset).filter(or_(*conds)).first()


def get_or_create_asset(db: Session, host: str = "", ip: str = "") -> tuple[Asset, bool]:
    asset = find_asset(db, host, ip)
    if asset:
        return asset, False
    from .enrichment import _valid_ipv4

    if not ip and host and _valid_ipv4(host):
        ip, host = host, ""
    asset = Asset(hostname=host, ip=ip, criticality="medium", open_ports=[])
    db.add(asset)
    db.flush()
    return asset, True


def asset_has_open_alerts(db: Session, asset: Asset) -> bool:
    conds = []
    if asset.hostname:
        conds.append(Alert.host.ilike(asset.hostname))
    if asset.ip:
        conds.extend([Alert.dst_ip == asset.ip, Alert.host == asset.ip])
    if not conds:
        return False
    return db.query(Alert.id).filter(Alert.status != "closed").filter(or_(*conds)).first() is not None


def reprioritize_asset(db: Session, asset: Asset) -> None:
    has_alerts = asset_has_open_alerts(db, asset)
    for v in asset.vulnerabilities:
        v.priority_score = priority_score(v.cvss, asset.criticality, v.exploit_available, has_alerts)


def upsert_finding(db: Session, asset: Asset, f: dict) -> bool:
    """Insert or update a finding keyed by asset + title + port. Returns True if created."""
    title = str(f.get("title") or "").strip()[:512]
    if not title:
        raise ImportErrorBadInput("Every finding needs a title")
    port = f.get("port")
    port = int(port) if port not in (None, "") else None
    cvss = max(0.0, min(10.0, float(f.get("cvss") or 0)))
    source = str(f.get("source") or "manual").lower()
    if source not in VULN_SOURCES:
        source = "manual"
    existing = (
        db.query(Vulnerability)
        .filter(
            Vulnerability.asset_id == asset.id,
            Vulnerability.title == title,
            Vulnerability.port.is_(None) if port is None else Vulnerability.port == port,
        )
        .first()
    )
    v = existing or Vulnerability(asset=asset, title=title, port=port)
    v.cve = str(f.get("cve") or "").upper()[:32]
    v.cvss = cvss
    v.severity = cvss_severity(cvss)
    v.service = str(f.get("service") or "")[:64]
    v.description = str(f.get("description") or "")[:8000]
    v.remediation = str(f.get("remediation") or "")[:8000]
    v.exploit_available = bool(f.get("exploit_available", False))
    v.source = source
    if f.get("status") in VULN_STATUSES:
        v.status = f["status"]
    elif existing is None:
        v.status = "open"
    if existing is None:
        db.add(v)
    db.flush()
    return existing is None


def import_findings(db: Session, findings: list[dict]) -> dict:
    if not isinstance(findings, list):
        raise ImportErrorBadInput("Findings must be a JSON list")
    if len(findings) > settings.max_findings_per_request:
        raise ImportErrorBadInput(f"At most {settings.max_findings_per_request} findings per import")
    summary = {"findings_created": 0, "findings_updated": 0, "assets_created": 0}
    touched: dict[int, Asset] = {}
    for f in findings:
        if not isinstance(f, dict):
            raise ImportErrorBadInput("Each finding must be a JSON object")
        host = str(f.get("host") or f.get("hostname") or f.get("ip") or "").strip()
        if not host:
            raise ImportErrorBadInput("Every finding needs a host")
        asset, created = get_or_create_asset(db, host=host, ip=str(f.get("ip") or ""))
        if created:
            summary["assets_created"] += 1
        if upsert_finding(db, asset, f):
            summary["findings_created"] += 1
        else:
            summary["findings_updated"] += 1
        touched[asset.id] = asset
    for asset in touched.values():
        db.refresh(asset)
        reprioritize_asset(db, asset)
    summary["_assets"] = list(touched.values())  # popped by the API layer to re-score linked alerts
    return summary


def import_nmap(db: Session, hosts: list[dict]) -> dict:
    summary = {
        "hosts": len(hosts),
        "assets_created": 0,
        "assets_updated": 0,
        "findings_created": 0,
        "findings_updated": 0,
    }
    touched: list[Asset] = []
    for h in hosts:
        asset, created = get_or_create_asset(db, host=h["hostname"] or h["ip"], ip=h["ip"])
        summary["assets_created" if created else "assets_updated"] += 1
        if h["ip"] and not asset.ip:
            asset.ip = h["ip"]
        if h["hostname"] and not asset.hostname:
            asset.hostname = h["hostname"]
        if h["os"]:
            asset.os = h["os"][:255]
        asset.open_ports = h["ports"]
        asset.last_scanned = utcnow()
        for p in h["ports"]:
            risky = RISKY_SERVICES.get(p["port"])
            if not risky:
                continue
            title, cvss, service, remediation = risky
            created_f = upsert_finding(
                db,
                asset,
                {
                    "title": title,
                    "cvss": cvss,
                    "port": p["port"],
                    "service": p["service"] or service,
                    "description": f"Nmap found {p['service'] or service} open on {p['port']}/{p['protocol']}"
                    + (f" ({p['product']})" if p["product"] else "")
                    + ". Exposed service increases attack surface.",
                    "remediation": remediation,
                    "source": "nmap",
                    "exploit_available": False,
                },
            )
            summary["findings_created" if created_f else "findings_updated"] += 1
        db.flush()
        db.refresh(asset)
        reprioritize_asset(db, asset)
        touched.append(asset)
    summary["_assets"] = touched
    return summary


# ---------------------------------------------------------------- Alert <-> VA link
def vuln_to_dict(v: Vulnerability) -> dict[str, Any]:
    return {
        "id": v.id,
        "title": v.title,
        "cve": v.cve,
        "cvss": v.cvss,
        "severity": v.severity,
        "port": v.port,
        "exploit_available": v.exploit_available,
        "priority_score": v.priority_score,
        "status": v.status,
    }


def asset_va_context(db: Session, host: str = "", dst_ip: str = "", src_ip: str = "") -> dict | None:
    """VA posture of the alert's target asset: open vulns, max CVSS, exploitable count, top 5 vulns."""
    asset = None
    if host:
        asset = find_asset(db, host=host)
    if not asset and dst_ip:
        asset = find_asset(db, ip=dst_ip)
    if not asset and src_ip:
        from .enrichment import is_internal_ip

        if is_internal_ip(src_ip):
            asset = find_asset(db, ip=src_ip)
    if not asset:
        return None
    open_vulns = [v for v in asset.vulnerabilities if v.status in OPEN_STATUSES]
    open_vulns.sort(key=lambda v: v.priority_score, reverse=True)
    return {
        "asset": {
            "id": asset.id,
            "hostname": asset.hostname,
            "ip": asset.ip,
            "os": asset.os,
            "criticality": asset.criticality,
            "owner": asset.owner,
        },
        "open_vulns": len(open_vulns),
        "max_cvss": max((v.cvss for v in open_vulns), default=0.0),
        "exploitable_count": sum(1 for v in open_vulns if v.exploit_available),
        "top_vulns": [vuln_to_dict(v) for v in open_vulns[:5]],
    }
