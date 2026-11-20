"""Explainable 0-100 alert risk score. Every contribution is stored as a human-readable reason."""

from __future__ import annotations

from .mitre import LATE_TACTICS, MID_TACTICS, tactics_of

BASE = {"low": 10, "medium": 25, "high": 40, "critical": 55}
ASSET_CRITICALITY = {"low": 0, "medium": 3, "high": 6, "critical": 10}


def compute_risk(
    severity: str, enriched_iocs: list[dict], techniques: list[dict], asset_ctx: dict | None, related_count: int
) -> tuple[int, list[dict]]:
    reasons: list[dict] = []

    def add(points: int, reason: str) -> None:
        if points:
            reasons.append({"points": points, "reason": reason})

    add(BASE.get(severity, 25), f"Base score for {severity} severity")

    malicious = [i for i in enriched_iocs if i.get("reputation") == "malicious"]
    suspicious = [i for i in enriched_iocs if i.get("reputation") == "suspicious"]
    if malicious:
        pts = min(25, 15 + 5 * (len(malicious) - 1))
        add(pts, f"{len(malicious)} malicious IOC(s) in threat intel: " + ", ".join(i["value"] for i in malicious[:3]))
    if suspicious:
        add(
            min(10, 5 * len(suspicious)),
            f"{len(suspicious)} suspicious IOC(s): " + ", ".join(i["value"] for i in suspicious[:3]),
        )

    tactics = set(tactics_of(techniques))
    late = sorted(tactics & LATE_TACTICS)
    mid = sorted(tactics & MID_TACTICS)
    if late:
        add(10, "Late kill-chain stage: " + ", ".join(late))
    elif mid:
        add(5, "Mid kill-chain stage: " + ", ".join(mid))
    if len(tactics) >= 3:
        add(5, f"Activity spans {len(tactics)} ATT&CK tactics")

    if asset_ctx:
        asset = asset_ctx.get("asset", {})
        crit = asset.get("criticality", "medium")
        add(
            ASSET_CRITICALITY.get(crit, 0),
            f"Target asset {asset.get('hostname') or asset.get('ip')} is {crit} criticality",
        )
        if asset_ctx.get("exploitable_count", 0) > 0:
            add(8, f"Target asset has {asset_ctx['exploitable_count']} open vulnerability(ies) with a public exploit")
        elif asset_ctx.get("max_cvss", 0) >= 9:
            add(5, f"Target asset has an open vulnerability with CVSS {asset_ctx['max_cvss']}")

    if related_count:
        add(min(10, 2 * related_count), f"{related_count} correlated alert(s) within the correlation window")

    total = sum(r["points"] for r in reasons)
    if total > 100:
        reasons.append({"points": 100 - total, "reason": "Capped at 100"})
        total = 100
    return max(0, total), reasons
