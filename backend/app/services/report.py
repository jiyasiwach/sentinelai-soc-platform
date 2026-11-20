"""Markdown incident report for a case."""

from __future__ import annotations

from ..models import Case, utcnow
from .vuln import asset_va_context


def _cell(value: object) -> str:
    return str(value if value not in (None, "") else "-").replace("|", "\\|").replace("\n", " ")


def case_markdown(db, case: Case) -> str:
    r = case.ai_report or {}
    alerts = sorted(case.alerts, key=lambda a: a.event_time)
    out = [
        f"# Incident Report - Case #{case.id}: {case.title}",
        "",
        f"- **Status:** {case.status}  ",
        f"- **Severity:** {case.severity}  ",
        f"- **Assignee:** {case.assignee or 'unassigned'}  ",
        f"- **Opened:** {case.created_at:%Y-%m-%d %H:%M} UTC  ",
        f"- **Closed:** {case.closed_at:%Y-%m-%d %H:%M} UTC  " if case.closed_at else "- **Closed:** -  ",
        f"- **Generated:** {utcnow():%Y-%m-%d %H:%M} UTC by SentinelAI",
        "",
        "## Executive summary",
        "",
        r.get("summary") or case.summary or "_No AI analysis has been run for this case yet._",
        "",
    ]
    if r:
        out += [
            f"**Verdict:** {r.get('verdict', '-')} (confidence {r.get('confidence', '-')}%) - engine: {r.get('engine', '-')}",
            "",
            "## Attack narrative",
            "",
            r.get("attack_narrative") or "-",
            "",
            "## Key findings",
            "",
            *[f"- {f}" for f in r.get("key_findings", [])],
            "",
        ]
    out += [
        "## Alert timeline",
        "",
        "| Time (UTC) | ID | Severity | Risk | Title | Host | User | Verdict |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for a in alerts:
        out.append(
            f"| {a.event_time:%Y-%m-%d %H:%M} | #{a.id} | {a.severity} | {a.risk_score} | {_cell(a.title)} | {_cell(a.host)} | {_cell(a.username)} | {a.verdict} |"
        )

    techniques: dict[str, dict] = {}
    iocs: dict[str, dict] = {}
    for a in alerts:
        for t in a.mitre or []:
            techniques.setdefault(t["id"], t)
        for i in a.iocs or []:
            iocs.setdefault(i["value"], i)
    out += ["", "## MITRE ATT&CK", ""]
    out += [
        f"- **{t['tactic']}** - [{t['id']}](https://attack.mitre.org/techniques/{t['id'].replace('.', '/')}/) {t['name']}"
        for t in techniques.values()
    ] or ["- None mapped"]
    out += ["", "## Indicators of compromise", "", "| Type | Value | Reputation | Tags |", "|---|---|---|---|"]
    for i in sorted(iocs.values(), key=lambda x: -int(x.get("score", 0))):
        out.append(
            f"| {i['type']} | `{_cell(i['value'])}` | {i.get('reputation', 'unknown')} | {_cell(', '.join(i.get('tags', [])))} |"
        )

    hosts = sorted({a.host for a in alerts if a.host})
    va_rows = [ctx for h in hosts if (ctx := asset_va_context(db, host=h))]
    if va_rows:
        out += ["", "## Vulnerability exposure of affected assets", ""]
        for ctx in va_rows:
            a = ctx["asset"]
            out.append(
                f"- **{a['hostname'] or a['ip']}** ({a['criticality']}): {ctx['open_vulns']} open, max CVSS {ctx['max_cvss']}, {ctx['exploitable_count']} exploitable"
            )
            for v in ctx["top_vulns"][:3]:
                out.append(
                    f"  - {v['cve'] or 'no CVE'} {v['title']} - CVSS {v['cvss']}, priority {v['priority_score']}"
                )

    if r.get("recommended_actions"):
        out += ["", "## Recommended actions", ""]
        out += [f"- [{a['priority']}] `{a['action']}` {a['target']} - {a['reason']}" for a in r["recommended_actions"]]
    out += ["", "## Response actions taken (simulated)", ""]
    out += [
        f"- {x.created_at:%Y-%m-%d %H:%M} `{x.action}` {x.target} by {x.performed_by} - {x.details}"
        for x in case.actions
    ] or ["- None"]
    out += ["", "## Analyst notes", ""]
    out += [f"- {n.created_at:%Y-%m-%d %H:%M} **{n.author}:** {n.content}" for n in case.notes] or ["- None"]
    if r.get("open_questions"):
        out += ["", "## Open questions", ""] + [f"- {q}" for q in r["open_questions"]]
    out += [
        "",
        "---",
        "_Response actions in SentinelAI are simulated and audited. Generated for analyst review; verify before external distribution._",
        "",
    ]
    return "\n".join(out)
