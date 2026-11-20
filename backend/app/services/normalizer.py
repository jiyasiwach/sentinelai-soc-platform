"""Normalise alerts from Wazuh, Splunk, Elastic or a generic JSON shape into one schema."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..models import utcnow

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

_WORDS = {
    "info": "low",
    "informational": "low",
    "low": "low",
    "minor": "low",
    "medium": "medium",
    "moderate": "medium",
    "warning": "medium",
    "warn": "medium",
    "high": "high",
    "error": "high",
    "major": "high",
    "important": "high",
    "critical": "critical",
    "crit": "critical",
    "severe": "critical",
    "emergency": "critical",
    "fatal": "critical",
}


def severity_from(value: Any, scale: str = "auto") -> str:
    """Map a word or number to low/medium/high/critical.

    Numeric scales: Wazuh rule level 0-15, generic 0-10, or 0-100 (Elastic risk score).
    """
    if value is None or value == "":
        return "medium"
    if isinstance(value, str):
        word = value.strip().lower()
        if word in _WORDS:
            return _WORDS[word]
        try:
            value = float(word)
        except ValueError:
            return "medium"
    try:
        n = float(value)
    except (TypeError, ValueError):
        return "medium"
    if scale == "wazuh" or (scale == "auto" and 10 < n <= 15):
        return "low" if n <= 4 else "medium" if n <= 7 else "high" if n <= 11 else "critical"
    if scale == "auto" and n <= 10:
        return "low" if n <= 3 else "medium" if n <= 6 else "high" if n <= 8 else "critical"
    return "low" if n < 40 else "medium" if n < 70 else "high" if n < 90 else "critical"


def get_path(data: Any, path: str, default: Any = None) -> Any:
    """Read `a.b.c` from nested dicts, also accepting flattened keys like {"kibana.alert.rule.name": ...}."""
    if not isinstance(data, dict):
        return default
    if path in data:
        return data[path]
    head, _, rest = path.partition(".")
    if rest and head in data:
        return get_path(data[head], rest, default)
    # Try progressively longer flattened prefixes: {"kibana.alert": {"rule.name": ...}}
    parts = path.split(".")
    for i in range(2, len(parts)):
        key = ".".join(parts[:i])
        if key in data:
            return get_path(data[key], ".".join(parts[i:]), default)
    return default


def first(data: Any, *paths: str, default: Any = "") -> Any:
    for p in paths:
        v = get_path(data, p)
        if v not in (None, "", [], {}):
            return v
    return default


def parse_time(value: Any) -> datetime:
    if value in (None, ""):
        return utcnow()
    if isinstance(value, int | float):
        ts = float(value)
        if ts > 1e12:  # milliseconds
            ts /= 1000
        return datetime.fromtimestamp(ts, tz=UTC).replace(tzinfo=None)
    text = str(value).strip()
    try:
        if text.replace(".", "", 1).isdigit():
            return parse_time(float(text))
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        # Wazuh uses +0000 without colon
        if len(text) > 5 and text[-5] in "+-" and text[-4:].isdigit() and ":" not in text[-5:]:
            text = text[:-2] + ":" + text[-2:]
        dt = datetime.fromisoformat(text.replace(" ", "T", 1) if "T" not in text else text)
        if dt.tzinfo:
            dt = dt.astimezone(UTC).replace(tzinfo=None)
        return dt
    except ValueError:
        return utcnow()


def detect_format(raw: dict) -> str:
    if not isinstance(raw, dict):
        return "generic"
    if isinstance(raw.get("rule"), dict) and ("agent" in raw or "level" in raw["rule"]):
        return "wazuh"
    if isinstance(raw.get("result"), dict) or "search_name" in raw:
        return "splunk"
    if get_path(raw, "kibana.alert.rule.name") is not None:
        return "elastic"
    return "generic"


def _s(value: Any, limit: int = 512) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value)
    return str(value)[:limit]


def _wazuh(raw: dict) -> dict:
    groups = get_path(raw, "rule.groups") or []
    return {
        "external_id": _s(first(raw, "id", "rule.id")),
        "title": _s(first(raw, "rule.description", default="Wazuh alert")),
        "description": _s(first(raw, "full_log", "rule.description"), 8000),
        "severity": severity_from(get_path(raw, "rule.level"), "wazuh"),
        "category": _s(groups[0] if isinstance(groups, list) and groups else groups),
        "host": _s(first(raw, "agent.name", "manager.name")),
        "username": _s(
            first(
                raw,
                "data.dstuser",
                "data.srcuser",
                "data.win.eventdata.targetUserName",
                "data.win.eventdata.subjectUserName",
            )
        ),
        "src_ip": _s(first(raw, "data.srcip", "data.src_ip")),
        "dst_ip": _s(first(raw, "data.dstip", "agent.ip")),
        "event_time": parse_time(first(raw, "timestamp", "@timestamp", default=None)),
    }


def _splunk(raw: dict) -> dict:
    r = raw.get("result") if isinstance(raw.get("result"), dict) else raw
    return {
        "external_id": _s(first(raw, "sid", "result.event_id", "event_id")),
        "title": _s(
            first(raw, "search_name", "result.search_name", "result.rule_name", default="Splunk notable event")
        ),
        "description": _s(first(r, "description", "message", "_raw", "rule_description"), 8000),
        "severity": severity_from(first(r, "urgency", "severity", default="medium")),
        "category": _s(first(r, "category", "type")),
        "host": _s(first(r, "dest", "dest_host", "host", "dvc")),
        "username": _s(first(r, "user", "dest_user", "src_user")),
        "src_ip": _s(first(r, "src", "src_ip")),
        "dst_ip": _s(first(r, "dest_ip", "dst_ip")),
        "event_time": parse_time(first(r, "_time", default=None)),
    }


def _elastic(raw: dict) -> dict:
    sev = first(raw, "kibana.alert.severity", "kibana.alert.risk_score", default="medium")
    return {
        "external_id": _s(first(raw, "kibana.alert.uuid", "_id")),
        "title": _s(first(raw, "kibana.alert.rule.name", default="Elastic alert")),
        "description": _s(first(raw, "kibana.alert.reason", "message", "kibana.alert.rule.description"), 8000),
        "severity": severity_from(sev),
        "category": _s(first(raw, "event.category", "kibana.alert.rule.category")),
        "host": _s(first(raw, "host.name", "host.hostname")),
        "username": _s(first(raw, "user.name", "user.target.name")),
        "src_ip": _s(first(raw, "source.ip")),
        "dst_ip": _s(first(raw, "destination.ip")),
        "event_time": parse_time(first(raw, "@timestamp", "kibana.alert.original_time", default=None)),
    }


def _generic(raw: dict) -> dict:
    return {
        "external_id": _s(first(raw, "id", "alert_id", "event_id")),
        "title": _s(first(raw, "title", "name", "rule_name", "alert", "message", default="Untitled alert")),
        "description": _s(first(raw, "description", "details", "message", "summary"), 8000),
        "severity": severity_from(first(raw, "severity", "level", "priority", default="medium")),
        "category": _s(first(raw, "category", "type", "tactic")),
        "host": _s(first(raw, "host", "hostname", "computer", "device", "asset")),
        "username": _s(first(raw, "user", "username", "account", "user_name")),
        "src_ip": _s(first(raw, "src_ip", "source_ip", "src", "srcip")),
        "dst_ip": _s(first(raw, "dst_ip", "dest_ip", "destination_ip", "dst", "dstip")),
        "event_time": parse_time(first(raw, "timestamp", "event_time", "time", "@timestamp", default=None)),
    }


PARSERS = {"wazuh": _wazuh, "splunk": _splunk, "elastic": _elastic, "generic": _generic}


def normalize(raw: dict, fmt: str = "auto") -> dict:
    if not isinstance(raw, dict):
        raise ValueError("Each alert must be a JSON object")
    fmt = (fmt or "auto").lower()
    if fmt == "auto":
        fmt = detect_format(raw)
    if fmt not in PARSERS:
        raise ValueError(f"Unknown alert format {fmt!r}")
    data = PARSERS[fmt](raw)
    data["source"] = fmt if fmt != "generic" else _s(raw.get("source") or "generic", 32)
    data["raw"] = raw
    return data
