"""Keyword-based MITRE ATT&CK mapping with word-boundary-safe patterns, sorted by kill-chain order."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

TACTICS = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]
TACTIC_ORDER = {t: i for i, t in enumerate(TACTICS)}
LATE_TACTICS = {"Lateral Movement", "Command and Control", "Exfiltration", "Impact"}
MID_TACTICS = {"Defense Evasion", "Credential Access", "Discovery"}
SHORT_KEYWORD_LEN = 5


def _pattern(keyword: str) -> re.Pattern:
    kw = re.escape(keyword.lower())
    # Short keywords need both boundaries ("rce" must never match "source");
    # longer ones only need a leading boundary so "encrypt" matches "encrypted".
    if len(keyword) <= SHORT_KEYWORD_LEN:
        return re.compile(rf"(?<![a-z0-9]){kw}(?![a-z0-9])")
    return re.compile(rf"(?<![a-z0-9]){kw}")


@lru_cache
def load_techniques() -> list[dict]:
    with open(DATA_DIR / "mitre_techniques.json", encoding="utf-8") as fh:
        techniques = json.load(fh)
    for t in techniques:
        t["_patterns"] = [(k, _pattern(k)) for k in t.get("keywords", [])]
    return techniques


def technique_catalog() -> list[dict]:
    return [{k: v for k, v in t.items() if not k.startswith("_")} for t in load_techniques()]


def map_techniques(text: str) -> list[dict]:
    text = (text or "").lower()
    hits = []
    for t in load_techniques():
        matched = [k for k, p in t["_patterns"] if p.search(text)]
        if matched:
            hits.append(
                {
                    "id": t["id"],
                    "name": t["name"],
                    "tactic": t["tactic"],
                    "matched": matched[:5],
                    "url": attack_url(t["id"]),
                }
            )
    hits.sort(key=lambda h: (TACTIC_ORDER.get(h["tactic"], 99), h["id"]))
    return hits


def attack_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def tactics_of(techniques: list[dict]) -> list[str]:
    seen = []
    for t in sorted(techniques, key=lambda h: TACTIC_ORDER.get(h.get("tactic", ""), 99)):
        if t.get("tactic") and t["tactic"] not in seen:
            seen.append(t["tactic"])
    return seen
