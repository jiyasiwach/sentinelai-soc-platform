"""Response playbooks, ranked by how well their triggers match an alert's techniques and text."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@lru_cache
def load_playbooks() -> list[dict]:
    with open(DATA_DIR / "playbooks.json", encoding="utf-8") as fh:
        return json.load(fh)


def rank_playbooks(techniques: list[dict], text: str = "", limit: int = 3) -> list[dict]:
    text = (text or "").lower()
    tech_ids = {t["id"] for t in techniques}
    tech_parents = {t["id"].split(".")[0] for t in techniques}
    tactics = {t["tactic"] for t in techniques}
    ranked = []
    for pb in load_playbooks():
        trig = pb.get("triggers", {})
        score = 0
        for tid in trig.get("techniques", []):
            if tid in tech_ids:
                score += 3
            elif tid.split(".")[0] in tech_parents:
                score += 2
        score += sum(1 for t in trig.get("tactics", []) if t in tactics)
        score += sum(2 for k in trig.get("keywords", []) if k.lower() in text)
        if score > 0:
            ranked.append(
                {
                    "id": pb["id"],
                    "name": pb["name"],
                    "score": score,
                    "description": pb.get("description", ""),
                    "steps": pb.get("steps", []),
                }
            )
    ranked.sort(key=lambda p: p["score"], reverse=True)
    return ranked[:limit]
