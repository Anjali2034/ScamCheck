"""Match a message against known Indian scam scripts."""
import json
import re

from scamcheck.config import DATA_DIR

_DB = json.loads((DATA_DIR / "scam_patterns.json").read_text(encoding="utf-8"))
_SCRIPTS = [
    {**s, "cues": [(re.compile(c["re"], re.I), c["w"]) for c in s["cues"]]} for s in _DB["scripts"]
]
_FLAGS = [(re.compile(f["re"], re.I), f["flag"]) for f in _DB["general_red_flags"]]


def match_scam_scripts(text: str) -> dict:
    matches = []
    for s in _SCRIPTS:
        hits, score = [], 0
        for rx, w in s["cues"]:
            m = rx.search(text)
            if m:
                hits.append(m.group(0))
                score += w
        if score >= 3:
            strength = "strong" if score >= 8 else "moderate" if score >= 5 else "weak"
            matches.append({"script": s["name"], "id": s["id"], "score": score, "strength": strength,
                            "matched_phrases": hits, "how_it_works": s["how_it_works"], "fact": s["fact"]})
    matches.sort(key=lambda m: m["score"], reverse=True)
    flags = [flag for rx, flag in _FLAGS if rx.search(text)]
    return {"matches": matches[:3], "general_red_flags": flags,
            "note": "Keyword matching only; reword or translate unusual phrasing yourself before relying on 'no match'."}
