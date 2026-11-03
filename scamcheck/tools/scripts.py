"""Match a message against known Indian scam scripts."""
import json
import re

from scamcheck.config import DATA_DIR

# Screenshot OCR often misplaces Hindi's short-i sign and drops the virama ("बिजली" comes back as "बजिली",
# "कनेक्शन" as "कनेकशन"). So every cue is also tried with both signs removed from the cue and from the text.
# The same goes for the nukta dot (ड़ and ज़ can each be typed two ways, and OCR drops the dot) and for ँ/ं, which
# people use interchangeably ("हूँ", "हूं").
_LOOSE = str.maketrans({"ि": None, "्": None, "़": None, "ँ": "ं",
                        **{chr(0x0958 + i): base for i, base in enumerate("कखगजडढफय")}})


def _cue(pattern: str) -> tuple[re.Pattern, re.Pattern]:
    # DOTALL: a cue may span a line break (screenshots wrap lines, people paste multi-line messages).
    return re.compile(pattern, re.I | re.S), re.compile(pattern.translate(_LOOSE), re.I | re.S)


def _search(cue: tuple[re.Pattern, re.Pattern], text: str, loose: str) -> re.Match | None:
    return cue[0].search(text) or cue[1].search(loose)


_DB = json.loads((DATA_DIR / "scam_patterns.json").read_text(encoding="utf-8"))
_SCRIPTS = [
    {**s, "cues": [(_cue(c["re"]), c["w"]) for c in s["cues"]]} for s in _DB["scripts"]
]
_FLAGS = [(_cue(f["re"]), f["flag"]) for f in _DB["general_red_flags"]]


def match_scam_scripts(text: str) -> dict:
    loose = text.translate(_LOOSE)
    matches = []
    for s in _SCRIPTS:
        hits, score = [], 0
        for cue, w in s["cues"]:
            m = _search(cue, text, loose)
            if m:
                hits.append(m.group(0))
                score += w
        if score >= 3:
            strength = "strong" if score >= 8 else "moderate" if score >= 5 else "weak"
            matches.append({"script": s["name"], "id": s["id"], "score": score, "strength": strength,
                            "matched_phrases": hits, "how_it_works": s["how_it_works"], "fact": s["fact"]})
    matches.sort(key=lambda m: m["score"], reverse=True)
    flags = [flag for cue, flag in _FLAGS if _search(cue, text, loose)]
    return {"matches": matches[:3], "general_red_flags": flags,
            "note": "Keyword matching only; reword or translate unusual phrasing yourself before relying on 'no match'."}
