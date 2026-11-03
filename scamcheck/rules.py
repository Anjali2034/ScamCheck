"""Deterministic verdicts: turn raw check results into graded evidence, a verdict and a plain reply.

This is what answers when the free AI quota runs out, and it is the floor the AI can't argue below.
"""
import re

from scamcheck import otp_shield
from scamcheck.tools.domain import SHORTENERS, short_link_id

VERDICTS = ["SAFE", "LIKELY_SAFE", "INCONCLUSIVE", "SUSPICIOUS", "LIKELY_SCAM", "SCAM"]  # mildest first

# check_domain findings worth showing on their own; brand findings are summarised separately.
_DOMAIN_FINDING_SEVERITY = [
    ("Look-alike", "critical"), ("Punycode", "high"), ("raw IP", "high"), ("free/tunnelling", "high"),
    ("'@'", "high"), ("shortener", "medium"), ("cheap TLD", "medium"), ("deep subdomain", "medium"), ("No HTTPS", "low"),
]
_SCRIPT_SEVERITY = {"strong": "critical", "moderate": "high", "weak": "medium"}
_OTP_FLAG = "Mentions OTP/PIN/CVV"

# First person only: scam texts themselves say "your bill was not paid", which must not read as a confession.
PAID_RE = re.compile(r"""(?ix)
      \b(?:i|we)\s+(?:have\s+|had\s+|just\s+)?(?:already\s+)?(?:paid|transferred|deposited|sent\s+(?:the\s+|him\s+|her\s+|them\s+)?(?:money|amount|₹|rs))
    | \balready\s+(?:paid|transferred|sent\s+(?:the\s+)?money)
    | \b(?:maine|humne)\b.{0,40}?\b(?:pay|payment|bhej|transfer|de\s+diye)
    | \bpay(?:ment)?\s+(?:kar\s+diya|kar\s+di|ho\s+gaya|kiya)
    | \bpaise?\s+(?:bhej|de)\s+di(?:ye|ya|e)
    | मैंने.{0,40}(?:भेज|पेमेंट|भुगतान) | पैसे\s+भेज\s+दिए
    | \b(?:i|we)\s+(?:\w+\s+){0,2}(?:shared|gave|told)\s+(?:\w+\s+){0,3}(?:otp|pin|cvv)
    | \b(?:i|we)\s+(?:\w+\s+){0,2}(?:installed|downloaded)\s+(?:\w+\s+){0,3}(?:app|apk|anydesk|teamviewer|quicksupport)
""")
# Common Hindi words written in Latin letters. Two different ones mark a message as Hinglish.
_HINGLISH_RE = re.compile(r"\b(aap|aapka|aapki|aapke|aapko|aapne|hai|hain|nahi|nahin|kya|karo|kare|karein|kijiye|bhejo|bhejiye|"
                          r"mat|liye|raha|rahi|gaya|hoga|jayega|jaega|paisa|paise|mera|meri|maine|abhi|turant|jaldi|"
                          r"rupaye|lene|dena|milega|jeeti|jeeta)\b", re.I)  # not "lakh": Indian English uses it too
_FRAUD_TYPE = {"digital_arrest": "digital_arrest", "task_scam": "task", "investment_scam": "investment",
               "fake_kyc": "netbanking", "upi_refund_collect": "upi"}


def _ev(source: str, finding: str, severity: str) -> dict:
    return {"source": source, "finding": finding, "severity": severity}


def _link_evidence(u: dict) -> list[dict]:
    out, d = [], u["domain"]
    host = d.get("host", u["url"])
    if d.get("is_official_domain"):
        return [_ev("Official domain list", f"The link goes to the official {d['brand']} website ({host}).", "reassuring")]
    if brand := d.get("possible_impersonated_brand"):
        out.append(_ev("Brand impersonation check", f"Pretends to be {brand}, but {host} is not an official {brand} website.",
                       "critical"))
    for f in d.get("findings", []):
        sev = next((s for key, s in _DOMAIN_FINDING_SEVERITY if key in f), None)
        if sev:
            out.append(_ev("Link check", f, sev))

    age = (d.get("registration") or {}).get("age_days")
    if age is not None and age < 30:
        out.append(_ev("Domain age (RDAP)", f"The website was registered only {age} days ago.", "critical"))
    elif age is not None and age < 180:
        out.append(_ev("Domain age (RDAP)", f"The website was registered {age} days ago.", "high"))

    rep = u.get("reputation") or {}
    sb = rep.get("safe_browsing") or {}
    if sb.get("flagged"):
        out.append(_ev("Google Safe Browsing", "Google lists this link as dangerous ("
                       + ", ".join(t.replace("_", " ").lower() for t in sb.get("threat_types", [])) + ").", "critical"))
    vt = rep.get("virustotal") or {}
    for key, what in (("url_report", "link"), ("domain_report", "website")):
        stats = vt.get(key)
        if isinstance(stats, dict):
            n = stats.get("malicious", 0) + stats.get("suspicious", 0)
            if n:
                out.append(_ev("VirusTotal", f"{n} security vendor{'s' if n > 1 else ''} flag this {what} as malicious.",
                               "critical" if n >= 2 else "high"))

    sb_visit = u.get("sandbox") or {}
    if sb_visit.get("status") == "ok":
        asks = [label for key, label in (("asks_password", "password/PIN"), ("asks_otp", "OTP"), ("asks_card", "card details"),
                                         ("asks_aadhaar_pan", "Aadhaar/PAN"), ("asks_bank_login", "bank login")) if sb_visit.get(key)]
        if asks:
            out.append(_ev("Sandbox visit", "The page asks for your " + ", ".join(asks) + ".", "critical"))
        if sb_visit.get("apk_links"):
            out.append(_ev("Sandbox visit", "The page offers an Android app (.apk) download outside the Play Store.", "critical"))
        if sb_visit.get("upi_deeplinks"):
            out.append(_ev("Sandbox visit", "The page opens a UPI payment request.", "high"))
    elif sb_visit.get("status") == "dead":
        out.append(_ev("Sandbox visit", "The website no longer exists. Phishing sites are often taken down within days.", "medium"))
    return out


def _url_evidence(u: dict) -> list[dict]:
    """A link's evidence, plus its real destination's when it redirects (a bit.ly link, a page that forwards)."""
    out, dest = _link_evidence(u), u.get("destination")
    if not dest:
        return out
    # Now that the destination is known, "a shortener hides it" no longer applies; and if the destination is an
    # official site, the shortener's own name says nothing about who sent it.
    out = [e for e in out if "shortener hides" not in e["finding"]
           and not (dest["domain"].get("is_official_domain") and e["source"] in ("Brand impersonation check", "Link check"))]
    out += _link_evidence(dest)
    out += _history_evidence(dest.get("history"))
    if dest.get("down"):
        out.append(_ev("Link check", "The short link points to a website that no longer exists.", "medium"))
    return out


def _links(findings: dict) -> list[dict]:
    """Every link and every real destination."""
    return [x for u in findings["urls"] for x in (u, u.get("destination")) if x]


def link_destinations(findings: dict) -> list[dict]:
    """Where links really go, to show the person: "bit.ly/abc goes to sbi-kyc-update.xyz"."""
    return [{"link": u["url"], "goes_to": u["destination"]["domain"].get("host") or u["destination"]["url"],
             "official": bool(u["destination"]["domain"].get("is_official_domain"))}
            for u in findings["urls"] if u.get("destination")]


def evidence_from(findings: dict, text: str) -> list[dict]:
    out = []
    for u in findings["urls"]:
        out += _url_evidence(u)
    for m in findings["scripts"].get("matches", []):
        out.append(_ev("Known scam scripts", f"Matches the '{m['script']}' scam. {m['fact']}", _SCRIPT_SEVERITY[m["strength"]]))
    flags = findings["scripts"].get("general_red_flags", [])
    if otp_shield.MASK in text:  # the message *is* the bank's OTP SMS, so mentioning an OTP is expected
        flags = [f for f in flags if not f.startswith(_OTP_FLAG)]
    out += [_ev("Wording", f, "medium") for f in flags[:3]]
    for p in findings["phones"]:
        for f in p.get("flags", []):
            sev = "critical" if "scam compounds" in f else "high" if "International" in f else "medium" if "140" in f else "low"
            out.append(_ev(f"Phone number {p['number']}", f, sev))
    for upi in findings["indicators"].get("upi_ids", []):
        if not upi["known_psp"]:
            out.append(_ev("UPI ID check", f"'@{upi['psp']}' in {upi['vpa']} is not a known bank or UPI app handle.", "medium"))
    for h in findings["history"] + [p.get("history", {}) for p in findings["phones"]]:
        out += _history_evidence(h)
    if otp_shield.MASK in text and not any(e["severity"] in ("critical", "high", "medium") for e in out):
        out.append(_ev("OTP message", "This looks like a normal OTP message. Those are only dangerous when someone asks "
                                      "you to share the code.", "reassuring"))
    return out


HISTORY = "Earlier ScamCheck reports"


def _history_evidence(h: dict | None) -> list[dict]:
    """Other people's scam verdicts on this link/number/UPI ID. One person is a hint (their verdict may have been
    wrong); two or more who each got a scam verdict is strong."""
    bad = sum(n for v, n in ((h or {}).get("verdicts") or {}).items() if v in ("SCAM", "LIKELY_SCAM"))
    if not bad:
        return []
    who = "1 other person" if bad == 1 else f"{bad} other people"
    return [_ev(HISTORY, f"{who} who checked {h['value']} on ScamCheck got a scam result.",
                "high" if bad >= 2 else "medium")]


def verdict_from(evidence: list[dict]) -> tuple[str, str]:
    count = {s: sum(e["severity"] == s for e in evidence) for s in ("critical", "high", "medium", "reassuring")}
    if count["critical"] >= 2 or (count["critical"] and count["high"]):
        return "SCAM", "high"
    if count["critical"]:
        return "LIKELY_SCAM", "medium"
    if count["high"] >= 2:
        return "LIKELY_SCAM", "medium"
    if count["high"] or count["medium"] >= 2:
        return "SUSPICIOUS", "medium"
    if count["medium"]:
        return "SUSPICIOUS", "low"
    if count["reassuring"]:
        return "LIKELY_SAFE", "medium"
    return "INCONCLUSIVE", "low"


def floor_for(evidence: list[dict]) -> str:
    """The mildest verdict the AI may give: it can be stricter than the rules, never softer than hard evidence, and it
    can't call something safe unless a check found a reason to (an official domain, a normal OTP message). A
    brand-new phishing link with no red flags yet must read "couldn't tell", not "safe"."""
    if any(e["severity"] == "critical" for e in evidence):
        return "LIKELY_SCAM"
    if any(e["severity"] == "high" for e in evidence):
        return "SUSPICIOUS"
    if any(e["severity"] == "reassuring" for e in evidence):
        return "SAFE"
    return "INCONCLUSIVE"


def scam_type_from(findings: dict, evidence: list[dict]) -> str:
    if findings["scripts"].get("matches"):
        return findings["scripts"]["matches"][0]["script"]
    brand = next((u["domain"].get("possible_impersonated_brand") for u in _links(findings)
                  if u["domain"].get("possible_impersonated_brand")), None)
    if brand:
        return f"Fake {brand} website"
    if any(e["severity"] == "critical" and e["source"] != "Wording" for e in evidence):
        return "Phishing link"
    return ""


def fraud_type_for(findings: dict, text: str) -> str:
    for m in findings["scripts"].get("matches", []):
        if m["id"] in _FRAUD_TYPE:
            return _FRAUD_TYPE[m["id"]]
    return "upi" if re.search(r"\b(upi|gpay|google pay|phonepe|paytm|bhim)\b", text, re.I) else "other"


def language(text: str) -> str:
    """"Hindi" (Devanagari), "Hinglish" (Hindi in Latin letters) or "English": the reply should match the person."""
    if re.search(r"[ऀ-ॿ]", text):
        return "Hindi"
    return "Hinglish" if len({w.lower() for w in _HINGLISH_RE.findall(text)}) >= 2 else "English"


def user_message(verdict: str, already_paid: bool, text: str) -> str:
    """The reply when the AI isn't available: short, calm, action first. Evidence is listed separately."""
    lang = ["Hindi", "English", "Hinglish"].index(language(text))
    if already_paid:
        return ("तुरंत 1930 पर कॉल करें (साइबर क्राइम हेल्पलाइन) और अपने बैंक को बताएं। जितनी जल्दी, पैसे रुकने की उतनी संभावना।",
                "Call 1930 (Cyber Crime Helpline) right now, then your bank. The sooner you report, the better the "
                "chance of freezing the money. I've drafted your complaint below.",
                "Abhi turant 1930 par call karein (Cyber Crime Helpline), phir apne bank ko batayein. Jitni jaldi report "
                "karenge, paise rukne ki utni zyada sambhavna hai. Neeche aapki complaint ka draft hai.")[lang]
    msgs = {
        "SCAM": ("यह धोखा है। लिंक न खोलें, पैसे न भेजें, और कोई OTP या PIN न बताएं।",
                 "This is a scam. Don't click the link, don't pay, and don't share any OTP or PIN.",
                 "Yeh scam hai. Link mat kholiye, paise mat bhejiye, aur koi OTP ya PIN kisi ko mat batayiye."),
        "LIKELY_SCAM": ("यह लगभग पक्का धोखा है। लिंक न खोलें, पैसे न भेजें, और कोई OTP या PIN न बताएं।",
                        "This is very likely a scam. Don't click the link, don't pay, and don't share any OTP or PIN.",
                        "Yeh lagbhag pakka scam hai. Link mat kholiye, paise mat bhejiye, aur koi OTP ya PIN mat batayiye."),
        "SUSPICIOUS": ("सावधान रहें, इसमें धोखे के संकेत हैं। कंपनी की आधिकारिक वेबसाइट पर दिए नंबर से खुद पुष्टि करें।",
                       "Be careful: this has warning signs. Check directly with the company using the number on its "
                       "official website or the back of your card, not one from the message.",
                       "Saavdhan rahiye, ismein dhokhe ke sanket hain. Company ki official website par diye number se khud "
                       "confirm kijiye, message wale number se nahi."),
        "LIKELY_SAFE": ("मुझे धोखे के संकेत नहीं मिले। फिर भी, कोई OTP या PIN किसी को न बताएं।",
                        "I didn't find signs of a scam. Still, never share an OTP or PIN with anyone who calls or messages you.",
                        "Mujhe scam ke sanket nahi mile. Phir bhi, koi OTP ya PIN kisi ko mat batayiye."),
        "SAFE": ("यह सुरक्षित लगता है। फिर भी, कोई OTP या PIN किसी को न बताएं।",
                 "This looks safe. Still, never share an OTP or PIN with anyone.",
                 "Yeh safe lagta hai. Phir bhi, koi OTP ya PIN kisi ko mat batayiye."),
        "INCONCLUSIVE": ("मैं पक्का नहीं कह सकता। सावधानी रखें: लिंक न खोलें और पैसे न भेजें जब तक खुद पुष्टि न कर लें।",
                         "I couldn't find enough to be sure either way. Until you've checked it yourself, don't click, "
                         "pay, or share any code.",
                         "Main pakka nahi keh sakta. Jab tak khud confirm na kar lein, link mat kholiye, paise mat bhejiye "
                         "aur koi code mat batayiye."),
    }
    return msgs[verdict][lang]


def suspect_indicators(findings: dict) -> list[dict]:
    """What to remember for "seen before" checks, when the verdict is bad. Official domains are never recorded."""
    ind = findings["indicators"]
    out = [{"kind": "domain", "value": u["domain"]["registrable_domain"]} for u in _links(findings)
           if not u["domain"].get("is_official_domain") and u["domain"].get("registrable_domain")
           and u["domain"]["registrable_domain"] not in SHORTENERS]
    # A short link is remembered as itself (bit.ly/abc123), never as "bit.ly", or every bit.ly link would look flagged.
    out += [{"kind": "short_link", "value": short_link_id(u["url"])} for u in findings["urls"]
            if u["domain"].get("registrable_domain") in SHORTENERS]
    out += [{"kind": "upi", "value": u["vpa"]} for u in ind.get("upi_ids", [])]
    out += [{"kind": "phone", "value": p} for p in ind.get("phone_numbers", [])]
    out += [{"kind": "email", "value": e} for e in ind.get("emails", [])]
    out += [{"kind": "handle", "value": h} for h in ind.get("messaging_handles", [])]
    return out
