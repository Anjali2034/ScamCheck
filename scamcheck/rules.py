"""Deterministic verdicts: turn raw check results into graded evidence, a verdict and a plain reply.

This is what answers when the free AI quota runs out, and it is the floor the AI can't argue below.
"""
import re

from scamcheck import otp_shield

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
_FRAUD_TYPE = {"digital_arrest": "digital_arrest", "task_scam": "task", "investment_scam": "investment",
               "fake_kyc": "netbanking", "upi_refund_collect": "upi"}


def _ev(source: str, finding: str, severity: str) -> dict:
    return {"source": source, "finding": finding, "severity": severity}


def _url_evidence(u: dict) -> list[dict]:
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
        bad = sum(n for v, n in (h.get("verdicts") or {}).items() if v in ("SCAM", "LIKELY_SCAM"))
        if bad:
            out.append(_ev("Earlier ScamCheck reports", f"{h['value']} was flagged as a scam in {bad} earlier check"
                           + ("s" if bad > 1 else "") + ".", "high"))
    if otp_shield.MASK in text and not any(e["severity"] in ("critical", "high", "medium") for e in out):
        out.append(_ev("OTP message", "This looks like a normal OTP message. Those are only dangerous when someone asks "
                                      "you to share the code.", "reassuring"))
    return out


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
    """The mildest verdict the AI may give: it can be stricter than the rules, never softer than hard evidence."""
    if any(e["severity"] == "critical" for e in evidence):
        return "LIKELY_SCAM"
    if any(e["severity"] == "high" for e in evidence):
        return "SUSPICIOUS"
    return "SAFE"


def scam_type_from(findings: dict, evidence: list[dict]) -> str:
    if findings["scripts"].get("matches"):
        return findings["scripts"]["matches"][0]["script"]
    brand = next((u["domain"].get("possible_impersonated_brand") for u in findings["urls"]
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


def user_message(verdict: str, already_paid: bool, text: str) -> str:
    """The reply when the AI isn't available: short, calm, action first. Evidence is listed separately."""
    hindi = bool(re.search(r"[ऀ-ॿ]", text))
    if already_paid:
        return ("तुरंत 1930 पर कॉल करें (साइबर क्राइम हेल्पलाइन) और अपने बैंक को बताएं। जितनी जल्दी, पैसे रुकने की उतनी संभावना।"
                if hindi else
                "Call 1930 (Cyber Crime Helpline) right now, then your bank. The sooner you report, the better the "
                "chance of freezing the money. I've drafted your complaint below.")
    msgs = {
        "SCAM": ("यह धोखा है। लिंक न खोलें, पैसे न भेजें, और कोई OTP या PIN न बताएं।",
                 "This is a scam. Don't click the link, don't pay, and don't share any OTP or PIN."),
        "LIKELY_SCAM": ("यह लगभग पक्का धोखा है। लिंक न खोलें, पैसे न भेजें, और कोई OTP या PIN न बताएं।",
                        "This is very likely a scam. Don't click the link, don't pay, and don't share any OTP or PIN."),
        "SUSPICIOUS": ("सावधान रहें, इसमें धोखे के संकेत हैं। कंपनी की आधिकारिक वेबसाइट पर दिए नंबर से खुद पुष्टि करें।",
                       "Be careful: this has warning signs. Check directly with the company using the number on its "
                       "official website or the back of your card, not one from the message."),
        "LIKELY_SAFE": ("मुझे धोखे के संकेत नहीं मिले। फिर भी, कोई OTP या PIN किसी को न बताएं।",
                        "I didn't find signs of a scam. Still, never share an OTP or PIN with anyone who calls or messages you."),
        "SAFE": ("यह सुरक्षित लगता है। फिर भी, कोई OTP या PIN किसी को न बताएं।",
                 "This looks safe. Still, never share an OTP or PIN with anyone."),
        "INCONCLUSIVE": ("मैं पक्का नहीं कह सकता। सावधानी रखें: लिंक न खोलें और पैसे न भेजें जब तक खुद पुष्टि न कर लें।",
                         "I couldn't find enough to be sure either way. Until you've checked it yourself, don't click, "
                         "pay, or share any code."),
    }
    return msgs[verdict][0 if hindi else 1]


def suspect_indicators(findings: dict) -> list[dict]:
    """What to remember for "seen before" checks, when the verdict is bad. Official domains are never recorded."""
    ind = findings["indicators"]
    out = [{"kind": "domain", "value": u["domain"]["registrable_domain"]} for u in findings["urls"]
           if not u["domain"].get("is_official_domain") and u["domain"].get("registrable_domain")]
    out += [{"kind": "upi", "value": u["vpa"]} for u in ind.get("upi_ids", [])]
    out += [{"kind": "phone", "value": p} for p in ind.get("phone_numbers", [])]
    out += [{"kind": "email", "value": e} for e in ind.get("emails", [])]
    out += [{"kind": "handle", "value": h} for h in ind.get("messaging_handles", [])]
    return out
