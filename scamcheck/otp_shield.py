"""OTP shield: people forward real OTP/PIN messages to ask "is this genuine?".

Hide the code before it is logged, stored, streamed or sent to the model, and warn the person before anything else.
Only the code is hidden; the rest of the message stays, because it is evidence.
"""
import re

MASK = "[OTP hidden]"

# Words that mark a nearby number as a secret code. Postal "PIN code" is deliberately not one of them.
_KEYWORD = re.compile(r"""(?ix)
      otp | ओटीपी | one[\s-]?time[\s-]?pass(?:word|code)
    | (?:verification|security|auth(?:entication)?|login|confirmation|access)\s+code
    | \bcode\s*(?:is\b|:|-)
    | \b(?:upi|atm|m)[\s-]?pin\b
    | \bpin\b(?!\s*-?\s*code)
""")
# Not part of a word, date, decimal or grouped amount ("1,20,000"), but a code may end a clause: "OTP is 482913, ..."
_NUMBER = re.compile(r"(?<![\w₹/])(?<!\d[.,])\d{4,8}(?![\w/]|[.,]\d)")
_CURRENCY_BEFORE = re.compile(r"(?:₹|rs\.?|inr)\s*$", re.I)
_POSTAL_BEFORE = re.compile(r"pin\s*-?\s*code\s*(?:is|:|-)?\s*$", re.I)  # "PIN code 110001" is an address
_PHONE_CHARS = set("0123456789 -+()")
WINDOW = 40  # characters between keyword and number: "OTP for your HDFC Bank login is 482913"


def _part_of_phone_number(text: str, start: int, end: int) -> bool:
    """'98765 43210' arrives as two 5-digit runs; a phone number is evidence, not a secret."""
    while start > 0 and text[start - 1] in _PHONE_CHARS:
        start -= 1
    while end < len(text) and text[end] in _PHONE_CHARS:
        end += 1
    return sum(c.isdigit() for c in text[start:end]) >= 10


def mask_otps(text: str) -> tuple[str, int]:
    """Return the text with one-time codes and PINs replaced by MASK, and how many were hidden."""
    keywords = [m.span() for m in _KEYWORD.finditer(text)]
    if not keywords:
        return text, 0
    spans = []
    for m in _NUMBER.finditer(text):
        s, e = m.span()
        before = text[max(0, s - 16):s]
        if _CURRENCY_BEFORE.search(before) or _POSTAL_BEFORE.search(before) or _part_of_phone_number(text, s, e):
            continue
        if any(ks - WINDOW <= e and ke + WINDOW >= s for ks, ke in keywords):
            spans.append((s, e))
    for s, e in reversed(spans):
        text = text[:s] + MASK + text[e:]
    return text, len(spans)


def warning(text: str) -> str:
    """The first thing the person reads, in their script (Devanagari gets Hindi)."""
    if re.search(r"[ऀ-ॿ]", text):
        return ("🔐 *आपने मुझे एक OTP/PIN भेजा है।* मैंने उसे छिपा दिया है और सेव नहीं करूँगा।\n"
                "OTP या PIN कभी किसी को न भेजें, मुझे भी नहीं। अगर किसी कॉलर, \"बैंक एजेंट\" या डिलीवरी वाले ने "
                "यह कोड माँगा है, तो यह धोखा है। उसे कोड न दें।")
    return ("🔐 *You just sent me a one-time code (OTP/PIN).* I've hidden it and won't store it.\n"
            "Never share an OTP or PIN with anyone, not even me. If a caller, \"bank agent\" or delivery person "
            "asked you for this code, it's a scam. Don't give it to them.")
