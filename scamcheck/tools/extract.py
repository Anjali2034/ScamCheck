"""Pull links, UPI IDs, phone numbers, emails and handles out of free text."""
import re

URL_RE = re.compile(
    r"""(?xi)
    \b(?:https?://|www\.)[^\s<>"'`]+            # explicit URLs
    | \b(?:[a-z0-9-]+\.)+(?:com|in|net|org|co|info|xyz|top|online|site|club|live|link|app|icu|vip|shop|cc|me|io|ly|gl|ink|buzz|sbs|cfd)(?:/[^\s<>"'`]*)?
    """
)
# UPI VPA: name@psp. Excludes things that look like email domains (contain a dot after @).
UPI_RE = re.compile(r"\b([a-zA-Z0-9.\-_]{2,256})@([a-zA-Z][a-zA-Z0-9]{2,64})\b(?!\.)")
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
PHONE_RE = re.compile(r"(?<![\w/])(\+?\d[\d\s\-()]{8,16}\d)(?![\w/])")
HANDLE_RE = re.compile(r"(?:t\.me/|telegram\.me/|wa\.me/)([A-Za-z0-9_+]{3,64})", re.I)
AMOUNT_RE = re.compile(r"(?:₹|rs\.?|inr)\s?([\d,]+(?:\.\d+)?)", re.I)

KNOWN_UPI_PSPS = {
    "ybl", "ibl", "axl", "okaxis", "okhdfcbank", "okicici", "oksbi", "paytm", "ptyes", "ptaxis",
    "pthdfc", "ptsbi", "upi", "apl", "yapl", "rapl", "jupiteraxis", "fbl", "axisbank", "icici",
    "hdfcbank", "sbi", "kotak", "kmbl", "pnb", "barodampay", "boi", "cnrb", "unionbank", "idfcbank",
    "indus", "federal", "yesbank", "airtel", "jio", "freecharge", "slice", "naviaxis", "waicici",
    "wahdfcbank", "waaxis", "wasbi", "abfspay", "superyes", "timecosmos", "pingpay", "dbs", "aubank",
}


def _normalise_phone(raw: str) -> str | None:
    digits = re.sub(r"\D", "", raw)
    if raw.strip().startswith("+"):
        return "+" + digits if 10 <= len(digits) <= 15 else None
    if len(digits) == 10 and digits[0] in "6789":
        return "+91" + digits
    if len(digits) == 12 and digits.startswith("91") and digits[2] in "6789":
        return "+" + digits
    if len(digits) == 11 and digits.startswith("0") and digits[1] in "6789":
        return "+91" + digits[1:]
    if digits.startswith("1800") or digits.startswith("1860"):
        return digits  # Indian toll-free
    return None


def extract_indicators(text: str) -> dict:
    urls = []
    for m in URL_RE.finditer(text):
        u = m.group(0).rstrip(".,;:!?)]}'\"")
        if "@" in u:
            continue
        if not u.lower().startswith(("http://", "https://")):
            u = "http://" + u
        if u not in urls:
            urls.append(u)

    emails = sorted(set(EMAIL_RE.findall(text)))
    upi_ids = []
    for m in UPI_RE.finditer(text):
        vpa = m.group(0)
        if any(vpa in e for e in emails):
            continue
        psp = m.group(2).lower()
        upi_ids.append({"vpa": vpa, "psp": psp, "known_psp": psp in KNOWN_UPI_PSPS})

    phones = []
    text_wo_urls = URL_RE.sub(" ", text)
    for m in PHONE_RE.finditer(text_wo_urls):
        n = _normalise_phone(m.group(1))
        if n and n not in phones:
            phones.append(n)

    return {
        "urls": urls,
        "upi_ids": upi_ids,
        "phone_numbers": phones,
        "emails": emails,
        "messaging_handles": sorted(set(HANDLE_RE.findall(text))),
        "amounts_mentioned": AMOUNT_RE.findall(text),
    }


def analyse_phone(number: str) -> dict:
    """Offline heuristics on a phone number's format and origin."""
    n = _normalise_phone(number) or number
    digits = re.sub(r"\D", "", n)
    flags = []
    country = "unknown"
    if n.startswith("+91"):
        country = "India"
        if len(digits) != 12:
            flags.append("Malformed Indian mobile number length.")
    elif digits.startswith(("1800", "1860")):
        country = "India (toll-free)"
        flags.append("Genuine bank toll-free numbers are listed on the bank's official website; verify there, not from the message.")
    elif n.startswith("+"):
        prefixes = {
            "+92": "Pakistan", "+84": "Vietnam", "+855": "Cambodia", "+856": "Laos", "+95": "Myanmar",
            "+62": "Indonesia", "+63": "Philippines", "+254": "Kenya", "+234": "Nigeria", "+1": "US/Canada",
            "+44": "UK", "+971": "UAE", "+880": "Bangladesh", "+977": "Nepal", "+60": "Malaysia",
        }
        for p in sorted(prefixes, key=len, reverse=True):
            if n.startswith(p):
                country = prefixes[p]
                break
        flags.append(
            f"International number ({country}). Indian banks, police, TRAI, courier firms and government "
            "agencies do not contact citizens from foreign WhatsApp numbers."
        )
        if country in {"Cambodia", "Laos", "Myanmar", "Vietnam"}:
            flags.append("This region hosts known scam compounds running task and investment fraud aimed at Indians.")
    if n.startswith("+91140") or digits.startswith("91140"):
        flags.append("140-series numbers are reserved for telemarketing.")
    return {"number": n, "country": country, "flags": flags}
